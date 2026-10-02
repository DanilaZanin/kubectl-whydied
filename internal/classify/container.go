package classify

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

func statusListName(kind string) string {
	switch kind {
	case "init":
		return "initContainerStatuses"
	case "ephemeral":
		return "ephemeralContainerStatuses"
	}
	return "containerStatuses"
}

func specListName(role string) string {
	switch role {
	case "init", "sidecar":
		return "initContainers"
	case "ephemeral":
		return "ephemeralContainers"
	}
	return "containers"
}

func currentState(cs *corev1.ContainerStatus) string {
	switch {
	case cs.State.Running != nil:
		return "running since " + fmtTime(mt(cs.State.Running.StartedAt))
	case cs.State.Waiting != nil:
		s := "waiting: " + cs.State.Waiting.Reason
		if cs.State.Waiting.Message != "" {
			s += " (" + cs.State.Waiting.Message + ")"
		}
		return s
	case cs.State.Terminated != nil:
		return fmt.Sprintf("terminated (exitCode=%d, reason=%s)", cs.State.Terminated.ExitCode, cs.State.Terminated.Reason)
	}
	return "unknown"
}

// isSynthesized reports whether the kubelet made up this termination (it did
// not observe the process end). Its exit code says nothing about the cause and
// must stay out of every causal heuristic.
func isSynthesized(t *corev1.ContainerStateTerminated) bool {
	return t != nil && (t.Reason == "ContainerStatusUnknown" || t.Reason == "RestartingAllContainers")
}

// inst is the container instance being explained: the selected termination and
// everything needed to tie evidence to exactly that instance.
type inst struct {
	cs       *corev1.ContainerStatus
	kind     string // status list kind: init | regular | ephemeral
	role     string // init | sidecar | regular | ephemeral
	spec     *corev1.Container
	specPath string // spec.containers[app]
	base     string // status.containerStatuses[app]
	term     *corev1.ContainerStateTerminated
	fromLast bool
	path     string // base + .state.terminated or .lastState.terminated
}

func (a *analysis) newInst(ref collect.StatusRef) *inst {
	cs := ref.Status
	spec, role := containerSpec(a.pod, cs.Name)
	if ref.Kind == "ephemeral" {
		role = "ephemeral"
	}
	in := &inst{cs: cs, kind: ref.Kind, role: role, spec: spec,
		specPath: fmt.Sprintf("spec.%s[%s]", specListName(role), cs.Name),
		base:     fmt.Sprintf("status.%s[%s]", statusListName(ref.Kind), cs.Name)}
	in.term, in.fromLast = collect.LastTermination(cs)
	if in.term != nil {
		src := "state.terminated"
		if in.fromLast {
			src = "lastState.terminated"
		}
		in.path = in.base + "." + src
	}
	return in
}

func termInfo(t *corev1.ContainerStateTerminated, src string) *Termination {
	return &Termination{Source: src, ContainerID: t.ContainerID, ExitCode: t.ExitCode, Signal: t.Signal,
		Reason: t.Reason, Message: t.Message, StartedAt: mt(t.StartedAt), FinishedAt: mt(t.FinishedAt)}
}

func (a *analysis) container(ref collect.StatusRef) ContainerReport {
	in := a.newInst(ref)
	cs, term := in.cs, in.term
	cr := ContainerReport{Name: cs.Name, Role: in.role, Image: cs.Image, RestartCount: cs.RestartCount, CurrentState: currentState(cs)}

	var vs []Verdict
	if term != nil {
		src := "state.terminated"
		if in.fromLast {
			src = "lastState.terminated"
		}
		cr.Termination = termInfo(term, src)
		probe, trig := a.probeKill(in)
		hook := a.postStart(in)
		exit := a.exitVerdicts(in, term, in.path)
		if term.Reason == "OOMKilled" {
			// The runtime's own report about this instance always comes first.
			vs = append(vs, exit...)
			vs = append(vs, probe...)
			vs = append(vs, hook...)
		} else {
			vs = append(vs, probe...)
			vs = append(vs, hook...)
			vs = append(vs, exit...)
		}
		vs = append(vs, a.nodeOOM(in)...)
		vs = append(vs, a.graceVerdict(in, trig)...)
		// A synthesized state.terminated hides the real previous termination; show it too.
		if isSynthesized(term) && !in.fromLast && cs.LastTerminationState.Terminated != nil {
			prev := cs.LastTerminationState.Terminated
			cr.Previous = termInfo(prev, "lastState.terminated")
			for _, v := range a.exitVerdicts(in, prev, in.base+".lastState.terminated") {
				v.Summary = "previous instance (lastState.terminated): " + v.Summary
				vs = append(vs, v)
			}
		}
	} else {
		vs = append(vs, a.postStart(in)...)
		if len(vs) == 0 {
			vs = append(vs, a.noTermination(in)...)
		}
	}
	if vs == nil {
		vs = []Verdict{}
	}
	cr.Verdicts = vs
	cr.Expected = a.expectedness(in)
	cr.Restart = a.restartDecision(in)
	return cr
}

// specOnly builds the report for a container that is in the pod spec but has no
// status yet (not scheduled, or the kubelet has not reported).
func (a *analysis) specOnly(name, role string) ContainerReport {
	return ContainerReport{Name: name, Role: role, CurrentState: "no status reported yet",
		Restart: RestartDecision{Policy: "", Decision: "unknown", Detail: "the pod status has no entry for this container"},
		Verdicts: []Verdict{{Kind: KindNoTermination, Confidence: NoData,
			Summary:  "the container is in the pod spec but the pod status has no entry for it yet (pod not scheduled or not started); nothing to explain",
			Evidence: []Evidence{podEv(a.pod, EvPodSpec, fmt.Sprintf("spec.%s[%s]", specListName(role), name), "present in spec", nil)}}}}
}

// termEvidence lists the termination facts verbatim.
func (a *analysis) termEvidence(term *corev1.ContainerStateTerminated, path string) []Evidence {
	p := a.pod
	fin := mt(term.FinishedAt)
	ev := []Evidence{
		podEv(p, EvPodStatus, path+".exitCode", fmt.Sprint(term.ExitCode), fin),
	}
	if term.Reason != "" {
		ev = append(ev, podEv(p, EvPodStatus, path+".reason", term.Reason, fin))
	}
	if term.Message != "" {
		ev = append(ev, podEv(p, EvPodStatus, path+".message", term.Message, fin))
	}
	if term.Signal != 0 {
		ev = append(ev, podEv(p, EvPodStatus, path+".signal", fmt.Sprint(term.Signal), fin))
	}
	return ev
}

func (a *analysis) exitVerdicts(in *inst, term *corev1.ContainerStateTerminated, path string) []Verdict {
	ev := a.termEvidence(term, path)
	code := term.ExitCode
	switch {
	case term.Reason == "OOMKilled":
		limit := "no memory limit set in spec"
		if in.spec != nil {
			if q, ok := in.spec.Resources.Limits[corev1.ResourceMemory]; ok {
				limit = "spec memory limit " + q.String()
			}
		}
		ev = append(ev, podEv(a.pod, EvPodSpec, in.specPath+".resources.limits.memory", limit, nil))
		return []Verdict{{
			Kind:       KindOOMKill,
			Confidence: Confirmed,
			Summary:    fmt.Sprintf("the runtime reported an OOM kill for this container instance (API reported exitCode=%d, reason=OOMKilled)", code),
			Competing: []string{
				"OOM level is unknown: the same reason is reported for a container cgroup limit, a pod-level cgroup limit and node-wide memory exhaustion",
				"memory usage at kill time is not available from the API",
			},
			Evidence: ev,
		}}
	case isSynthesized(term):
		what := "the kubelet could not observe how the container ended and synthesized exitCode=%d"
		if term.Reason == "RestartingAllContainers" {
			what = "the kubelet marked the container terminated while restarting all containers of the pod (reason RestartingAllContainers) and synthesized exitCode=%d"
		}
		return []Verdict{{
			Kind:       KindStatusUnknown,
			Confidence: Confirmed,
			Summary:    fmt.Sprintf(what+"; the exit code carries no information about the cause", code),
			Competing:  []string{"any cause: the real exit status was never observed"},
			Evidence:   ev,
		}}
	case term.Reason == "StartError" || term.Reason == "ContainerCannotRun" || term.Reason == "CreateContainerError":
		return []Verdict{{
			Kind:       KindStartError,
			Confidence: Confirmed,
			Summary:    fmt.Sprintf("the container runtime reported that the container could not be started (API reported exitCode=%d, reason=%s); message quoted verbatim", code, term.Reason),
			Evidence:   ev,
		}}
	case code == 0:
		return []Verdict{{
			Kind:       KindAppExit,
			Confidence: Confirmed,
			Summary:    "the container's main process exited with exitCode=0 (API reported exitCode=0)",
			Evidence:   ev,
		}}
	case code >= 129 && code <= 128+64: // Linux signals 1..64
		sig := int(code) - 128
		name2 := signalName(sig)
		conv := podEv(a.pod, EvConvention, "exit code 128+n", fmt.Sprintf("%d = 128+%d = %s (shell/runtime convention, Linux numbering)", code, sig, name2), nil)
		conv.Note = "convention only: the API signal field is shown only when the API set it"
		ev = append(ev, conv)
		competing := []string{
			fmt.Sprintf("the application called exit(%d) itself; the API cannot distinguish that from death by %s", code, name2),
		}
		if code == 137 {
			competing = append(competing, "an OOM kill that the runtime did not label OOMKilled")
		}
		return []Verdict{{
			Kind:       KindExitSignal,
			Confidence: Likely,
			Summary:    fmt.Sprintf("API reported exitCode=%d; by convention that is %s (128+%d), but the API does not say what sent it", code, name2, sig),
			Competing:  competing,
			Evidence:   ev,
		}}
	default:
		extra := ""
		switch code {
		case 126:
			extra = "; by convention 126 means command found but not executable"
		case 127:
			extra = "; by convention 127 means command not found"
		case 2:
			extra = "; by convention 2 often means misuse of a shell builtin, but its meaning is defined by the program"
		}
		if code > 128+64 {
			extra = "; the value is above 192, so it is not a Linux signal exit code and is reported as is"
		}
		if extra != "" {
			ev = append(ev, podEv(a.pod, EvConvention, "exit code", fmt.Sprintf("%d%s", code, extra), nil))
		}
		return []Verdict{{
			Kind:       KindAppExit,
			Confidence: Confirmed,
			Summary:    fmt.Sprintf("the container's main process exited with exitCode=%d (API reported exitCode=%d)%s", code, code, extra),
			Evidence:   ev,
		}}
	}
}

// trigger is a stop that has a known start time and a known grace period.
type trigger struct {
	start time.Time
	grace time.Duration
	why   string
}

func (a *analysis) probeKill(in *inst) ([]Verdict, *trigger) {
	term := in.term
	if isSynthesized(term) {
		return nil, nil
	}
	var best *corev1.Event
	var bestKind string
	bestMatch := matchNone
	var unhealthy []*corev1.Event
	for _, e := range a.podEvents {
		if containerOfEvent(e) != in.cs.Name {
			continue
		}
		m := a.instanceMatch(e, term)
		if m == matchNone {
			continue
		}
		if e.Reason == "Unhealthy" && strings.Contains(strings.ToLower(e.Message), "probe") {
			unhealthy = append(unhealthy, e)
			continue
		}
		if e.Reason != "Killing" {
			continue
		}
		var kind string
		switch {
		case strings.Contains(e.Message, "failed liveness probe"):
			kind = KindLivenessKill
		case strings.Contains(e.Message, "failed startup probe"):
			kind = KindStartupKill
		default:
			continue
		}
		// Events are sorted by time: keep the latest, but an exact match beats a weak one.
		if best == nil || m == matchExact || bestMatch != matchExact {
			best, bestKind, bestMatch = e, kind, m
		}
	}
	if best == nil {
		return nil, nil
	}
	ev := []Evidence{evEvent(best)}
	ev = append(ev, a.termEvidence(term, in.path)...)
	probe := "liveness"
	var pr *corev1.Probe
	if in.spec != nil {
		pr = in.spec.LivenessProbe
		if bestKind == KindStartupKill {
			probe, pr = "startup", in.spec.StartupProbe
		}
	}
	if pr != nil {
		ev = append(ev, podEv(a.pod, EvPodSpec, fmt.Sprintf("%s.%sProbe", in.specPath, probe), describeProbe(pr), nil))
		ev[len(ev)-1].Note = "failureThreshold is configured; the API does not report how many consecutive failures happened (event count is not a failure count)"
	}
	for i, u := range unhealthy {
		if i >= len(unhealthy)-3 {
			ev = append(ev, evEvent(u))
		}
	}
	v := Verdict{
		Kind:       bestKind,
		Confidence: Confirmed,
		Summary:    fmt.Sprintf("the kubelet reported stopping the container because it failed its %s probe (Killing event names the probe and this container, and its time lies inside this instance's lifetime and the %s window)", probe, a.o.Window),
		Evidence:   ev,
	}
	if bestMatch != matchExact {
		v.Confidence = Likely
		v.Summary += "; the event time is not firmly tied to this instance (boundary of its lifetime, unknown start time, or outside the correlation window)"
		v.Competing = append(v.Competing, "the Killing event belongs to an earlier or later instance of this container")
	} else if eventCount(best) > 1 {
		v.Summary += fmt.Sprintf(" (aggregated event, repeated %d times; its first or last occurrence is the match)", eventCount(best))
	}
	v.Competing = append(v.Competing, "the internal reason for each probe failure is only in the Unhealthy event text (context lines)")

	var trig *trigger
	if bestMatch == matchExact {
		_, last := eventTimes(best)
		if g, why, ok := a.probeGrace(pr, probe); ok {
			trig = &trigger{start: last, grace: g, why: why}
		}
	}
	return []Verdict{v}, trig
}

// probeGrace is the grace period the kubelet uses for a probe kill: the probe's
// own terminationGracePeriodSeconds when set, else the pod's (when the pod is
// not already being deleted, in which case deletionGracePeriodSeconds wins and
// is no longer known).
func (a *analysis) probeGrace(pr *corev1.Probe, probe string) (time.Duration, string, bool) {
	if a.pod.DeletionTimestamp != nil {
		return 0, "", false
	}
	if pr != nil && pr.TerminationGracePeriodSeconds != nil {
		return time.Duration(*pr.TerminationGracePeriodSeconds) * time.Second, probe + " probe terminationGracePeriodSeconds", true
	}
	if g := a.pod.Spec.TerminationGracePeriodSeconds; g != nil {
		return time.Duration(*g) * time.Second, "pod spec terminationGracePeriodSeconds", true
	}
	return 0, "", false
}

func describeProbe(pr *corev1.Probe) string {
	h := "handler"
	switch {
	case pr.Exec != nil:
		h = fmt.Sprintf("exec %v", pr.Exec.Command)
	case pr.HTTPGet != nil:
		h = fmt.Sprintf("httpGet %s:%s", pr.HTTPGet.Path, pr.HTTPGet.Port.String())
	case pr.TCPSocket != nil:
		h = "tcpSocket " + pr.TCPSocket.Port.String()
	case pr.GRPC != nil:
		h = fmt.Sprintf("grpc port %d", pr.GRPC.Port)
	}
	s := fmt.Sprintf("%s periodSeconds=%d failureThreshold=%d timeoutSeconds=%d", h, pr.PeriodSeconds, pr.FailureThreshold, pr.TimeoutSeconds)
	if pr.TerminationGracePeriodSeconds != nil {
		s += fmt.Sprintf(" terminationGracePeriodSeconds=%d", *pr.TerminationGracePeriodSeconds)
	}
	return s
}

// postStart reports a failed postStart hook as a fact (FailedPostStartHook
// event) and, separately, the kubelet's kill that the hook failure triggered.
// The event is recorded before the kill is attempted, so the kill is only
// confirmed when the explained instance's termination is tied to it.
func (a *analysis) postStart(in *inst) []Verdict {
	var failed, kills []*corev1.Event
	for _, e := range a.podEvents {
		if containerOfEvent(e) != in.cs.Name {
			continue
		}
		switch {
		case e.Reason == "FailedPostStartHook":
			failed = append(failed, e)
		case e.Reason == "Killing" && e.Message == "FailedPostStartHook":
			kills = append(kills, e)
		}
	}
	// Without a termination there is one instance only if it never restarted.
	noInstance := in.term == nil
	if noInstance && in.cs.RestartCount > 0 {
		return nil
	}
	if noInstance && in.cs.State.Running != nil {
		// Bind to the running instance: events before its start belong to nothing we can name.
		start := in.cs.State.Running.StartedAt.Time
		var keep []*corev1.Event
		for _, e := range failed {
			if _, l := eventTimes(e); !l.Before(start) {
				keep = append(keep, e)
			}
		}
		failed = keep
		keep = nil
		for _, e := range kills {
			if _, l := eventTimes(e); !l.Before(start) {
				keep = append(keep, e)
			}
		}
		kills = keep
	}
	var out []Verdict
	pick := func(es []*corev1.Event) (ev []Evidence, level int) {
		level = matchNone
		for _, e := range es {
			m := matchExact
			if !noInstance {
				m = a.instanceMatch(e, in.term)
			}
			if m == matchNone {
				continue
			}
			ev = append(ev, evEvent(e))
			if m == matchExact || level == matchNone {
				level = m
			}
		}
		return ev, level
	}
	if ev, lvl := pick(failed); lvl != matchNone {
		v := Verdict{Kind: KindPostStartFailed, Confidence: Confirmed, Evidence: ev,
			Summary: "the kubelet reported that the postStart lifecycle hook of this container failed (FailedPostStartHook event)"}
		if lvl != matchExact {
			v.Confidence = Likely
			v.Competing = []string{"the event is not firmly tied to this instance's lifetime"}
		}
		out = append(out, v)
	}
	if ev, lvl := pick(kills); lvl != matchNone {
		v := Verdict{Kind: KindPostStartKill, Confidence: Likely, Evidence: ev,
			Summary:   "the kubelet recorded killing the container because of the failed postStart hook",
			Competing: []string{"the event is recorded before the kill is attempted, so it does not show that the kill succeeded"}}
		if !noInstance && lvl == matchExact {
			v.Confidence = Confirmed
			v.Summary += "; this instance ended inside the same window"
			v.Competing = nil
		}
		out = append(out, v)
	}
	return out
}

func (a *analysis) nodeOOM(in *inst) []Verdict {
	term := in.term
	if isSynthesized(term) || (term.Reason != "OOMKilled" && term.ExitCode != 137) {
		return nil
	}
	var ev []Evidence
	for _, e := range a.nodeEvents {
		if e.Reason == "SystemOOM" && a.occursNear(e, term.FinishedAt.Time) {
			ev = append(ev, evEvent(e))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return []Verdict{{
		Kind:       KindNodeOOMCandidate,
		Confidence: Likely,
		Summary:    "a SystemOOM event on the node has a known occurrence inside the correlation window; it names a victim process, not this pod or container, so the link is not proven",
		Competing:  []string{"a container-level (cgroup limit) OOM kill unrelated to the node event", "another SIGKILL source"},
		Evidence:   append(ev, a.termEvidence(term, in.path)...),
	}}
}

// terminationStart returns the earliest evidence that a teardown of this pod
// began during the selected instance's lifetime: the DisruptionTarget
// transition, a "Stopping container" Killing event, an eviction or preemption
// event, a taint "Marking for deletion" that was not cancelled, or the deletion
// deadline minus a non-zero deletionGracePeriodSeconds. Anything outside the
// instance's lifetime belongs to an earlier or later stop episode and is ignored.
func (a *analysis) terminationStart(in *inst) (time.Time, bool) {
	p := a.pod
	var best time.Time
	inLife := func(t time.Time) bool {
		if t.IsZero() || in.term == nil || in.term.FinishedAt.IsZero() {
			return false
		}
		start := in.term.StartedAt.Time
		if start.IsZero() {
			return false
		}
		// An event before startedAt belongs to an earlier instance or episode.
		return !t.Before(start) && !t.After(in.term.FinishedAt.Add(time.Second))
	}
	consider := func(t time.Time) {
		if inLife(t) && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	if c := disruptionTarget(p); c != nil && c.Status == corev1.ConditionTrue {
		consider(c.LastTransitionTime.Time)
	}
	var lastCancel time.Time
	for _, e := range a.podEvents {
		if e.Reason == "TaintManagerEviction" && strings.HasPrefix(e.Message, "Cancelling deletion") {
			_, l := eventTimes(e)
			lastCancel = l
		}
	}
	for _, e := range a.podEvents {
		_, l := eventTimes(e)
		switch {
		case e.Reason == "Killing" && strings.HasPrefix(e.Message, "Stopping container") && containerOfEvent(e) == in.cs.Name:
			consider(l)
		case e.Reason == "Evicted" || e.Reason == "Preempting" || e.Reason == "Preempted":
			consider(l)
		case e.Reason == "TaintManagerEviction" && strings.HasPrefix(e.Message, "Marking for deletion") && !l.Before(lastCancel):
			consider(l)
		}
	}
	if p.DeletionTimestamp != nil && p.DeletionGracePeriodSeconds != nil && *p.DeletionGracePeriodSeconds > 0 {
		consider(p.DeletionTimestamp.Add(-time.Duration(*p.DeletionGracePeriodSeconds) * time.Second))
	}
	return best, !best.IsZero()
}

// teardownGrace is the grace period of a deletion-driven stop: the known,
// non-zero deletionGracePeriodSeconds. Once the kubelet has stopped everything
// it rewrites that field to 0, so the value used at kill time is then unknown
// and nothing is computed from the pod spec.
func (a *analysis) teardownGrace() (time.Duration, bool) {
	g := a.pod.DeletionGracePeriodSeconds
	if g == nil || *g <= 0 {
		return 0, false
	}
	return time.Duration(*g) * time.Second, true
}

func (a *analysis) graceVerdict(in *inst, probe *trigger) []Verdict {
	term := in.term
	if isSynthesized(term) || term.ExitCode != 137 || term.Reason == "OOMKilled" || term.FinishedAt.IsZero() {
		return nil
	}
	p := a.pod
	var trig *trigger
	switch {
	case probe != nil:
		trig = probe
	default:
		start, ok := a.terminationStart(in)
		g, gok := a.teardownGrace()
		if !ok || !gok {
			return nil
		}
		trig = &trigger{start: start, grace: g, why: "metadata.deletionGracePeriodSeconds"}
	}
	if term.FinishedAt.Sub(trig.start) < trig.grace-2*time.Second {
		return nil
	}
	ev := []Evidence{podEv(p, EvConvention, "grace period used", fmt.Sprintf("%ds from %s", int64(trig.grace/time.Second), trig.why), nil)}
	for _, e := range a.podEvents {
		if e.Reason == "Killing" && containerOfEvent(e) == in.cs.Name && a.instanceMatch(e, term) == matchExact {
			ev = append(ev, evEvent(e))
		}
	}
	if c := disruptionTarget(p); c != nil {
		ev = append(ev, podEv(p, EvPodCondition, "status.conditions[DisruptionTarget]", fmt.Sprintf("reason=%s", c.Reason), mt(c.LastTransitionTime)))
	}
	ev = append(ev, a.termEvidence(term, in.path)...)
	return []Verdict{{
		Kind:       KindKilledAfterGrace,
		Confidence: Likely,
		Summary:    fmt.Sprintf("the stop began at %s and the container ended with exitCode=137 %s later, at or after the %s grace period (%s): consistent with a SIGKILL after the grace period", trig.start.UTC().Format(time.RFC3339), term.FinishedAt.Sub(trig.start).Round(time.Second), trig.grace, trig.why),
		Competing: []string{
			"preStop hook time or an eviction override can change the effective grace",
			"an OOM kill not labelled OOMKilled, an external SIGKILL, or the application calling exit(137)",
		},
		Evidence: ev,
	}}
}

func (a *analysis) noTermination(in *inst) []Verdict {
	p := a.pod
	cs, base := in.cs, in.base
	switch {
	case cs.State.Waiting != nil:
		w := cs.State.Waiting
		switch w.Reason {
		case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull", "RegistryUnavailable":
			ev := []Evidence{podEv(p, EvPodStatus, base+".state.waiting.reason", w.Reason, nil)}
			if w.Message != "" {
				ev = append(ev, podEv(p, EvPodStatus, base+".state.waiting.message", w.Message, nil))
			}
			if in.spec != nil {
				ev = append(ev, podEv(p, EvPodSpec, in.specPath+".image", in.spec.Image, nil))
			}
			for _, e := range a.podEvents {
				if e.Reason == "Failed" || e.Reason == "BackOff" || e.Reason == "Pulling" {
					if c := containerOfEvent(e); c == "" || c == cs.Name {
						ev = append(ev, evEvent(e))
					}
				}
			}
			return []Verdict{{
				Kind:       KindImagePull,
				Confidence: Confirmed,
				Summary:    "the container has not started: the kubelet reports it cannot pull the image (waiting reason " + w.Reason + "); the registry error text is quoted verbatim",
				Evidence:   ev,
			}}
		case "CreateContainerConfigError", "CreateContainerError", "RunContainerError", "PostStartHookError":
			ev := []Evidence{podEv(p, EvPodStatus, base+".state.waiting.reason", w.Reason, nil)}
			if w.Message != "" {
				ev = append(ev, podEv(p, EvPodStatus, base+".state.waiting.message", w.Message, nil))
			}
			return []Verdict{{Kind: KindStartError, Confidence: Confirmed,
				Summary: "the container has not started: the kubelet reports waiting reason " + w.Reason + " (message quoted verbatim)", Evidence: ev}}
		}
		ev := []Evidence{podEv(p, EvPodStatus, base+".state.waiting.reason", w.Reason, nil)}
		return []Verdict{{Kind: KindNoTermination, Confidence: Confirmed,
			Summary: "no termination is recorded for this container; it is waiting (" + w.Reason + ")", Evidence: ev}}
	case cs.State.Running != nil:
		ev := []Evidence{podEv(p, EvPodStatus, base+".state.running.startedAt", fmtTime(mt(cs.State.Running.StartedAt)), mt(cs.State.Running.StartedAt))}
		ev = append(ev, podEv(p, EvPodStatus, base+".restartCount", fmt.Sprint(cs.RestartCount), nil))
		s := "no termination is recorded for this container: it is running and the status has no previous state"
		if cs.RestartCount > 0 {
			s = fmt.Sprintf("the container is running and the status has no previous state, but restartCount=%d says it restarted; the earlier terminations are not retained by the API (history is not available)", cs.RestartCount)
		} else {
			s += " (restartCount=0)"
		}
		if p.DeletionTimestamp != nil {
			s += "; the pod is being deleted but the container has not stopped yet"
		}
		return []Verdict{{Kind: KindNoTermination, Confidence: Confirmed, Summary: s, Evidence: ev}}
	}
	return []Verdict{{Kind: KindNoTermination, Confidence: NoData, Summary: "no state information in the pod status"}}
}

func (a *analysis) podTerminating() (bool, string) {
	p := a.pod
	switch {
	case p.DeletionTimestamp != nil:
		return true, "the pod is being deleted (metadata.deletionTimestamp is set)"
	case disruptionTarget(p) != nil && disruptionTarget(p).Status == corev1.ConditionTrue:
		return true, "the pod has a DisruptionTarget condition"
	case p.Status.Reason == "Evicted" || p.Status.Reason == "Preempting":
		return true, "the pod status reason is " + p.Status.Reason
	}
	return false, ""
}

// regularDone reports whether every regular container has finished for good:
// the pod is in a terminal phase, or each regular container is terminated now
// and its restart decision is "not restarting". The short gap between an exit
// and the restart of an Always container does not count. It also returns the
// latest finish time.
func (a *analysis) regularDone() (bool, time.Time) {
	p := a.pod
	var latest time.Time
	done := true
	n := 0
	for _, ref := range collect.AllStatuses(p) {
		if ref.Kind != "regular" {
			continue
		}
		n++
		in := a.newInst(ref)
		if t := ref.Status.State.Terminated; t != nil && t.FinishedAt.After(latest) {
			latest = t.FinishedAt.Time
		}
		// The app must really have terminated (a pod failing in init never ran it),
		// and unless the pod is terminal it must not be about to restart.
		if ref.Status.State.Terminated == nil || (!podTerminal(p) && a.restartDecision(in).Decision != "not-restarting") {
			done = false
		}
	}
	return n > 0 && done, latest
}

func (a *analysis) expectedness(in *inst) *Expectedness {
	term := in.term
	if term == nil {
		return nil
	}
	p := a.pod
	e := func(s, why string) *Expectedness { return &Expectedness{State: s, Why: why} }
	if isSynthesized(term) {
		return e(ExpectedUnknown, "the termination was synthesized by the kubelet (reason "+term.Reason+"); nothing shows whether the stop was intended")
	}
	if in.role == "ephemeral" {
		if term.ExitCode == 0 {
			return e(ExpectedYes, "an ephemeral container is never restarted, so exiting is its normal end; exit code 0")
		}
		return e(ExpectedUnknown, "an ephemeral (debug) container ended non-zero; the API does not say whether that was intended, and it is never restarted")
	}
	terminating, whyTerm := a.podTerminating()
	start, known := a.terminationStart(in)
	tied := terminating && known && !term.FinishedAt.Time.Before(start.Add(-time.Second))
	switch in.role {
	case "init":
		if term.ExitCode == 0 {
			return e(ExpectedYes, "init containers are expected to run to completion; exit code 0 is the normal result")
		}
		return e(ExpectedNo, "an init container exited non-zero; init containers must exit 0 for the pod to proceed")
	case "sidecar":
		if term.Reason == "OOMKilled" {
			return e(ExpectedNo, "the runtime reported an OOM kill of this sidecar; that is not a normal shutdown")
		}
		if tied {
			return e(ExpectedYes, "a restartable init container (native sidecar) is stopped when the pod is torn down: "+whyTerm+" (this instance ended after the teardown started)")
		}
		if done, latest := a.regularDone(); done && !term.FinishedAt.Time.Before(latest.Add(-time.Second)) {
			return e(ExpectedYes, "a restartable init container (native sidecar) is stopped when the pod's regular containers have finished for good; this instance ended after the last of them (exit codes such as 143 or 137 are normal for that shutdown)")
		}
		if term.ExitCode == 0 {
			return e(ExpectedUnknown, "the sidecar exited 0 while the pod's regular containers were not all finished; the API does not say whether that was intended")
		}
		return e(ExpectedNo, "the sidecar stopped while the rest of the pod was still running or restarting")
	}
	if terminating {
		switch {
		case !known:
			return e(ExpectedUnknown, whyTerm+", but no evidence ties a teardown start to this instance, so the stop cannot be called part of it")
		case !tied:
			return e(ExpectedUnknown, fmt.Sprintf("the pod is terminating (%s) but this instance ended at %s, before the teardown started at %s; it stopped for another reason", whyTerm, fmtTime(mt(term.FinishedAt)), start.UTC().Format(time.RFC3339)))
		}
		return e(ExpectedYes, "the stop is part of pod termination: "+whyTerm+" (this instance ended after the teardown started)")
	}
	policy := effectivePolicy(p, in.spec, in.role)
	if term.ExitCode == 0 {
		if policy == "Always" {
			return e(ExpectedUnknown, "the container exited 0 but its restart policy is Always, so the kubelet restarts it anyway; the API does not say whether a long-running container was meant to exit")
		}
		return e(ExpectedYes, "the container completed with exit code 0 and its restart policy is "+policy)
	}
	return e(ExpectedNo, "the container stopped with a non-zero exit code while its pod was not being terminated")
}

// matchRule evaluates restartPolicyRules in order against an exit code. It
// returns the first matching rule's index and action; unknown is set when a rule
// uses an operator or action this version does not know, with the rule quoted.
func matchRule(rules []corev1.ContainerRestartRule, code int32) (idx int, action corev1.ContainerRestartRuleAction, unknown string) {
	for i, r := range rules {
		if r.ExitCodes == nil {
			return -1, "", fmt.Sprintf("rule %d has no exitCodes condition: %+v", i, r)
		}
		in := false
		for _, v := range r.ExitCodes.Values {
			in = in || v == code
		}
		var hit bool
		switch r.ExitCodes.Operator {
		case corev1.ContainerRestartRuleOnExitCodesOpIn:
			hit = in
		case corev1.ContainerRestartRuleOnExitCodesOpNotIn:
			hit = !in
		default:
			return -1, "", fmt.Sprintf("rule %d uses unknown operator %q", i, r.ExitCodes.Operator)
		}
		if !hit {
			continue
		}
		if r.Action != corev1.ContainerRestartRuleActionRestart && r.Action != corev1.ContainerRestartRuleActionRestartAllContainers {
			return -1, "", fmt.Sprintf("rule %d matched with unknown action %q", i, r.Action)
		}
		return i, r.Action, ""
	}
	return -1, "", ""
}

func (a *analysis) restartDecision(in *inst) RestartDecision {
	p, cs, term := a.pod, in.cs, in.term
	policy := effectivePolicy(p, in.spec, in.role)
	d := RestartDecision{Policy: policy, Decision: "unknown"}
	if in.role == "ephemeral" {
		d.Policy = "never (ephemeral)"
		d.Decision = "not-restarting"
		d.Detail = "ephemeral containers are never restarted"
		return d
	}
	deleting := p.DeletionTimestamp != nil
	switch {
	case cs.State.Running != nil:
		d.Decision = "running"
		d.Detail = fmt.Sprintf("running since %s; restartCount=%d as reported now (it can reset when the pod is recreated)", fmtTime(mt(cs.State.Running.StartedAt)), cs.RestartCount)
	case podTerminal(p):
		d.Decision = "not-restarting"
		d.Detail = fmt.Sprintf("the pod is in the terminal phase %s, so the kubelet no longer restarts its containers (restart policy %s)", p.Status.Phase, policy)
	case deleting:
		// A deleting pod never restarts containers, whatever the container state says.
		d.Decision = "not-restarting"
		d.Detail = "the pod is being deleted; the kubelet does not start new containers for it"
	case cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff":
		d.Decision = "back-off"
		d.Detail = "the kubelet is delaying the next start (CrashLoopBackOff: exponential back-off, documented cap 5 minutes); the API does not report the remaining delay"
		d.Evidence = append(d.Evidence, podEv(p, EvPodStatus, in.base+".state.waiting.reason", "CrashLoopBackOff", nil))
	case cs.State.Waiting != nil:
		d.Detail = "waiting: " + cs.State.Waiting.Reason
	case term != nil && !in.fromLast:
		a.stopDecision(in, &d)
	}
	// RestartAllContainers on another container restarts this one too.
	if !deleting && !podTerminal(p) && d.Decision != "not-restarting" {
		if name, idx, ok := a.restartAllTrigger(cs.Name); ok {
			d.Decision = "restarting"
			d.Detail = fmt.Sprintf("container %s matched restartPolicyRules[%d] with action RestartAllContainers, so all containers of the pod restart", name, idx)
		}
	}
	for _, e := range a.podEvents {
		if e.Reason == "BackOff" && containerOfEvent(e) == cs.Name {
			d.Evidence = append(d.Evidence, evEvent(e))
		}
	}
	return d
}

// restartAllTrigger finds another container whose current termination matched a
// RestartAllContainers rule.
func (a *analysis) restartAllTrigger(except string) (name string, idx int, ok bool) {
	for _, ref := range collect.AllStatuses(a.pod) {
		t := ref.Status.State.Terminated
		if ref.Status.Name == except || t == nil {
			continue
		}
		spec, _ := containerSpec(a.pod, ref.Status.Name)
		if spec == nil || len(spec.RestartPolicyRules) == 0 {
			continue
		}
		if i, action, unknown := matchRule(spec.RestartPolicyRules, t.ExitCode); unknown == "" && i >= 0 && action == corev1.ContainerRestartRuleActionRestartAllContainers {
			return ref.Status.Name, i, true
		}
	}
	return "", 0, false
}

// stopDecision decides what happens after the current stop (state.terminated).
// It is only called for a pod that is neither deleting nor in a terminal phase.
func (a *analysis) stopDecision(in *inst, d *RestartDecision) {
	term := in.term
	policy := d.Policy
	if in.role == "init" && term.ExitCode == 0 {
		d.Decision = "done"
		d.Detail = "the init container completed successfully; it is not restarted"
		return
	}
	restart, prefix := false, ""
	if in.spec != nil && len(in.spec.RestartPolicyRules) > 0 {
		idx, action, unknown := matchRule(in.spec.RestartPolicyRules, term.ExitCode)
		switch {
		case unknown != "":
			d.Decision = "unknown"
			d.Detail = "restartPolicyRules cannot be evaluated by this version: " + unknown
			return
		case idx >= 0:
			restart = true
			prefix = fmt.Sprintf("restartPolicyRules[%d] matched exitCode=%d with action %s", idx, term.ExitCode, action)
			if action == corev1.ContainerRestartRuleActionRestartAllContainers {
				prefix += " (all containers of the pod are restarted)"
			}
		default:
			prefix = fmt.Sprintf("no restartPolicyRules entry matched exitCode=%d; the container restart policy applies: ", term.ExitCode)
		}
	}
	if !restart {
		switch {
		case in.role == "init":
			restart = policy != "Never"
			if restart {
				prefix += fmt.Sprintf("restart policy %s retries a failed init container (with back-off)", policy)
			} else {
				prefix += "restart policy Never: a failed init container is not retried and fails the pod"
			}
		case policy == "Never" || (policy == "OnFailure" && term.ExitCode == 0):
			prefix += fmt.Sprintf("restart policy %s does not restart a container that ended with exitCode=%d", policy, term.ExitCode)
		default:
			restart = true
			prefix += fmt.Sprintf("restart policy %s restarts this container (with back-off after repeated failures)", policy)
		}
	}
	if !restart {
		d.Decision = "not-restarting"
		d.Detail = prefix
		return
	}
	d.Decision, d.Detail = "restarting", prefix
	// The kubelet reports a delayed restart as a BackOff event. While it lasts the
	// status often still shows state.terminated instead of CrashLoopBackOff. Only
	// a recent event is a current back-off; an old one is history.
	var last time.Time
	for _, e := range a.podEvents {
		_, l := eventTimes(e)
		if e.Reason == "BackOff" && containerOfEvent(e) == in.cs.Name && !l.Before(term.FinishedAt.Add(-time.Second)) && l.After(last) {
			last = l
		}
	}
	switch {
	case last.IsZero():
	case a.s.CollectedAt.IsZero() || a.s.CollectedAt.Sub(last) <= 2*backoffCap:
		d.Decision = "back-off"
		d.Detail = prefix + "; a recent BackOff event was recorded after this stop, so the next start is delayed (exponential back-off, documented cap 5 minutes); the API does not report the remaining delay"
	default:
		d.Decision = "unknown"
		d.Detail = prefix + fmt.Sprintf("; the last BackOff event (%s) is historical relative to the observation, so whether a back-off is still running is unknown", fmtTime(tp(last)))
	}
}

// backoffCap is the documented maximum CrashLoopBackOff delay.
const backoffCap = 5 * time.Minute
