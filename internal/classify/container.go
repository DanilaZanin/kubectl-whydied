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

func (a *analysis) container(ref collect.StatusRef) ContainerReport {
	p := a.pod
	cs := ref.Status
	spec, role := containerSpec(p, cs.Name)
	if ref.Kind == "ephemeral" {
		role = "ephemeral"
	}
	cr := ContainerReport{Name: cs.Name, Role: role, Image: cs.Image, RestartCount: cs.RestartCount, CurrentState: currentState(cs)}
	term, fromLast := collect.LastTermination(cs)
	base := fmt.Sprintf("status.%s[%s]", statusListName(ref.Kind), cs.Name)

	if term != nil {
		src := "state.terminated"
		if fromLast {
			src = "lastState.terminated"
		}
		cr.Termination = &Termination{
			Source: src, ContainerID: term.ContainerID, ExitCode: term.ExitCode, Signal: term.Signal,
			Reason: term.Reason, Message: term.Message, StartedAt: mt(term.StartedAt), FinishedAt: mt(term.FinishedAt),
		}
	}

	var vs []Verdict
	if term != nil {
		path := base + "." + cr.Termination.Source
		causes := append(a.probeKill(cs.Name, spec, term, path), a.postStart(cs.Name, term)...)
		exit := a.exitVerdicts(spec, term, path, cs.Name)
		if term.Reason == "OOMKilled" {
			// The runtime's own report about this instance always comes first.
			vs = append(exit, causes...)
		} else {
			vs = append(causes, exit...)
		}
		vs = append(vs, a.nodeOOM(term, path)...)
		vs = append(vs, a.graceVerdict(cs.Name, term, path)...)
		if term.Reason == "ContainerStatusUnknown" && cs.LastTerminationState.Terminated != nil {
			// The synthesized status hides the real previous termination; show it too.
			prev := cs.LastTerminationState.Terminated
			cr.Previous = &Termination{Source: "lastState.terminated", ContainerID: prev.ContainerID, ExitCode: prev.ExitCode,
				Signal: prev.Signal, Reason: prev.Reason, Message: prev.Message, StartedAt: mt(prev.StartedAt), FinishedAt: mt(prev.FinishedAt)}
			for _, v := range a.exitVerdicts(spec, prev, base+".lastState.terminated", cs.Name) {
				v.Summary = "previous instance (lastState.terminated): " + v.Summary
				vs = append(vs, v)
			}
		}
	} else {
		vs = append(vs, a.postStart(cs.Name, nil)...)
		if len(vs) == 0 {
			vs = append(vs, a.noTermination(cs, base)...)
		}
	}
	if vs == nil {
		vs = []Verdict{}
	}
	cr.Verdicts = vs
	cr.Expected = a.expectedness(role, cs, term)
	cr.Restart = a.restartDecision(role, spec, cs, term, fromLast, base)
	return cr
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

func (a *analysis) exitVerdicts(spec *corev1.Container, term *corev1.ContainerStateTerminated, path, name string) []Verdict {
	ev := a.termEvidence(term, path)
	code := term.ExitCode
	switch {
	case term.Reason == "OOMKilled":
		limit := "no memory limit set in spec"
		if spec != nil {
			if q, ok := spec.Resources.Limits[corev1.ResourceMemory]; ok {
				limit = "spec memory limit " + q.String()
			}
		}
		ev = append(ev, podEv(a.pod, EvPodSpec, "spec.containers["+name+"].resources.limits.memory", limit, nil))
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
	case term.Reason == "ContainerStatusUnknown":
		return []Verdict{{
			Kind:       KindStatusUnknown,
			Confidence: Confirmed,
			Summary:    fmt.Sprintf("the kubelet could not observe how the container ended and synthesized exitCode=%d; the exit code carries no information about the cause", code),
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
	case code >= 129 && code <= 255:
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

func (a *analysis) probeKill(name string, spec *corev1.Container, term *corev1.ContainerStateTerminated, path string) []Verdict {
	var best *corev1.Event
	var bestKind string
	bestMatch := matchNone
	var unhealthy []*corev1.Event
	for _, e := range a.podEvents {
		if containerOfEvent(e) != name {
			continue
		}
		m := instanceMatch(e, term)
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
		// Events are sorted by time: keep the latest, but an exact match beats a spanning one.
		if best == nil || m == matchExact || bestMatch != matchExact {
			best, bestKind, bestMatch = e, kind, m
		}
	}
	if best == nil {
		return nil
	}
	ev := []Evidence{evEvent(best)}
	ev = append(ev, a.termEvidence(term, path)...)
	probe := "liveness"
	var pr *corev1.Probe
	if spec != nil {
		pr = spec.LivenessProbe
		if bestKind == KindStartupKill {
			probe, pr = "startup", spec.StartupProbe
		}
	}
	if pr != nil {
		ev = append(ev, podEv(a.pod, EvPodSpec, fmt.Sprintf("spec.containers[%s].%sProbe", name, probe), describeProbe(pr),
			nil))
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
		Summary:    fmt.Sprintf("the kubelet reported stopping the container because it failed its %s probe (Killing event names the probe and this container, and its time lies inside this instance's lifetime)", probe),
		Evidence:   ev,
	}
	if bestMatch == matchSpans {
		v.Confidence = Likely
		v.Summary += fmt.Sprintf("; the Killing event is aggregated (repeated %d times) and spans this instance, but none of its known occurrences lies inside the instance's lifetime", eventCount(best))
		v.Competing = append(v.Competing, "the kill may belong to an earlier or later instance: the times of the middle repetitions are not recorded")
	} else if eventCount(best) > 1 {
		v.Summary += fmt.Sprintf(" (aggregated event, repeated %d times; its first or last occurrence lies inside this instance's lifetime)", eventCount(best))
	}
	v.Competing = append(v.Competing, "the internal reason for each probe failure is only in the Unhealthy event text (context lines)")
	return []Verdict{v}
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

func (a *analysis) postStart(name string, term *corev1.ContainerStateTerminated) []Verdict {
	var hits []*corev1.Event
	for _, e := range a.podEvents {
		if containerOfEvent(e) != name {
			continue
		}
		if e.Reason == "FailedPostStartHook" || (e.Reason == "Killing" && e.Message == "FailedPostStartHook") {
			hits = append(hits, e)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	v := Verdict{Kind: KindPostStartFailed, Confidence: Confirmed,
		Summary: "the kubelet reported a failed postStart lifecycle hook for this container and killed it (FailedPostStartHook events)"}
	covered := term == nil
	for _, e := range hits {
		if term != nil && instanceMatch(e, term) != matchExact {
			continue
		}
		covered = true
		v.Evidence = append(v.Evidence, evEvent(e))
	}
	if !covered {
		return nil // the events belong to a different instance than the one explained
	}
	return []Verdict{v}
}

func (a *analysis) nodeOOM(term *corev1.ContainerStateTerminated, path string) []Verdict {
	if term.Reason != "OOMKilled" && term.ExitCode != 137 {
		return nil
	}
	var ev []Evidence
	for _, e := range a.nodeEvents {
		if e.Reason == "SystemOOM" && covers(e, term.FinishedAt.Time, a.o.Window) {
			ev = append(ev, evEvent(e))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	v := Verdict{
		Kind:       KindNodeOOMCandidate,
		Confidence: Likely,
		Summary:    "a SystemOOM event on the node falls inside the correlation window; it names a victim process, not this pod or container, so the link is not proven",
		Competing:  []string{"a container-level (cgroup limit) OOM kill unrelated to the node event", "another SIGKILL source"},
		Evidence:   append(ev, a.termEvidence(term, path)...),
	}
	return []Verdict{v}
}

// terminationStart returns the earliest time at which this pod's termination
// is known to have started for the container: the DisruptionTarget transition,
// a "Stopping container" Killing event, an eviction or preemption event, or the
// deletion deadline minus a non-zero deletionGracePeriodSeconds.
func (a *analysis) terminationStart(container string) (time.Time, bool) {
	p := a.pod
	var best time.Time
	consider := func(t time.Time) {
		if !t.IsZero() && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	if c := disruptionTarget(p); c != nil && c.Status == corev1.ConditionTrue {
		consider(c.LastTransitionTime.Time)
	}
	for _, e := range a.podEvents {
		_, l := eventTimes(e)
		switch {
		case e.Reason == "Killing" && strings.HasPrefix(e.Message, "Stopping container") && containerOfEvent(e) == container:
			consider(l)
		case e.Reason == "Evicted" || e.Reason == "Preempting" || e.Reason == "Preempted":
			consider(l)
		case e.Reason == "TaintManagerEviction" && strings.HasPrefix(e.Message, "Marking for deletion"):
			consider(l)
		}
	}
	if p.DeletionTimestamp != nil && p.DeletionGracePeriodSeconds != nil && *p.DeletionGracePeriodSeconds > 0 {
		consider(p.DeletionTimestamp.Add(-time.Duration(*p.DeletionGracePeriodSeconds) * time.Second))
	}
	return best, !best.IsZero()
}

func (a *analysis) effectiveGrace() time.Duration {
	if g := a.pod.Spec.TerminationGracePeriodSeconds; g != nil {
		return time.Duration(*g) * time.Second
	}
	return 30 * time.Second
}

func (a *analysis) graceVerdict(name string, term *corev1.ContainerStateTerminated, path string) []Verdict {
	p := a.pod
	if term.ExitCode != 137 || term.Reason == "OOMKilled" || term.FinishedAt.IsZero() {
		return nil
	}
	start, ok := a.terminationStart(name)
	if !ok {
		return nil
	}
	grace := a.effectiveGrace()
	if term.FinishedAt.Sub(start) < grace-2*time.Second {
		return nil
	}
	ev := []Evidence{podEv(p, EvPodSpec, "spec.terminationGracePeriodSeconds", fmt.Sprint(int64(grace/time.Second)), nil)}
	ev[0].Note = "pod-level value; a probe-level override, preStop time or eviction override can change the effective grace"
	for _, e := range a.podEvents {
		if e.Reason == "Killing" && strings.HasPrefix(e.Message, "Stopping container") && containerOfEvent(e) == name {
			ev = append(ev, evEvent(e))
		}
	}
	if c := disruptionTarget(p); c != nil {
		ev = append(ev, podEv(p, EvPodCondition, "status.conditions[DisruptionTarget]", fmt.Sprintf("reason=%s", c.Reason), mt(c.LastTransitionTime)))
	}
	ev = append(ev, a.termEvidence(term, path)...)
	return []Verdict{{
		Kind:       KindKilledAfterGrace,
		Confidence: Likely,
		Summary:    fmt.Sprintf("termination began at %s (earliest termination evidence) and the container ended with exitCode=137 %s later, at or after the %s grace period: consistent with a SIGKILL after the grace period", start.UTC().Format(time.RFC3339), term.FinishedAt.Sub(start).Round(time.Second), grace),
		Competing: []string{
			"the effective grace period can differ (probe-level override, preStop time, eviction override)",
			"an OOM kill not labelled OOMKilled, an external SIGKILL, or the application calling exit(137)",
		},
		Evidence: ev,
	}}
}

func (a *analysis) noTermination(cs *corev1.ContainerStatus, base string) []Verdict {
	p := a.pod
	switch {
	case cs.State.Waiting != nil:
		w := cs.State.Waiting
		switch w.Reason {
		case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull", "RegistryUnavailable":
			ev := []Evidence{podEv(p, EvPodStatus, base+".state.waiting.reason", w.Reason, nil)}
			if w.Message != "" {
				ev = append(ev, podEv(p, EvPodStatus, base+".state.waiting.message", w.Message, nil))
			}
			ev = append(ev, podEv(p, EvPodSpec, "image", cs.Image, nil))
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
		s := "no termination is recorded for this container: it is running with restartCount=0 and no previous state"
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

func (a *analysis) regularFinished() bool {
	p := a.pod
	if len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, c := range p.Status.ContainerStatuses {
		if c.State.Terminated == nil {
			return false
		}
	}
	return true
}

func (a *analysis) expectedness(role string, cs *corev1.ContainerStatus, term *corev1.ContainerStateTerminated) *Expectedness {
	if term == nil {
		return nil
	}
	p := a.pod
	spec, _ := containerSpec(p, cs.Name)
	policy := effectivePolicy(p, spec, role)
	terminating, whyTerm := a.podTerminating()
	e := func(s, why string) *Expectedness { return &Expectedness{State: s, Why: why} }
	switch role {
	case "init":
		if term.ExitCode == 0 {
			return e(ExpectedYes, "init containers are expected to run to completion; exit code 0 is the normal result")
		}
		return e(ExpectedNo, "an init container exited non-zero; init containers must exit 0 for the pod to proceed")
	case "sidecar":
		if terminating || podTerminal(p) || a.regularFinished() {
			return e(ExpectedYes, "a restartable init container (native sidecar) is stopped when the pod ends: all regular containers finished or the pod is terminating; exit codes such as 143 or 137 are normal for that shutdown")
		}
		if term.ExitCode == 0 {
			return e(ExpectedUnknown, "the sidecar exited 0 while the pod is still running; the API does not say whether that was intended")
		}
		return e(ExpectedNo, "the sidecar stopped while the rest of the pod is still running")
	}
	if terminating {
		start, known := a.terminationStart(cs.Name)
		switch {
		case !known:
			return e(ExpectedUnknown, whyTerm+", but no evidence shows when the termination started, so the stop cannot be tied to it")
		case term.FinishedAt.IsZero() || term.FinishedAt.Time.Before(start.Add(-time.Second)):
			return e(ExpectedUnknown, fmt.Sprintf("the pod is terminating (%s) but this instance ended at %s, before the termination started at %s; it stopped for another reason", whyTerm, fmtTime(mt(term.FinishedAt)), start.UTC().Format(time.RFC3339)))
		}
		return e(ExpectedYes, "the stop is part of pod termination: "+whyTerm+" (this instance ended after the termination started)")
	}
	if term.ExitCode == 0 {
		if policy == "Always" {
			return e(ExpectedUnknown, "the container exited 0 but its restart policy is Always, so the kubelet restarts it anyway; the API does not say whether a long-running container was meant to exit")
		}
		return e(ExpectedYes, "the container completed with exit code 0 and its restart policy is "+policy)
	}
	return e(ExpectedNo, "the container stopped with a non-zero exit code while its pod was not being terminated")
}

func (a *analysis) restartDecision(role string, spec *corev1.Container, cs *corev1.ContainerStatus, term *corev1.ContainerStateTerminated, fromLast bool, base string) RestartDecision {
	p := a.pod
	policy := effectivePolicy(p, spec, role)
	d := RestartDecision{Policy: policy, Decision: "unknown"}
	var notes []string
	if spec != nil && len(spec.RestartPolicyRules) > 0 {
		notes = append(notes, fmt.Sprintf("the container has %d restartPolicyRules that are not evaluated by kubectl-whydied", len(spec.RestartPolicyRules)))
	}
	switch {
	case cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff":
		d.Decision = "back-off"
		d.Detail = "the kubelet is delaying the next start (CrashLoopBackOff: exponential back-off, documented cap 5 minutes); the API does not report the remaining delay"
		d.Evidence = append(d.Evidence, podEv(p, EvPodStatus, base+".state.waiting.reason", "CrashLoopBackOff", nil))
	case cs.State.Waiting != nil:
		d.Detail = "waiting: " + cs.State.Waiting.Reason
	case cs.State.Running != nil:
		d.Decision = "running"
		d.Detail = fmt.Sprintf("running since %s; restartCount=%d as reported now (it can reset when the pod is recreated)", fmtTime(mt(cs.State.Running.StartedAt)), cs.RestartCount)
	case term != nil && !fromLast:
		switch {
		case podTerminal(p):
			d.Decision = "not-restarting"
			d.Detail = fmt.Sprintf("the pod is in the terminal phase %s, so the kubelet no longer restarts its containers (restart policy %s)", p.Status.Phase, policy)
		case policy == "Never" || (policy == "OnFailure" && term.ExitCode == 0):
			d.Decision = "not-restarting"
			d.Detail = fmt.Sprintf("restart policy %s does not restart a container that ended with exitCode=%d", policy, term.ExitCode)
		default:
			d.Decision = "restarting"
			d.Detail = fmt.Sprintf("restart policy %s restarts this container (with back-off after repeated failures)", policy)
		}
	}
	for _, e := range a.podEvents {
		if e.Reason == "BackOff" && containerOfEvent(e) == cs.Name {
			d.Evidence = append(d.Evidence, evEvent(e))
		}
	}
	if len(notes) > 0 {
		d.Detail += "; " + strings.Join(notes, "; ")
	}
	return d
}
