package classify

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func mtime(d time.Duration) metav1.Time { return metav1.NewTime(t0.Add(d)) }

type podOpt func(*corev1.Pod)

func newPod(opts ...podOpt) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns", UID: "pod-uid", CreationTimestamp: mtime(-time.Hour)},
		Spec: corev1.PodSpec{
			NodeName: "node1", RestartPolicy: corev1.RestartPolicyAlways,
			Containers: []corev1.Container{{Name: "app", Image: "img"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", Image: "img", RestartCount: 3, ContainerID: "containerd://new",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		}}},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func withLast(code int32, reason string) podOpt {
	return func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{
			ExitCode: code, Reason: reason, ContainerID: "containerd://old",
			StartedAt: mtime(-10 * time.Minute), FinishedAt: mtime(-time.Minute),
		}
	}
}

func withCond(reason, msg string) podOpt {
	return func(p *corev1.Pod) {
		p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: corev1.DisruptionTarget, Status: corev1.ConditionTrue, Reason: reason, Message: msg, LastTransitionTime: mtime(-time.Minute)})
	}
}

func event(reason, msg, field string, first, last time.Duration, count int32) corev1.Event {
	return corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: reason + msg},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web", Namespace: "ns", UID: "pod-uid", FieldPath: field},
		Reason:         reason, Message: msg, Count: count,
		FirstTimestamp: mtime(first), LastTimestamp: mtime(last),
	}
}

func snap(p *corev1.Pod, evs ...corev1.Event) *collect.Snapshot {
	return &collect.Snapshot{Version: 1, CollectedAt: t0, Namespace: "ns", Name: "web", Pod: p, Events: evs}
}

func find(r *Report, kind string) *Verdict {
	for _, v := range r.AllVerdicts() {
		if v.Kind == kind {
			v := v
			return &v
		}
	}
	return nil
}

func mustAnalyze(t *testing.T, s *collect.Snapshot) *Report {
	t.Helper()
	r, err := Analyze(s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name      string
		code      int32
		reason    string
		kind      string
		conf      Confidence
		textHas   string
		competing string
	}{
		{"oom", 137, "OOMKilled", KindOOMKill, Confirmed, "OOM kill", "OOM level is unknown"},
		{"exit0", 0, "Completed", KindAppExit, Confirmed, "exitCode=0", ""},
		{"exit1", 1, "Error", KindAppExit, Confirmed, "exitCode=1", ""},
		{"exit2", 2, "Error", KindAppExit, Confirmed, "exitCode=2", ""},
		{"exit127", 127, "StartError", KindStartError, Confirmed, "could not be started", ""},
		{"exit127app", 127, "Error", KindAppExit, Confirmed, "command not found", ""},
		{"exit137", 137, "Error", KindExitSignal, Likely, "SIGKILL", "exit(137) itself"},
		{"exit139", 139, "Error", KindExitSignal, Likely, "SIGSEGV", "exit(139) itself"},
		{"exit143", 143, "Error", KindExitSignal, Likely, "SIGTERM", "exit(143) itself"},
		{"unknown", 137, "ContainerStatusUnknown", KindStatusUnknown, Confirmed, "synthesized", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustAnalyze(t, snap(newPod(withLast(c.code, c.reason))))
			v := find(r, c.kind)
			if v == nil {
				t.Fatalf("no %s verdict: %+v", c.kind, r.AllVerdicts())
			}
			if v.Confidence != c.conf {
				t.Errorf("confidence = %s, want %s", v.Confidence, c.conf)
			}
			if !strings.Contains(v.Summary, c.textHas) {
				t.Errorf("summary %q lacks %q", v.Summary, c.textHas)
			}
			if c.competing != "" && !strings.Contains(strings.Join(v.Competing, "|"), c.competing) {
				t.Errorf("competing %v lacks %q", v.Competing, c.competing)
			}
			if len(v.Evidence) == 0 || v.Evidence[0].UID != "pod-uid" || v.Evidence[0].Kind != EvPodStatus {
				t.Errorf("first evidence should be pod status with uid: %+v", v.Evidence)
			}
		})
	}
}

// The negative case from the plan: exit(137) without OOM must never be a
// confirmed SIGKILL, and must not produce an OOM verdict.
func TestExit137IsNeverConfirmedSigkill(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withLast(137, "Error"))))
	for _, v := range r.AllVerdicts() {
		if v.Confidence == Confirmed && strings.Contains(v.Summary, "SIGKILL") {
			t.Errorf("confirmed verdict claims SIGKILL: %s", v.Summary)
		}
		if v.Kind == KindOOMKill {
			t.Errorf("unexpected OOM verdict")
		}
	}
}

func TestSignalFieldOnlyWhenAPISetsIt(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withLast(137, "Error"))))
	if r.Containers[0].Termination.Signal != 0 {
		t.Fatal("signal must stay 0 when the API does not set it")
	}
	for _, e := range find(r, KindExitSignal).Evidence {
		if strings.HasSuffix(e.Field, ".signal") {
			t.Fatalf("signal evidence invented: %+v", e)
		}
	}
}

func TestInstanceSelection(t *testing.T) {
	p := newPod(withLast(1, "Error"))
	p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 2, Reason: "Error", ContainerID: "containerd://newest", FinishedAt: mtime(-time.Second)}}
	r := mustAnalyze(t, snap(p))
	tm := r.Containers[0].Termination
	if tm.Source != "state.terminated" || tm.ExitCode != 2 || tm.ContainerID != "containerd://newest" {
		t.Fatalf("must explain state.terminated first: %+v", tm)
	}
	p2 := newPod(withLast(1, "Error"))
	tm = mustAnalyze(t, snap(p2)).Containers[0].Termination
	if tm.Source != "lastState.terminated" || tm.ContainerID != "containerd://old" {
		t.Fatalf("must fall back to lastState: %+v", tm)
	}
}

func TestProbeKill(t *testing.T) {
	probe := func(p *corev1.Pod) {
		p.Spec.Containers[0].LivenessProbe = &corev1.Probe{PeriodSeconds: 2, FailureThreshold: 3, TimeoutSeconds: 1,
			ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"cat", "/x"}}}}
	}
	kill := "Container app failed liveness probe, will be restarted"
	cases := []struct {
		name string
		evs  []corev1.Event
		kind string
		conf Confidence
	}{
		{"confirmed", []corev1.Event{
			event("Unhealthy", "Liveness probe failed: cat: can't open", "spec.containers{app}", -2*time.Minute, -time.Minute, 3),
			event("Killing", kill, "spec.containers{app}", -time.Minute, -time.Minute, 1)}, KindLivenessKill, Confirmed},
		{"aggregated", []corev1.Event{event("Killing", kill, "spec.containers{app}", -time.Hour, -time.Minute, 5)}, KindLivenessKill, Confirmed},
		{"startup", []corev1.Event{event("Killing", "Container app failed startup probe, will be restarted", "spec.containers{app}", -time.Minute, -time.Minute, 1)}, KindStartupKill, Confirmed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustAnalyze(t, snap(newPod(withLast(137, "Error"), probe), c.evs...))
			v := find(r, c.kind)
			if v == nil || v.Confidence != c.conf {
				t.Fatalf("got %+v, want %s %s", v, c.kind, c.conf)
			}
			if v.Evidence[0].Kind != EvEvent || v.Evidence[0].Time == nil {
				t.Errorf("first evidence must be the event with time: %+v", v.Evidence[0])
			}
		})
	}
	negatives := map[string][]corev1.Event{
		"other container":  {event("Killing", "Container side failed liveness probe, will be restarted", "spec.containers{side}", -time.Minute, -time.Minute, 1)},
		"unhealthy only":   {event("Unhealthy", "Liveness probe failed: x", "spec.containers{app}", -time.Minute, -time.Minute, 4)},
		"earlier instance": {event("Killing", kill, "spec.containers{app}", -50*time.Minute, -50*time.Minute, 1)},
		"later instance":   {event("Killing", kill, "spec.containers{app}", time.Minute, time.Minute, 1)},
		"generic stopping": {event("Killing", "Stopping container app", "spec.containers{app}", -time.Minute, -time.Minute, 1)},
	}
	for name, evs := range negatives {
		t.Run("no kill: "+name, func(t *testing.T) {
			r := mustAnalyze(t, snap(newPod(withLast(137, "Error"), probe), evs...))
			if find(r, KindLivenessKill) != nil || find(r, KindStartupKill) != nil {
				t.Fatal("probe kill must not be claimed")
			}
		})
	}
}

func TestEventsMatchedByUID(t *testing.T) {
	other := event("Killing", "Container app failed liveness probe, will be restarted", "spec.containers{app}", -time.Minute, -time.Minute, 1)
	other.InvolvedObject.UID = "older-pod-uid"
	r := mustAnalyze(t, snap(newPod(withLast(1, "Error")), other))
	if find(r, KindLivenessKill) != nil {
		t.Fatal("event of another UID must not be used")
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "different UID") || !strings.Contains(r.Notes[0], "older-pod-uid") {
		t.Fatalf("ignored events must be reported: %v", r.Notes)
	}
}

func TestDisruption(t *testing.T) {
	cases := []struct {
		name string
		opts []podOpt
		evs  []corev1.Event
		kind string
	}{
		{"scheduler preemption", []podOpt{withCond("PreemptionByScheduler", "preempted")}, nil, KindPreemptScheduler},
		{"preempted event only", nil, []corev1.Event{event("Preempted", "Preempted by pod x on node node1", "", -time.Minute, -time.Minute, 1)}, KindPreemptScheduler},
		{"taint", []podOpt{withCond("DeletionByTaintManager", "taint")}, []corev1.Event{event("TaintManagerEviction", "Marking for deletion Pod ns/web", "", -time.Minute, -time.Minute, 1)}, KindTaintEviction},
		{"eviction api", []podOpt{withCond("EvictionByEvictionAPI", "Eviction API: evicting")}, nil, KindEvictionAPI},
		{"pod gc", []podOpt{withCond("DeletionByPodGC", "node gone")}, nil, KindPodGC},
		{"kubelet termination", []podOpt{withCond("TerminationByKubelet", "node shutdown")}, nil, KindKubeletTermination},
		{"storage emptydir", []podOpt{withCond("TerminationByKubelet", "m"), func(p *corev1.Pod) {
			p.Status.Phase, p.Status.Reason, p.Status.Message = corev1.PodFailed, "Evicted", `Usage of EmptyDir volume "data" exceeds the limit "10Mi". `
		}}, nil, KindEvictionStorage},
		{"storage container", []podOpt{func(p *corev1.Pod) {
			p.Status.Phase, p.Status.Reason, p.Status.Message = corev1.PodFailed, "Evicted", `Container app exceeded its local ephemeral storage limit "1Gi". `
		}}, nil, KindEvictionStorage},
		{"node pressure", []podOpt{func(p *corev1.Pod) {
			p.Status.Phase, p.Status.Reason, p.Status.Message = corev1.PodFailed, "Evicted", "The node was low on resource: memory. Threshold quantity: 100Mi, available: 50Mi. "
		}}, nil, KindEvictionNodePress},
		{"kubelet preempting", []podOpt{func(p *corev1.Pod) {
			p.Status.Phase, p.Status.Reason, p.Status.Message = corev1.PodFailed, "Preempting", "Preempted in order to admit critical pod"
		}}, nil, KindPreemptKubelet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustAnalyze(t, snap(newPod(c.opts...), c.evs...))
			if len(r.Verdicts) == 0 || r.Verdicts[0].Kind != c.kind || r.Verdicts[0].Confidence != Confirmed {
				t.Fatalf("pod verdicts = %+v, want %s confirmed", r.Verdicts, c.kind)
			}
		})
	}
	t.Run("storage eviction is not node pressure", func(t *testing.T) {
		r := mustAnalyze(t, snap(newPod(func(p *corev1.Pod) {
			p.Status.Reason, p.Status.Message = "Evicted", `Usage of EmptyDir volume "d" exceeds the limit "1Mi". `
		})))
		if find(r, KindEvictionNodePress) != nil {
			t.Fatal("storage-limit eviction must not be reported as node pressure")
		}
	})
}

func TestTaintCancellation(t *testing.T) {
	evs := []corev1.Event{
		event("TaintManagerEviction", "Marking for deletion Pod ns/web", "", -5*time.Minute, -5*time.Minute, 1),
		event("TaintManagerEviction", "Cancelling deletion of Pod ns/web", "", -4*time.Minute, -4*time.Minute, 1),
	}
	r := mustAnalyze(t, snap(newPod(), evs...))
	if find(r, KindTaintCancelled) == nil || find(r, KindTaintEviction) != nil {
		t.Fatalf("cancellation must not be reported as eviction: %+v", r.Verdicts)
	}
}

func controllerOwners() []collect.Owner {
	return []collect.Owner{
		{Kind: "ReplicaSet", Name: "web-abc", UID: "rs-uid", Found: true, Revision: "1"},
		{Kind: "Deployment", Name: "web", UID: "dep-uid", Found: true, Revision: "2"},
	}
}

func ownerEvent(uid types.UID, kind, reason, msg string) corev1.Event {
	return corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: reason + string(uid)},
		InvolvedObject: corev1.ObjectReference{Kind: kind, Name: "x", Namespace: "ns", UID: uid},
		Reason:         reason, Message: msg, Count: 1, FirstTimestamp: mtime(-time.Minute), LastTimestamp: mtime(-time.Minute)}
}

func TestControllerDelete(t *testing.T) {
	del := p0Delete("web")
	t.Run("rollout", func(t *testing.T) {
		s := snap(newPod(func(p *corev1.Pod) { p.DeletionTimestamp = ptr(mtime(time.Minute)) }), del)
		s.Owners = controllerOwners()
		r := mustAnalyze(t, s)
		cd, sr := find(r, KindControllerDelete), find(r, KindScaleRollout)
		if cd == nil || cd.Confidence != Confirmed {
			t.Fatalf("controller delete missing: %+v", r.Verdicts)
		}
		if sr == nil || sr.Confidence != Likely {
			t.Fatalf("rollout reason must be likely: %+v", sr)
		}
		if find(r, KindDeletionUnattrib) != nil {
			t.Fatal("must not also report unattributed deletion")
		}
	})
	t.Run("manual scale has no rollout claim", func(t *testing.T) {
		s := snap(newPod(func(p *corev1.Pod) { p.DeletionTimestamp = ptr(mtime(time.Minute)) }), del)
		s.Owners = controllerOwners()
		s.Owners[0].Revision, s.Owners[1].Revision = "2", "2"
		r := mustAnalyze(t, s)
		if find(r, KindControllerDelete) == nil || find(r, KindScaleRollout) != nil {
			t.Fatalf("got %+v", r.Verdicts)
		}
	})
	t.Run("event for a similarly named pod is ignored", func(t *testing.T) {
		s := snap(newPod(), p0Delete("web-1"))
		s.Owners = controllerOwners()
		if find(mustAnalyze(t, s), KindControllerDelete) != nil {
			t.Fatal("web-1 event must not match pod web")
		}
	})
	t.Run("event older than the pod is ignored", func(t *testing.T) {
		old := p0Delete("web")
		old.LastTimestamp, old.FirstTimestamp = mtime(-2*time.Hour), mtime(-2*time.Hour)
		s := snap(newPod(), old)
		s.Owners = controllerOwners()
		if find(mustAnalyze(t, s), KindControllerDelete) != nil {
			t.Fatal("event before pod creation must not match")
		}
	})
}

func p0Delete(pod string) corev1.Event {
	return ownerEvent("rs-uid", "ReplicaSet", "SuccessfulDelete", "Deleted pod: "+pod)
}

func ptr[T any](v T) *T { return &v }

func TestUserDeleteIsUnattributed(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(time.Minute))
		p.DeletionGracePeriodSeconds = ptr(int64(90))
	})))
	v := find(r, KindDeletionUnattrib)
	if v == nil || v.Confidence != Likely {
		t.Fatalf("got %+v", r.Verdicts)
	}
	if !strings.Contains(strings.Join(v.Competing, "|"), "audit log") {
		t.Errorf("must name the missing audit log: %v", v.Competing)
	}
}

func TestPodGone(t *testing.T) {
	s := &collect.Snapshot{CollectedAt: t0, Namespace: "ns", Name: "web",
		Events: []corev1.Event{event("Killing", "Stopping container app", "spec.containers{app}", -time.Minute, -time.Minute, 1)}}
	r := mustAnalyze(t, s)
	if len(r.Verdicts) != 1 || r.Verdicts[0].Kind != KindPodGone || r.Verdicts[0].Confidence != NoData {
		t.Fatalf("got %+v", r.Verdicts)
	}
	if !r.HasData() {
		t.Error("events still referencing the name count as data for the exit code")
	}
	empty := mustAnalyze(t, &collect.Snapshot{CollectedAt: t0, Namespace: "ns", Name: "web"})
	if empty.HasData() {
		t.Error("no pod and no events must be exit code 2 material")
	}
	if len(empty.Gaps) == 0 {
		t.Error("expired events must be reported as a gap")
	}
}

func TestRolesAndExpectedness(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	mk := func(role string, code int32, mod func(*corev1.Pod)) *ContainerReport {
		p := newPod()
		st := corev1.ContainerStatus{Name: "c", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code, Reason: "x", FinishedAt: mtime(-time.Second)}}}
		switch role {
		case "init":
			p.Spec.InitContainers = []corev1.Container{{Name: "c"}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{st}
		case "sidecar":
			p.Spec.InitContainers = []corev1.Container{{Name: "c", RestartPolicy: &always}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{st}
		default:
			p.Spec.Containers[0].Name = "c"
			p.Status.ContainerStatuses = []corev1.ContainerStatus{st}
		}
		if mod != nil {
			mod(p)
		}
		r, err := Analyze(snap(p), Options{Container: "c"})
		if err != nil {
			t.Fatal(err)
		}
		return &r.Containers[0]
	}
	finished := func(p *corev1.Pod) {
		p.Status.Phase = corev1.PodSucceeded
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
	}
	cases := []struct {
		name  string
		c     *ContainerReport
		role  string
		state string
	}{
		{"init ok", mk("init", 0, nil), "init", ExpectedYes},
		{"init failed", mk("init", 3, nil), "init", ExpectedNo},
		{"sidecar at job end", mk("sidecar", 137, finished), "sidecar", ExpectedYes},
		{"sidecar dies early", mk("sidecar", 1, nil), "sidecar", ExpectedNo},
		{"regular always exit 0", mk("regular", 0, nil), "regular", ExpectedUnknown},
		{"regular never exit 0", mk("regular", 0, func(p *corev1.Pod) { p.Spec.RestartPolicy = corev1.RestartPolicyNever }), "regular", ExpectedYes},
		{"regular crash", mk("regular", 1, nil), "regular", ExpectedNo},
		{"regular stopped while deleting", mk("regular", 143, func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.StartedAt = mtime(-time.Hour)
			p.DeletionTimestamp = ptr(mtime(time.Minute))
			withCond("EvictionByEvictionAPI", "x")(p) // transition at -1m, instance ended at -1s
		}), "regular", ExpectedYes},
		{"crashed before the deletion started", mk("regular", 1, func(p *corev1.Pod) {
			p.DeletionTimestamp = ptr(mtime(time.Minute))
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.DisruptionTarget, Status: corev1.ConditionTrue, Reason: "EvictionByEvictionAPI", LastTransitionTime: mtime(time.Second)}}
		}), "regular", ExpectedNo},
		{"deleting without any start evidence", mk("regular", 1, func(p *corev1.Pod) { p.DeletionTimestamp = ptr(mtime(time.Minute)) }), "regular", ExpectedUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.c.Role != c.role || c.c.Expected == nil || c.c.Expected.State != c.state {
				t.Fatalf("role=%s expected=%+v, want %s/%s", c.c.Role, c.c.Expected, c.role, c.state)
			}
		})
	}
}

func termNow(code int32, finish time.Duration) corev1.ContainerState {
	return corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code, Reason: "Error", StartedAt: mtime(finish - time.Minute), FinishedAt: mtime(finish)}}
}

func TestRestartDecision(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withLast(1, "Error"))))
	if d := r.Containers[0].Restart; d.Decision != "back-off" || d.Policy != "Always" {
		t.Fatalf("%+v", d)
	}
	p := newPod(func(p *corev1.Pod) {
		p.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
		p.Status.Phase = corev1.PodSucceeded
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}}
	})
	if d := mustAnalyze(t, snap(p)).Containers[0].Restart; d.Decision != "not-restarting" {
		t.Fatalf("%+v", d)
	}
}

// restartPolicyRules are evaluated in order; the first match wins (item 3).
func TestRestartPolicyRules(t *testing.T) {
	mk := func(code int32, rules []corev1.ContainerRestartRule) RestartDecision {
		p := newPod(func(p *corev1.Pod) {
			never := corev1.ContainerRestartPolicyNever
			p.Spec.Containers[0].RestartPolicy = &never
			p.Spec.Containers[0].RestartPolicyRules = rules
			p.Status.ContainerStatuses[0].State = termNow(code, -time.Second)
		})
		return mustAnalyze(t, snap(p)).Containers[0].Restart
	}
	in42 := corev1.ContainerRestartRule{Action: corev1.ContainerRestartRuleActionRestart, ExitCodes: &corev1.ContainerRestartRuleOnExitCodes{Operator: corev1.ContainerRestartRuleOnExitCodesOpIn, Values: []int32{42}}}
	if d := mk(42, []corev1.ContainerRestartRule{in42}); d.Decision != "restarting" || !strings.Contains(d.Detail, "restartPolicyRules[0]") {
		t.Fatalf("Never + rule Restart for 42 and exit 42 must restart: %+v", d)
	}
	if d := mk(1, []corev1.ContainerRestartRule{in42}); d.Decision != "not-restarting" || d.Policy != "Never" || !strings.Contains(d.Detail, "no restartPolicyRules entry matched") {
		t.Fatalf("no rule matches: container policy applies: %+v", d)
	}
	all := corev1.ContainerRestartRule{Action: corev1.ContainerRestartRuleActionRestartAllContainers, ExitCodes: &corev1.ContainerRestartRuleOnExitCodes{Operator: corev1.ContainerRestartRuleOnExitCodesOpNotIn, Values: []int32{0}}}
	if d := mk(3, []corev1.ContainerRestartRule{in42, all}); d.Decision != "restarting" || !strings.Contains(d.Detail, "RestartAllContainers") || !strings.Contains(d.Detail, "[1]") {
		t.Fatalf("first matching rule incl. RestartAllContainers: %+v", d)
	}
	bad := corev1.ContainerRestartRule{Action: corev1.ContainerRestartRuleActionRestart, ExitCodes: &corev1.ContainerRestartRuleOnExitCodes{Operator: "Weird", Values: []int32{1}}}
	if d := mk(1, []corev1.ContainerRestartRule{bad}); d.Decision != "unknown" || !strings.Contains(d.Detail, "Weird") {
		t.Fatalf("unknown operator must give unknown with the rule quoted: %+v", d)
	}
}

// Role matters before policy (item 2).
func TestRestartMatrixByRole(t *testing.T) {
	init0 := newPod(func(p *corev1.Pod) {
		p.Spec.InitContainers = []corev1.Container{{Name: "setup"}}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "setup", State: termNow(0, -time.Minute)}}
		p.Status.InitContainerStatuses[0].State.Terminated.Reason = "Completed"
	})
	r := mustAnalyze(t, snap(init0))
	for _, c := range r.Containers {
		if c.Name == "setup" && c.Restart.Decision != "done" {
			t.Fatalf("a completed init container is done, not restarting: %+v", c.Restart)
		}
	}
	eph := newPod(func(p *corev1.Pod) {
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg"}}}
		p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "dbg", State: termNow(1, -time.Minute)}}
	})
	for _, c := range mustAnalyze(t, snap(eph)).Containers {
		if c.Name == "dbg" && (c.Restart.Decision != "not-restarting" || !strings.Contains(c.Restart.Detail, "never restarted")) {
			t.Fatalf("ephemeral containers are never restarted: %+v", c.Restart)
		}
	}
	del := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(time.Minute))
		p.Status.ContainerStatuses[0].State = termNow(1, -time.Second)
	})
	if d := mustAnalyze(t, snap(del)).Containers[0].Restart; d.Decision != "not-restarting" {
		t.Fatalf("a terminating pod in a non-terminal phase does not restart containers: %+v", d)
	}
}

func TestNodeSignals(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", UID: "node-uid"},
		Spec:   corev1.NodeSpec{Taints: []corev1.Taint{{Key: "k", Value: "v", Effect: corev1.TaintEffectNoExecute}}},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, Message: "Kubelet stopped posting node status.", LastTransitionTime: mtime(-3 * time.Minute)}}}}
	s := snap(newPod(withLast(137, "Error")))
	s.Node = node
	r := mustAnalyze(t, s)
	nr := find(r, KindNodeNotReady)
	if nr == nil || !strings.Contains(nr.Summary, "not that this container stopped") {
		t.Fatalf("node NotReady must be 'unobservable', not a container death: %+v", nr)
	}
	foundTaint := false
	for _, e := range r.Context {
		foundTaint = foundTaint || (e.Field == "spec.taints" && e.Value == "k=v:NoExecute")
	}
	if !foundTaint {
		t.Error("taints must appear as context")
	}
	for _, v := range r.AllVerdicts() {
		if v.Kind == KindTaintEviction {
			t.Error("a taint alone must not produce a verdict")
		}
	}
}

func TestSystemOOMIsOnlyACandidate(t *testing.T) {
	s := snap(newPod(withLast(137, "Error")))
	s.Events = append(s.Events, corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "oom"},
		InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: "node1", UID: "node1"},
		Reason:         "SystemOOM", Message: "System OOM encountered, victim process: x, pid: 1", Count: 1, FirstTimestamp: mtime(-time.Minute), LastTimestamp: mtime(-time.Minute)})
	r := mustAnalyze(t, s)
	v := find(r, KindNodeOOMCandidate)
	if v == nil || v.Confidence != Likely {
		t.Fatalf("got %+v", v)
	}
	if find(r, KindOOMKill) != nil {
		t.Fatal("a node event alone must not become an OOMKilled verdict")
	}
}

func TestKilledAfterGrace(t *testing.T) {
	mk := func(grace int64, finishAfterStart time.Duration) *Report {
		p := newPod(func(p *corev1.Pod) {
			p.DeletionTimestamp = ptr(mtime(time.Duration(grace) * time.Second))
			p.DeletionGracePeriodSeconds = ptr(grace)
			p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", StartedAt: mtime(-time.Hour), FinishedAt: mtime(finishAfterStart)}}
		})
		return mustAnalyze(t, snap(p, event("Killing", "Stopping container app", "spec.containers{app}", 0, 0, 1)))
	}
	if v := find(mk(30, 31*time.Second), KindKilledAfterGrace); v == nil || v.Confidence != Likely || len(v.Competing) == 0 {
		t.Fatalf("got %+v", v)
	}
	// deletionGracePeriodSeconds=90 is known: a stop 35s after the start is within it (item 6).
	if find(mk(90, 35*time.Second), KindKilledAfterGrace) != nil {
		t.Fatal("35s of a 90s grace period is not after the grace period")
	}
	if find(mk(90, 91*time.Second), KindKilledAfterGrace) == nil {
		t.Fatal("91s of a 90s grace period is after it")
	}
}

func TestImagePullAndStartError(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].RestartCount = 0
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: `Back-off pulling image "x"`}}
	})
	v := find(mustAnalyze(t, snap(p)), KindImagePull)
	if v == nil || v.Confidence != Confirmed {
		t.Fatalf("got %+v", v)
	}
}

func TestNoTermination(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].RestartCount = 0
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: mtime(-time.Hour)}}
	})
	r := mustAnalyze(t, snap(p))
	v := find(r, KindNoTermination)
	if v == nil || v.Confidence != Confirmed {
		t.Fatalf("got %+v", v)
	}
	if r.Containers[0].Termination != nil {
		t.Fatal("no termination to explain")
	}
}

func TestGapsAreNotEvidence(t *testing.T) {
	s := snap(newPod(withLast(1, "Error")))
	s.Gaps = []collect.Gap{{Source: "events for pod name", Reason: "forbidden by RBAC: events is forbidden"}}
	r := mustAnalyze(t, s)
	for _, g := range r.Gaps {
		if strings.Contains(g.Reason, "expire") {
			t.Fatalf("events are not readable: the expiry gap must not be added: %+v", g)
		}
	}
	checked := strings.Join(r.Checked, "|")
	if !strings.Contains(checked, "events: not readable (RBAC)") || strings.Contains(checked, "0 found") {
		t.Fatalf("Checked must say events were not readable: %v", r.Checked)
	}
	if v := find(r, KindAppExit); v == nil || v.Confidence != Confirmed {
		t.Fatalf("a terminated state alone confirms the exit; missing events must not change it: %+v", v)
	}
}

func TestExpiredEventsGap(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withLast(1, "Error"))))
	found := false
	for _, g := range r.Gaps {
		found = found || strings.Contains(g.Reason, "expire")
	}
	if !found {
		t.Fatalf("no events and no RBAC error: the expiry gap is expected: %+v", r.Gaps)
	}
}

func TestStaleDeletionGraceIsNotUsed(t *testing.T) {
	// deletionGracePeriodSeconds is 0 once the kubelet has stopped everything. The
	// grace used at kill time is then unknown; it must not be guessed from the spec.
	p := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(0))
		p.DeletionGracePeriodSeconds = ptr(int64(0))
		p.Spec.TerminationGracePeriodSeconds = ptr(int64(30))
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", StartedAt: mtime(-time.Minute), FinishedAt: mtime(0)}}
	})
	late := event("Killing", "Stopping container app", "spec.containers{app}", -31*time.Second, -31*time.Second, 1)
	if find(mustAnalyze(t, snap(p, late)), KindKilledAfterGrace) != nil {
		t.Fatal("grace is unknown after deletionGracePeriodSeconds was zeroed: no verdict")
	}
}

// Probe kills use the probe-level grace, not the pod's (item 6).
func TestProbeKillGrace(t *testing.T) {
	mk := func(probeGrace *int64, finish time.Duration) *Report {
		p := newPod(func(p *corev1.Pod) {
			p.Spec.TerminationGracePeriodSeconds = ptr(int64(30))
			p.Spec.Containers[0].LivenessProbe = &corev1.Probe{TerminationGracePeriodSeconds: probeGrace}
			p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", StartedAt: mtime(-time.Hour), FinishedAt: mtime(finish)}}
		})
		return mustAnalyze(t, snap(p, event("Killing", "Container app failed liveness probe, will be restarted", "spec.containers{app}", 0, 0, 1)))
	}
	if find(mk(ptr(int64(90)), 35*time.Second), KindKilledAfterGrace) != nil {
		t.Fatal("probe grace 90s: 35s is within it")
	}
	if find(mk(nil, 35*time.Second), KindKilledAfterGrace) == nil {
		t.Fatal("pod grace 30s applies when the probe has none")
	}
}

func TestSynthesizedStatusShowsRealPreviousTermination(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "ContainerStatusUnknown", FinishedAt: mtime(0)}}
	}, withLast(7, "Error"))
	r := mustAnalyze(t, snap(p))
	c := r.Containers[0]
	if c.Previous == nil || c.Previous.ExitCode != 7 {
		t.Fatalf("real lastState must be shown: %+v", c.Previous)
	}
	if find(r, KindStatusUnknown) == nil || !strings.Contains(strings.Join(summaries(c.Verdicts), "|"), "previous instance") {
		t.Fatalf("%+v", c.Verdicts)
	}
}

func summaries(vs []Verdict) []string {
	var o []string
	for _, v := range vs {
		o = append(o, v.Summary)
	}
	return o
}

func TestProbeEventsMustBelongToTheInstance(t *testing.T) {
	// a16: the last instance was OOMKilled; the Killing event is from an earlier one.
	p := newPod(withLast(137, "OOMKilled"))
	r := mustAnalyze(t, snap(p, event("Killing", "Container app failed liveness probe, will be restarted", "spec.containers{app}", -time.Hour, -30*time.Minute, 1)))
	if find(r, KindLivenessKill) != nil || r.Containers[0].Verdicts[0].Kind != KindOOMKill {
		t.Fatalf("%+v", r.Containers[0].Verdicts)
	}
	// Both in the instance: OOM still comes first.
	r = mustAnalyze(t, snap(p, event("Killing", "Container app failed liveness probe, will be restarted", "spec.containers{app}", -2*time.Minute, -time.Minute, 1)))
	if r.Containers[0].Verdicts[0].Kind != KindOOMKill {
		t.Fatalf("an OOMKilled instance must lead with the runtime's report: %+v", r.Containers[0].Verdicts)
	}
}

func TestJSONListsAreNeverNull(t *testing.T) {
	r := mustAnalyze(t, &collect.Snapshot{CollectedAt: t0, Namespace: "ns", Name: "web"})
	if r.Containers == nil || r.Verdicts == nil {
		t.Fatal("containers and verdicts must be empty lists, not null")
	}
	r = mustAnalyze(t, snap(newPod()))
	if r.Verdicts == nil {
		t.Fatal("pod verdicts must be an empty list")
	}
}

func TestRestartTextForTerminalPod(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.Phase = corev1.PodFailed
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error", FinishedAt: mtime(0)}}
	})
	d := mustAnalyze(t, snap(p)).Containers[0].Restart
	if !strings.Contains(d.Detail, "terminal phase") || strings.Contains(d.Detail, "restart policy Always does not restart") {
		t.Fatalf("%q", d.Detail)
	}
}

func TestUnknownContainer(t *testing.T) {
	if _, err := Analyze(snap(newPod()), Options{Container: "nope"}); err == nil {
		t.Fatal("unknown container must be an error")
	}
}

func TestContainerFilter(t *testing.T) {
	p := newPod(withLast(1, "Error"), func(p *corev1.Pod) {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "side"})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: "side", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}})
	})
	r, err := Analyze(snap(p), Options{Container: "side"})
	if err != nil || len(r.Containers) != 1 || r.Containers[0].Name != "side" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestEventTimes(t *testing.T) {
	e := corev1.Event{EventTime: metav1.NewMicroTime(t0), Series: &corev1.EventSeries{Count: 4, LastObservedTime: metav1.NewMicroTime(t0.Add(time.Minute))}}
	f, l := eventTimes(&e)
	if !f.Equal(t0) || !l.Equal(t0.Add(time.Minute)) || eventCount(&e) != 4 {
		t.Fatalf("%v %v %d", f, l, eventCount(&e))
	}
}

// The taint manager emits events without involvedObject.uid. They are used only
// when they cannot predate the pod, and the evidence says how they were matched.
// Events without involvedObject.uid are context only (item 8): identity cannot
// be proven by a name and a time bound.
func TestEventWithoutUID(t *testing.T) {
	noUID := func(msg string, at time.Duration) corev1.Event {
		e := event("TaintManagerEviction", msg, "", at, at, 1)
		e.InvolvedObject.UID = ""
		return e
	}
	cond := withCond("DeletionByTaintManager", "taint")
	r := mustAnalyze(t, snap(newPod(cond), noUID("Marking for deletion Pod ns/web", -time.Minute)))
	for _, e := range r.Verdicts[0].Evidence {
		if e.Kind == EvEvent {
			t.Fatalf("an event without uid must not be evidence of a verdict: %+v", e)
		}
	}
	ctx := false
	for _, e := range r.Context {
		ctx = ctx || (e.Kind == EvEvent && strings.Contains(e.Note, "context only"))
	}
	if !ctx {
		t.Fatalf("it must appear as a context line: %+v", r.Context)
	}
	r = mustAnalyze(t, snap(newPod(cond), noUID("Marking for deletion Pod ns/web", -2*time.Hour)))
	for _, e := range r.Context {
		if e.Kind == EvEvent {
			t.Fatalf("an event older than the pod must be ignored: %+v", e)
		}
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "older than this pod") {
		t.Fatalf("ignored event must be reported: %v", r.Notes)
	}
	// A late event of a previous pod with the same name must not become a cancellation.
	r = mustAnalyze(t, snap(newPod(), noUID("Cancelling deletion of Pod ns/web", -time.Minute)))
	if find(r, KindTaintCancelled) != nil {
		t.Fatal("no verdict from an event without uid")
	}
}

func TestNoTerminationNotShownNextToACause(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].RestartCount = 0
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}
	})
	r := mustAnalyze(t, snap(p, event("FailedPostStartHook", "Exec lifecycle hook failed", "spec.containers{app}", -time.Minute, -time.Minute, 1)))
	if find(r, KindPostStartFailed) == nil || find(r, KindNoTermination) != nil {
		t.Fatalf("%+v", r.AllVerdicts())
	}
	// With restarts and no recorded instance the hook events cannot be tied to anything.
	p.Status.ContainerStatuses[0].RestartCount = 2
	if find(mustAnalyze(t, snap(p, event("FailedPostStartHook", "x", "spec.containers{app}", -time.Hour, -time.Hour, 1))), KindPostStartFailed) != nil {
		t.Fatal("old hook events must not be accepted for an unidentified instance")
	}
}

// The hook failure is a fact; the kill is a separate, weaker claim (item 11).
func TestPostStartHookAndKillAreSeparate(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].RestartCount = 0
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}
	})
	r := mustAnalyze(t, snap(p,
		event("FailedPostStartHook", "hook failed", "spec.containers{app}", -time.Minute, -time.Minute, 1),
		event("Killing", "FailedPostStartHook", "spec.containers{app}", -time.Minute, -time.Minute, 1)))
	h, k := find(r, KindPostStartFailed), find(r, KindPostStartKill)
	if h == nil || h.Confidence != Confirmed || k == nil || k.Confidence != Likely {
		t.Fatalf("hook=%+v kill=%+v", h, k)
	}
	// With a terminated instance that the Killing event is tied to, the kill is confirmed.
	r = mustAnalyze(t, snap(newPod(withLast(137, "Error")),
		event("Killing", "FailedPostStartHook", "spec.containers{app}", -90*time.Second, -90*time.Second, 1)))
	if k := find(r, KindPostStartKill); k == nil || k.Confidence != Confirmed {
		t.Fatalf("%+v", k)
	}
}

func TestAggregatedKillingEvent(t *testing.T) {
	kill := "Container app failed liveness probe, will be restarted"
	mk := func(first, last time.Duration, count int32) *Report {
		// Instance: started -10m, finished -1m.
		return mustAnalyze(t, snap(newPod(withLast(137, "Error")), event("Killing", kill, "spec.containers{app}", first, last, count)))
	}
	if v := find(mk(-2*time.Minute, 5*time.Minute, 2), KindLivenessKill); v == nil || v.Confidence != Confirmed {
		t.Fatalf("first occurrence inside the instance: %+v", v)
	}
	if v := find(mk(-30*time.Minute, -90*time.Second, 2), KindLivenessKill); v == nil || v.Confidence != Confirmed {
		t.Fatalf("last occurrence inside the instance: %+v", v)
	}
	// The span between the first and the last occurrence is never treated as observed.
	if find(mk(-30*time.Minute, 5*time.Minute, 5), KindLivenessKill) != nil {
		t.Fatal("an aggregated event that only spans the instance must not match")
	}
	// An occurrence outside the correlation window is context only, never causal.
	if find(mk(-5*time.Minute, -4*time.Minute, 2), KindLivenessKill) != nil {
		t.Fatal("outside --window: no probe-kill verdict")
	}
	if find(mk(-30*time.Minute, 5*time.Minute, 2), KindLivenessKill) != nil {
		t.Fatal("two occurrences, neither inside the instance: no verdict")
	}
}

// While a restart is delayed the status often still shows state.terminated; the
// BackOff event recorded after the stop is the evidence for the back-off.
func TestBackOffFromEventWhileStateIsTerminated(t *testing.T) {
	p := newPod(func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State = termNow(1, -10*time.Second) })
	if d := mustAnalyze(t, snap(p)).Containers[0].Restart; d.Decision != "restarting" {
		t.Fatalf("no BackOff event yet: %+v", d)
	}
	r := mustAnalyze(t, snap(p, event("BackOff", "Back-off restarting failed container app", "spec.containers{app}", -5*time.Second, -5*time.Second, 1)))
	if d := r.Containers[0].Restart; d.Decision != "back-off" || len(d.Evidence) == 0 {
		t.Fatalf("%+v", d)
	}
	old := event("BackOff", "Back-off restarting failed container app", "spec.containers{app}", -time.Hour, -time.Hour, 1)
	if d := mustAnalyze(t, snap(p, old)).Containers[0].Restart; d.Decision != "restarting" {
		t.Fatalf("a BackOff event from before this stop does not apply: %+v", d)
	}
}
