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
		{"outside window", []corev1.Event{event("Killing", kill, "spec.containers{app}", -50*time.Minute, -50*time.Minute, 1)}, KindLivenessKill, Likely},
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
		{"regular stopped while deleting", mk("regular", 143, func(p *corev1.Pod) { p.DeletionTimestamp = ptr(mtime(time.Minute)) }), "regular", ExpectedYes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.c.Role != c.role || c.c.Expected == nil || c.c.Expected.State != c.state {
				t.Fatalf("role=%s expected=%+v, want %s/%s", c.c.Role, c.c.Expected, c.role, c.state)
			}
		})
	}
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
	rules := newPod(withLast(1, "Error"), func(p *corev1.Pod) {
		a := corev1.ContainerRestartPolicyNever
		p.Spec.Containers[0].RestartPolicy = &a
		p.Spec.Containers[0].RestartPolicyRules = []corev1.ContainerRestartRule{{Action: corev1.ContainerRestartRuleActionRestart}}
	})
	d := mustAnalyze(t, snap(rules)).Containers[0].Restart
	if d.Policy != "Never" || !strings.Contains(d.Detail, "restartPolicyRules") {
		t.Fatalf("container-level policy and rules must be reported: %+v", d)
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
	p := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(-time.Second))
		p.DeletionGracePeriodSeconds = ptr(int64(30))
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", FinishedAt: mtime(0)}}
	})
	v := find(mustAnalyze(t, snap(p)), KindKilledAfterGrace)
	if v == nil || v.Confidence != Likely || len(v.Competing) == 0 {
		t.Fatalf("got %+v", v)
	}
	early := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(time.Hour))
		p.DeletionGracePeriodSeconds = ptr(int64(30))
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", FinishedAt: mtime(0)}}
	})
	if find(mustAnalyze(t, snap(early)), KindKilledAfterGrace) != nil {
		t.Fatal("a kill long before the deadline is not 'after grace'")
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
	gotRBAC, gotExpired := false, false
	for _, g := range r.Gaps {
		gotRBAC = gotRBAC || strings.Contains(g.Reason, "RBAC")
		gotExpired = gotExpired || strings.Contains(g.Reason, "expire")
	}
	if !gotRBAC || !gotExpired {
		t.Fatalf("gaps = %+v", r.Gaps)
	}
	if v := find(r, KindAppExit); v == nil || v.Confidence != Confirmed {
		t.Fatalf("a terminated state alone confirms the exit; missing events must not change it: %+v", v)
	}
	for _, v := range r.AllVerdicts() {
		for _, e := range v.Evidence {
			if e.Field == "" {
				t.Errorf("empty evidence: %+v", e)
			}
		}
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
func TestEventWithoutUID(t *testing.T) {
	noUID := func(msg string, at time.Duration) corev1.Event {
		e := event("TaintManagerEviction", msg, "", at, at, 1)
		e.InvolvedObject.UID = ""
		return e
	}
	cond := withCond("DeletionByTaintManager", "taint")
	r := mustAnalyze(t, snap(newPod(cond), noUID("Marking for deletion Pod ns/web", -time.Minute)))
	var matched bool
	for _, e := range r.Verdicts[0].Evidence {
		matched = matched || (e.Kind == EvEvent && strings.Contains(e.Note, "no involvedObject.uid"))
	}
	if !matched {
		t.Fatalf("event without uid should be used and labelled: %+v", r.Verdicts[0].Evidence)
	}
	r = mustAnalyze(t, snap(newPod(cond), noUID("Marking for deletion Pod ns/web", -2*time.Hour)))
	for _, e := range r.Verdicts[0].Evidence {
		if e.Kind == EvEvent {
			t.Fatalf("an event older than the pod must be ignored: %+v", e)
		}
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "older than this pod") {
		t.Fatalf("ignored event must be reported: %v", r.Notes)
	}
}

func TestNoTerminationNotShownNextToACause(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}
	})
	r := mustAnalyze(t, snap(p, event("FailedPostStartHook", "Exec lifecycle hook failed", "spec.containers{app}", -time.Minute, -time.Minute, 1)))
	if find(r, KindPostStartFailed) == nil || find(r, KindNoTermination) != nil {
		t.Fatalf("%+v", r.AllVerdicts())
	}
}
