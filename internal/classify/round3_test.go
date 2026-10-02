package classify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func inRule(action corev1.ContainerRestartRuleAction, codes ...int32) corev1.ContainerRestartRule {
	return corev1.ContainerRestartRule{Action: action, ExitCodes: &corev1.ContainerRestartRuleOnExitCodes{Operator: corev1.ContainerRestartRuleOnExitCodesOpIn, Values: codes}}
}

func decisionOf(t *testing.T, r *Report, name string) RestartDecision {
	t.Helper()
	for _, c := range r.Containers {
		if c.Name == name {
			return c.Restart
		}
	}
	t.Fatalf("no container %s", name)
	return RestartDecision{}
}

// S2: a deleting pod never restarts, whatever the container state says.
func TestDeletingPodWithCrashLoopBackOffDoesNotRestart(t *testing.T) {
	p := newPod(func(p *corev1.Pod) { p.DeletionTimestamp = ptr(mtime(time.Minute)) }, withLast(1, "Error"))
	if d := mustAnalyze(t, snap(p)).Containers[0].Restart; d.Decision != "not-restarting" {
		t.Fatalf("%+v", d)
	}
}

// S3: rules apply to init containers; RestartAllContainers restarts the neighbours.
func TestRulesOnInitAndRestartAllNeighbours(t *testing.T) {
	never := corev1.ContainerRestartPolicyNever
	p := newPod(func(p *corev1.Pod) {
		p.Status.Phase = corev1.PodPending
		p.Spec.InitContainers = []corev1.Container{{Name: "setup", RestartPolicy: &never, RestartPolicyRules: []corev1.ContainerRestartRule{inRule(corev1.ContainerRestartRuleActionRestart, 3)}}}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "setup", State: termNow(3, -time.Second)}}
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}
	})
	if d := decisionOf(t, mustAnalyze(t, snap(p)), "setup"); d.Decision != "restarting" || !strings.Contains(d.Detail, "restartPolicyRules[0]") {
		t.Fatalf("init rules must be evaluated: %+v", d)
	}
	pair := newPod(func(p *corev1.Pod) {
		a := corev1.ContainerRestartPolicyNever
		p.Spec.Containers = []corev1.Container{
			{Name: "a", RestartPolicy: &a, RestartPolicyRules: []corev1.ContainerRestartRule{inRule(corev1.ContainerRestartRuleActionRestartAllContainers, 42)}},
			{Name: "b"},
		}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{
			{Name: "a", State: termNow(42, -time.Second)},
			{Name: "b", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: mtime(-time.Hour)}}},
		}
	})
	r := mustAnalyze(t, snap(pair))
	if d := decisionOf(t, r, "b"); d.Decision != "restarting" || !strings.Contains(d.Detail, "RestartAllContainers") {
		t.Fatalf("the neighbour restarts too: %+v", d)
	}
	if d := decisionOf(t, r, "a"); d.Decision != "restarting" {
		t.Fatalf("%+v", d)
	}
}

// S4: a failed init means the app never ran; an old sidecar crash is not the normal end.
func TestSidecarCrashWhenAppNeverRanIsNotExpected(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	p := newPod(func(p *corev1.Pod) {
		p.Spec.RestartPolicy = corev1.RestartPolicyNever
		p.Status.Phase = corev1.PodFailed
		p.Spec.InitContainers = []corev1.Container{{Name: "side", RestartPolicy: &always}}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "side", State: termNow(137, -5*time.Second)}}
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}
	})
	r, _ := Analyze(snap(p), Options{Container: "side"})
	if e := r.Containers[0].Expected; e.State == ExpectedYes {
		t.Fatalf("the main container never ran: %+v", e)
	}
}

// S5: a Killing event before startedAt belongs to an earlier episode.
func TestStoppingEventBeforeStartIsNotTeardown(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(time.Minute))
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error", StartedAt: mtime(-time.Minute), FinishedAt: mtime(-10 * time.Second)}}
	})
	before := event("Killing", "Stopping container app", "spec.containers{app}", -61*time.Second, -61*time.Second, 1)
	if e := mustAnalyze(t, snap(p, before)).Containers[0].Expected; e.State == ExpectedYes {
		t.Fatalf("one second before startedAt: %+v", e)
	}
	after := event("Killing", "Stopping container app", "spec.containers{app}", -20*time.Second, -20*time.Second, 1)
	if e := mustAnalyze(t, snap(p, after)).Containers[0].Expected; e.State != ExpectedYes {
		t.Fatalf("a stop inside the lifetime is the teardown: %+v", e)
	}
}

// S9: outside --window an event is context only, never a causal verdict.
func TestProbeKillOutsideWindowIsContextOnly(t *testing.T) {
	p := newPod(func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State = termNow(137, 0) })
	ev := event("Killing", "Container app failed liveness probe, will be restarted", "spec.containers{app}", -30*time.Second, -30*time.Second, 1)
	r, err := Analyze(snap(p, ev), Options{Window: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if find(r, KindLivenessKill) != nil {
		t.Fatal("30s before finish with --window 1s must not produce a probe-kill verdict")
	}
	ctx := false
	for _, e := range r.Context {
		ctx = ctx || (e.Kind == EvEvent && strings.Contains(e.Note, "event outside correlation window"))
	}
	if !ctx {
		t.Fatalf("the event must stay visible as context: %+v", r.Context)
	}
	if v := find(mustAnalyze(t, snap(p, ev)), KindLivenessKill); v == nil || v.Confidence != Confirmed {
		t.Fatalf("inside the default window: %+v", v)
	}
}

// S11: with no termination, hook events must belong to the running instance.
func TestPostStartEventsBoundToRunningInstance(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].RestartCount = 0
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: mtime(-time.Minute)}}
	})
	if find(mustAnalyze(t, snap(p, event("FailedPostStartHook", "x", "spec.containers{app}", -time.Hour, -time.Hour, 1))), KindPostStartFailed) != nil {
		t.Fatal("an event before the running instance started must not be confirmed")
	}
	if v := find(mustAnalyze(t, snap(p, event("FailedPostStartHook", "x", "spec.containers{app}", -30*time.Second, -30*time.Second, 1))), KindPostStartFailed); v == nil || v.Confidence != Confirmed {
		t.Fatalf("%+v", v)
	}
}

// S17: an ephemeral container with no status yet.
func TestEphemeralWithoutStatus(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg"}}}
	})
	r, err := Analyze(snap(p), Options{Container: "dbg"})
	if err != nil || len(r.Containers) != 1 || r.Containers[0].Role != "ephemeral" || r.Containers[0].Verdicts[0].Confidence != NoData {
		t.Fatalf("%v %+v", err, r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), `"containers":null`) || strings.Contains(string(b), `"verdicts":null`) {
		t.Fatalf("arrays must never be null: %s", b)
	}
}

// N1: a container-level restartPolicy beats the pod's, for init containers too.
func TestInitContainerOwnPolicyWins(t *testing.T) {
	onFailure := corev1.ContainerRestartPolicyOnFailure
	p := newPod(func(p *corev1.Pod) {
		p.Spec.RestartPolicy = corev1.RestartPolicyNever
		p.Status.Phase = corev1.PodPending
		p.Spec.InitContainers = []corev1.Container{{Name: "setup", RestartPolicy: &onFailure}}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "setup", State: termNow(1, -time.Second)}}
	})
	if d := decisionOf(t, mustAnalyze(t, snap(p)), "setup"); d.Decision != "restarting" || d.Policy != "OnFailure" {
		t.Fatalf("%+v", d)
	}
}

// N2: only a recent BackOff event is a current back-off.
func TestHistoricalBackOffIsNotCurrent(t *testing.T) {
	p := newPod(func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State = termNow(1, -20*time.Minute) })
	old := event("BackOff", "Back-off restarting failed container app", "spec.containers{app}", -20*time.Minute, -20*time.Minute, 1)
	d := mustAnalyze(t, snap(p, old)).Containers[0].Restart
	if d.Decision != "unknown" || !strings.Contains(d.Detail, "older than the 5 minute") {
		t.Fatalf("%+v", d)
	}
}

// O6: the rules branch uses the same back-off logic.
func TestRuleRestartAlsoBackOff(t *testing.T) {
	never := corev1.ContainerRestartPolicyNever
	p := newPod(func(p *corev1.Pod) {
		p.Spec.Containers[0].RestartPolicy = &never
		p.Spec.Containers[0].RestartPolicyRules = []corev1.ContainerRestartRule{inRule(corev1.ContainerRestartRuleActionRestart, 42)}
		p.Status.ContainerStatuses[0].State = termNow(42, -10*time.Second)
	})
	r := mustAnalyze(t, snap(p, event("BackOff", "Back-off restarting failed container app", "spec.containers{app}", -5*time.Second, -5*time.Second, 1)))
	if d := r.Containers[0].Restart; d.Decision != "back-off" || !strings.Contains(d.Detail, "restartPolicyRules[0]") {
		t.Fatalf("%+v", d)
	}
}

// O2: the list row is the crashed app container, not the completed init.
func TestHeadlinePrefersFailedAppOverCompletedInit(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Spec.InitContainers = []corev1.Container{{Name: "setup"}}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "setup", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed", StartedAt: mtime(-time.Hour), FinishedAt: mtime(-59 * time.Minute)}}}}
		p.Status.ContainerStatuses[0].State = termNow(4, -time.Second)
	})
	name, v, ok := mustAnalyze(t, snap(p)).Headline()
	if !ok || name != "app" || v.Kind != KindAppExit || !strings.Contains(v.Summary, "exitCode=4") {
		t.Fatalf("%s %+v", name, v)
	}
}

// O3: ephemeral expectedness agrees with the restart text.
func TestEphemeralExpectednessText(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg"}}}
		p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "dbg", State: termNow(1, -time.Second)}}
	})
	r, _ := Analyze(snap(p), Options{Container: "dbg"})
	c := r.Containers[0]
	if c.Expected.State == ExpectedNo || !strings.Contains(c.Expected.Why, "never restarted") || c.Restart.Decision != "not-restarting" {
		t.Fatalf("%+v %+v", c.Expected, c.Restart)
	}
}

// N2: a BackOff is current only within the 5 minute maximum plus 30s slack.
func TestBackOffBoundary(t *testing.T) {
	p := newPod(func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State = termNow(1, -20*time.Minute) })
	at := func(age time.Duration) string {
		e := event("BackOff", "Back-off restarting failed container app", "spec.containers{app}", -age, -age, 1)
		return mustAnalyze(t, snap(p, e)).Containers[0].Restart.Decision
	}
	for age, want := range map[time.Duration]string{5 * time.Minute: "back-off", 5*time.Minute + 30*time.Second: "back-off", 5*time.Minute + 31*time.Second: "unknown", 9 * time.Minute: "unknown"} {
		if got := at(age); got != want {
			t.Errorf("BackOff %s old: %s, want %s", age, got, want)
		}
	}
}

// S3: RestartAllContainers restarts every container, also one that exited under its own Never.
func TestRestartAllIncludesNeighbourThatExitedUnderNever(t *testing.T) {
	never := corev1.ContainerRestartPolicyNever
	p := newPod(func(p *corev1.Pod) {
		p.Spec.Containers = []corev1.Container{
			{Name: "a", RestartPolicy: &never, RestartPolicyRules: []corev1.ContainerRestartRule{inRule(corev1.ContainerRestartRuleActionRestartAllContainers, 42)}},
			{Name: "b", RestartPolicy: &never},
		}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "a", State: termNow(42, -time.Second)}, {Name: "b", State: termNow(0, -time.Minute)}}
	})
	r := mustAnalyze(t, snap(p))
	if d := decisionOf(t, r, "b"); d.Decision != "restarting" || !strings.Contains(d.Detail, "already exited") {
		t.Fatalf("b exited 0 under Never but RestartAllContainers restarts it: %+v", d)
	}
}

func TestSpecOnlyEphemeralRestartText(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg"}}}
	})
	r, _ := Analyze(snap(p), Options{Container: "dbg"})
	if d := r.Containers[0].Restart; d.Policy != "never (ephemeral)" || d.Decision != "not-restarting" {
		t.Fatalf("%+v", d)
	}
}
