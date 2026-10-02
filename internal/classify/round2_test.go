package classify

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

// Item 1: DisruptionTarget is the start of a disruption; the outcome is a separate fact.
func TestDisruptionIsInitiationNotOutcome(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withCond("EvictionByEvictionAPI", "Eviction API: evicting"))))
	v := r.Verdicts[0]
	if !strings.Contains(v.Summary, "initiated") || !strings.Contains(v.Summary, "outcome at observation time") || !strings.Contains(v.Summary, "not marked for deletion") {
		t.Fatalf("condition alone must not claim the pod was evicted: %s", v.Summary)
	}
	for _, bad := range []string{"was evicted", "deleted this pod", "preempted this pod"} {
		if strings.Contains(v.Summary, bad) {
			t.Fatalf("categorical claim %q from a condition: %s", bad, v.Summary)
		}
	}
	del := newPod(withCond("PreemptionByScheduler", "x"), func(p *corev1.Pod) { p.DeletionTimestamp = ptr(mtime(time.Minute)) })
	if v := mustAnalyze(t, snap(del)).Verdicts[0]; !strings.Contains(v.Summary, "is being deleted") {
		t.Fatalf("outcome must state the deletion: %s", v.Summary)
	}
}

// Item 4 and 5: expectedness ties to the selected instance.
func TestSidecarExpectedness(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	mk := func(sideTerm corev1.ContainerStateTerminated, mod func(*corev1.Pod)) *Expectedness {
		p := newPod(func(p *corev1.Pod) {
			p.Spec.RestartPolicy = corev1.RestartPolicyNever
			p.Spec.InitContainers = []corev1.Container{{Name: "side", RestartPolicy: &always}}
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "side", State: corev1.ContainerState{Terminated: &sideTerm}}}
			p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed", StartedAt: mtime(-time.Hour), FinishedAt: mtime(-10 * time.Second)}}
			if mod != nil {
				mod(p)
			}
		})
		r, err := Analyze(snap(p), Options{Container: "side"})
		if err != nil {
			t.Fatal(err)
		}
		return r.Containers[0].Expected
	}
	atEnd := corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", StartedAt: mtime(-time.Hour), FinishedAt: mtime(-5 * time.Second)}
	if e := mk(atEnd, nil); e.State != ExpectedYes {
		t.Fatalf("sidecar ending after the last regular container: %+v", e)
	}
	early := atEnd
	early.FinishedAt = mtime(-30 * time.Minute)
	if e := mk(early, nil); e.State == ExpectedYes {
		t.Fatalf("a sidecar that died long before the job ended is not an expected stop: %+v", e)
	}
	oom := atEnd
	oom.Reason = "OOMKilled"
	if e := mk(oom, nil); e.State != ExpectedNo {
		t.Fatalf("an explicit OOM is not a normal shutdown: %+v", e)
	}
	// Always: the regular container is only between an exit and its restart.
	gap := func(p *corev1.Pod) { p.Spec.RestartPolicy = corev1.RestartPolicyAlways }
	if e := mk(atEnd, gap); e.State == ExpectedYes {
		t.Fatalf("the short gap before an Always restart is not 'all regular containers finished': %+v", e)
	}
}

// Item 5: a stale "Stopping container" from an earlier episode does not make a later crash expected.
func TestStaleStoppingEventIsIgnored(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(time.Minute))
		p.DeletionGracePeriodSeconds = ptr(int64(30))
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error", StartedAt: mtime(-time.Minute), FinishedAt: mtime(-time.Second)}}
	})
	old := event("Killing", "Stopping container app", "spec.containers{app}", -2*time.Hour, -2*time.Hour, 1)
	r := mustAnalyze(t, snap(p, old))
	if e := r.Containers[0].Expected; e.State == ExpectedYes {
		t.Fatalf("a Stopping event from before this instance started must not tie the stop to the teardown: %+v", e)
	}
	if find(r, KindKilledAfterGrace) != nil {
		t.Fatal("no grace verdict from a stale Stopping event")
	}
}

// A cancelled taint eviction does not start a teardown.
func TestCancelledTaintDoesNotTieTeardown(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.DeletionTimestamp = ptr(mtime(time.Minute))
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error", StartedAt: mtime(-time.Minute), FinishedAt: mtime(-time.Second)}}
	})
	r := mustAnalyze(t, snap(p,
		event("TaintManagerEviction", "Marking for deletion Pod ns/web", "", -30*time.Second, -30*time.Second, 1),
		event("TaintManagerEviction", "Cancelling deletion of Pod ns/web", "", -20*time.Second, -20*time.Second, 1)))
	if e := r.Containers[0].Expected; e.State == ExpectedYes {
		t.Fatalf("a cancelled marking must not make the stop expected: %+v", e)
	}
}

// Item 7: synthesized statuses stay out of the causal heuristics.
func TestSynthesizedStatusesExcluded(t *testing.T) {
	for _, reason := range []string{"ContainerStatusUnknown", "RestartingAllContainers"} {
		p := newPod(func(p *corev1.Pod) {
			p.DeletionTimestamp = ptr(mtime(0))
			p.DeletionGracePeriodSeconds = ptr(int64(5))
			p.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: reason, StartedAt: mtime(-time.Hour), FinishedAt: mtime(0)}}
		})
		s := snap(p, event("Killing", "Stopping container app", "spec.containers{app}", -time.Minute, -time.Minute, 1))
		s.Events = append(s.Events, event("SystemOOM", "System OOM", "", -time.Second, -time.Second, 1))
		s.Events[len(s.Events)-1].InvolvedObject.Kind = "Node"
		r := mustAnalyze(t, s)
		for _, k := range []string{KindNodeOOMCandidate, KindKilledAfterGrace, KindExitSignal} {
			if find(r, k) != nil {
				t.Fatalf("%s: synthesized exit 137 must not feed %s", reason, k)
			}
		}
		if find(r, KindStatusUnknown) == nil || r.Containers[0].Expected.State != ExpectedUnknown {
			t.Fatalf("%s: %+v", reason, r.Containers[0])
		}
	}
}

// Item 10: only known occurrences count, never the span of an aggregated event.
func TestNodeOOMUsesKnownOccurrences(t *testing.T) {
	mk := func(first, last time.Duration, count int32) *Report {
		s := snap(newPod(withLast(137, "Error")))
		e := event("SystemOOM", "System OOM encountered", "", first, last, count)
		e.InvolvedObject.Kind = "Node"
		s.Events = append(s.Events, e)
		return mustAnalyze(t, s)
	}
	// instance finished at -1m; window 2m. Occurrences at -10m and +10m: the span covers it, no occurrence does.
	if find(mk(-10*time.Minute, 10*time.Minute, 2), KindNodeOOMCandidate) != nil {
		t.Fatal("the span of an aggregated event is not an occurrence")
	}
	if find(mk(-90*time.Second, 10*time.Minute, 2), KindNodeOOMCandidate) == nil {
		t.Fatal("a known occurrence inside the window is a candidate")
	}
}

// Item 16: spec paths follow the container role.
func TestSpecPathForInitContainer(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Spec.InitContainers = []corev1.Container{{Name: "setup", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Mi")}}}}
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "setup", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled", StartedAt: mtime(-time.Minute), FinishedAt: mtime(-time.Second)}}}}
	})
	r, _ := Analyze(snap(p), Options{Container: "setup"})
	found := false
	for _, e := range find(r, KindOOMKill).Evidence {
		found = found || e.Field == "spec.initContainers[setup].resources.limits.memory"
	}
	if !found {
		t.Fatalf("%+v", find(r, KindOOMKill).Evidence)
	}
}

// Item 17: -c finds containers that are only in the spec.
func TestContainerOnlyInSpec(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status = corev1.PodStatus{Phase: corev1.PodPending}
	})
	r, err := Analyze(snap(p), Options{Container: "app"})
	if err != nil {
		t.Fatalf("a container in the spec exists even without a status: %v", err)
	}
	if len(r.Containers) != 1 || r.Containers[0].Verdicts[0].Confidence != NoData {
		t.Fatalf("%+v", r.Containers)
	}
}

// Item 18: restartCount is reported as is.
func TestRunningWithRestartsAndNoHistory(t *testing.T) {
	p := newPod(func(p *corev1.Pod) {
		p.Status.ContainerStatuses[0].RestartCount = 3
		p.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: mtime(-time.Minute)}}
	})
	v := find(mustAnalyze(t, snap(p)), KindNoTermination)
	if v == nil || !strings.Contains(v.Summary, "restartCount=3") || strings.Contains(v.Summary, "restartCount=0") {
		t.Fatalf("%+v", v)
	}
}

// Item 19: a selected lastState is not copied into Previous.
func TestNoPreviousWhenLastStateIsSelected(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withLast(137, "ContainerStatusUnknown"))))
	if r.Containers[0].Previous != nil {
		t.Fatalf("%+v", r.Containers[0].Previous)
	}
	for _, v := range r.Containers[0].Verdicts {
		if strings.Contains(v.Summary, "previous instance") {
			t.Fatal(v.Summary)
		}
	}
}

// Item 20: exit codes above 192 are not signals.
func TestExit255IsNotASignal(t *testing.T) {
	r := mustAnalyze(t, snap(newPod(withLast(255, "Error"))))
	if find(r, KindExitSignal) != nil || find(r, KindAppExit) == nil {
		t.Fatalf("%+v", r.AllVerdicts())
	}
	if v := find(mustAnalyze(t, snap(newPod(withLast(192, "Error")))), KindExitSignal); v == nil {
		t.Fatal("192 = 128+64 is the last Linux signal number")
	}
}

// Item 13: logs not tied to the explained instance become a gap, and the
// association is always labelled as an assumption.
func TestLogsBindingGap(t *testing.T) {
	mk := func(l collect.Logs) *Report {
		s := snap(newPod(withLast(1, "Error")))
		s.Logs = map[string]collect.Logs{"app": l}
		return mustAnalyze(t, s)
	}
	ok := mk(collect.Logs{Previous: true, PodUID: "pod-uid", Source: "lastState.terminated", ContainerID: "containerd://old", Lines: []string{"x"}})
	if !strings.Contains(ok.Containers[0].LogNote, "assumption") {
		t.Fatal("log association must be labelled as an assumption")
	}
	for _, g := range ok.Gaps {
		if strings.HasPrefix(g.Source, "logs/") {
			t.Fatalf("matching logs: no gap: %+v", g)
		}
	}
	for name, l := range map[string]collect.Logs{
		"other containerID": {Previous: true, PodUID: "pod-uid", Source: "lastState.terminated", ContainerID: "containerd://newer", Lines: []string{"x"}},
		"other pod uid":     {Previous: true, PodUID: "someone-else", Source: "lastState.terminated", ContainerID: "containerd://old", Lines: []string{"x"}},
		"other source":      {PodUID: "pod-uid", Source: "state.terminated", ContainerID: "containerd://old", Lines: []string{"x"}},
	} {
		r := mk(l)
		found := false
		for _, g := range r.Gaps {
			found = found || strings.HasPrefix(g.Source, "logs/")
		}
		if !found {
			t.Errorf("%s: expected a logs gap", name)
		}
	}
}
