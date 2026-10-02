package e2e

import (
	"strings"
	"testing"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

func load(t *testing.T, name string) (*classify.Report, *API) {
	t.Helper()
	s, err := collect.Load("../../internal/classify/testdata/" + name + ".snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := classify.Analyze(s, classify.Options{Window: 5 * 60e9})
	if err != nil {
		t.Fatal(err)
	}
	return r, APIFromSnapshot(s)
}

func TestValidateAcceptsRealReports(t *testing.T) {
	for _, n := range []string{"oom.v1.37.0", "liveness-kill.v1.37.0", "rollout.v1.37.0", "drain.v1.37.0", "sidecar-stop.v1.37.0"} {
		r, api := load(t, n)
		if err := Validate(r, api); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

// Forged or wrong evidence must be caught (item 14).
func TestValidateRejectsInventedEvidence(t *testing.T) {
	mutations := map[string]func(*classify.Report){
		"invented field": func(r *classify.Report) {
			r.Containers[0].Verdicts[0].Evidence[0].Field = "status.containerStatuses[app].lastState.terminated.nonsense"
		},
		"wrong value": func(r *classify.Report) { r.Containers[0].Verdicts[0].Evidence[0].Value = "999" },
		"empty uid":   func(r *classify.Report) { r.Containers[0].Verdicts[0].Evidence[0].UID = "" },
		"foreign uid": func(r *classify.Report) { r.Containers[0].Verdicts[0].Evidence[0].UID = "not-the-pod" },
		"wrong containerID": func(r *classify.Report) {
			r.Containers[0].Termination.ContainerID = "containerd://forged"
		},
		"wrong container scope": func(r *classify.Report) {
			r.Containers[0].Verdicts[0].Evidence[0].Field = strings.Replace(r.Containers[0].Verdicts[0].Evidence[0].Field, "[app]", "[other]", 1)
		},
	}
	for name, mut := range mutations {
		r, api := load(t, "oom.v1.37.0")
		mut(r)
		if err := Validate(r, api); err == nil {
			t.Errorf("%s: forged evidence passed", name)
		}
	}
	// Event evidence: invented time and message.
	r, api := load(t, "liveness-kill.v1.37.0")
	for _, c := range r.Containers {
		for i := range c.Verdicts {
			for j := range c.Verdicts[i].Evidence {
				if c.Verdicts[i].Evidence[j].Kind == classify.EvEvent {
					ev := &c.Verdicts[i].Evidence[j]
					ev.Value += " (forged)"
					if err := Validate(r, api); err == nil {
						t.Fatal("a forged event message passed")
					}
					return
				}
			}
		}
	}
	t.Fatal("no event evidence to mutate")
}

// S14: exact value comparison, evidence times and owner/node values are checked.
func TestValidateIsExactAndChecksTimesOwnersAndNodes(t *testing.T) {
	// exit1 fixture: the API exitCode is 1; "137" contains "1" but must not pass.
	r, api := load(t, "exit1.v1.37.0")
	ev := &r.Containers[0].Verdicts[0].Evidence[0]
	if !strings.HasSuffix(ev.Field, ".exitCode") {
		t.Fatalf("unexpected first evidence %q", ev.Field)
	}
	ev.Value = "137"
	if err := Validate(r, api); err == nil {
		t.Error("a value that merely contains the API value passed")
	}
	r, api = load(t, "exit1.v1.37.0")
	t0 := *r.Containers[0].Verdicts[0].Evidence[0].Time
	forged := t0.Add(7e9)
	r.Containers[0].Verdicts[0].Evidence[0].Time = &forged
	if err := Validate(r, api); err == nil {
		t.Error("an evidence time that is not in the API passed")
	}
	// Owner revision.
	r, api = load(t, "rollout.v1.37.0")
	n := 0
	for i := range r.Verdicts {
		for j := range r.Verdicts[i].Evidence {
			if e := &r.Verdicts[i].Evidence[j]; e.Kind == classify.EvOwner && strings.Contains(e.Field, "revision") {
				e.Value = "99"
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no owner revision evidence in the rollout fixture")
	}
	if err := Validate(r, api); err == nil {
		t.Error("a forged owner revision passed")
	}
	// Node taint context.
	r, api = load(t, "drain.v1.37.0")
	n = 0
	for i := range r.Context {
		if r.Context[i].Field == "spec.taints" {
			r.Context[i].Value = "forged=1:NoExecute"
			n++
		}
	}
	if n == 0 {
		t.Fatal("no node taint context in the drain fixture")
	}
	if err := Validate(r, api); err == nil {
		t.Error("a forged node taint passed")
	}
}

// O1: a CrashLoop restart between two API reads changes the instance key, so
// the harness retries the attempt instead of validating against another instance.
func TestInstanceKey(t *testing.T) {
	_, a := load(t, "exit1.v1.37.0")
	_, b := load(t, "exit1.v1.37.0")
	if instanceKey(a) != instanceKey(b) {
		t.Fatal("the same read must give the same key")
	}
	status := nested(b.Pod, "status")["containerStatuses"].([]any)[0].(map[string]any)
	status["restartCount"] = float64(99)
	if instanceKey(a) == instanceKey(b) {
		t.Fatal("a changed restartCount must change the key")
	}
	_, c := load(t, "exit1.v1.37.0")
	nested(nested(c.Pod, "status")["containerStatuses"].([]any)[0].(map[string]any), "lastState", "terminated")["containerID"] = "containerd://other"
	if instanceKey(a) == instanceKey(c) {
		t.Fatal("a changed containerID must change the key")
	}
	if instanceKey(&API{Pod: map[string]any{}}) != "gone" {
		t.Fatal("no pod: gone")
	}
}
