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
