package classify_test

import (
	"strings"
	"testing"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

func analyzeFixture(t *testing.T, name string) *classify.Report {
	t.Helper()
	s, err := collect.Load("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	r, err := classify.Analyze(s, classify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// a16: the last instance was OOMKilled; the Killing event for the liveness
// probe belongs to an earlier instance and must not be attributed to it.
func TestRegressionOOMInstanceNotBlamedOnEarlierProbeKill(t *testing.T) {
	r := analyzeFixture(t, "regress-a16-oom-after-probe-kill.snap.json")
	vs := r.Containers[0].Verdicts
	if vs[0].Kind != classify.KindOOMKill {
		t.Fatalf("first verdict = %s, want %s", vs[0].Kind, classify.KindOOMKill)
	}
	for _, v := range r.AllVerdicts() {
		if v.Kind == classify.KindLivenessKill || v.Kind == classify.KindStartupKill {
			t.Fatalf("probe kill attributed to the wrong instance: %+v", v)
		}
	}
}

// a05: the last instance was stopped by pod deletion; the earlier instance was
// the one killed by the probe.
func TestRegressionDeletedInstanceNotBlamedOnEarlierProbeKill(t *testing.T) {
	r := analyzeFixture(t, "regress-a05-deleted-after-probe-kill.snap.json")
	for _, v := range r.AllVerdicts() {
		if v.Kind == classify.KindLivenessKill {
			t.Fatalf("probe kill attributed to the wrong instance: %+v", v)
		}
		if v.Kind == classify.KindKilledAfterGrace && strings.Contains(v.Summary, "0s grace") {
			t.Fatalf("grace computed from the post-termination deletionGracePeriodSeconds=0: %s", v.Summary)
		}
	}
}
