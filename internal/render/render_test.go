package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
)

func sample() *classify.Report {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return &classify.Report{
		ObservedAt: now, Window: "2m0s",
		Pod: classify.PodInfo{Namespace: "ns", Name: "web", UID: "u1", Exists: true, Phase: "Running"},
		Containers: []classify.ContainerReport{{
			Name: "app", Role: "regular", CurrentState: "waiting: CrashLoopBackOff",
			Termination: &classify.Termination{Source: "lastState.terminated", ExitCode: 137, Reason: "OOMKilled"},
			Restart:     classify.RestartDecision{Policy: "Always", Decision: "back-off", Detail: "d"},
			Verdicts: []classify.Verdict{{
				Kind: classify.KindOOMKill, Confidence: classify.Confirmed, Summary: "oom",
				Competing: []string{"level unknown"},
				Evidence:  []classify.Evidence{{Kind: classify.EvPodStatus, Object: "Pod ns/web", UID: "u1", Field: "f", Value: "OOMKilled", Time: &now}},
			}},
		}},
		Checked: []string{"pod status and spec"},
	}
}

func TestTextColorOnlyWhenAsked(t *testing.T) {
	var plain, colored bytes.Buffer
	Text(&plain, sample(), false)
	Text(&colored, sample(), true)
	if strings.Contains(plain.String(), "\x1b[") {
		t.Error("plain output must not contain escapes")
	}
	if !strings.Contains(colored.String(), "\x1b[32m[confirmed]") {
		t.Error("confirmed must be green when color is on")
	}
	for _, want := range []string{"Summary", "[pod-status] Pod ns/web f = OOMKilled @ 2026-10-02T12:00:00Z (uid u1)", "caveat: level unknown", "Checked"} {
		if !strings.Contains(plain.String(), want) {
			t.Errorf("missing %q in:\n%s", want, plain.String())
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample()); err != nil {
		t.Fatal(err)
	}
	var got classify.Report
	if err := json.Unmarshal(b.Bytes(), &got); err != nil || got.Containers[0].Verdicts[0].Kind != classify.KindOOMKill {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestLine(t *testing.T) {
	l := Line(sample())
	if !strings.HasPrefix(l, "ns/web app: [confirmed] oom-kill-reported") {
		t.Fatal(l)
	}
	if got := Line(&classify.Report{Pod: classify.PodInfo{Namespace: "a", Name: "b"}}); got != "a/b: no data" {
		t.Fatal(got)
	}
}
