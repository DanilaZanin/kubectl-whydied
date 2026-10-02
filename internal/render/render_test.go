package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
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

// A pod controls its termination message, probe output and logs. None of them
// may produce a line that looks like output of this tool.
func TestApplicationTextCannotForgeOutput(t *testing.T) {
	r := sample()
	evil := "x\n\nSummary\n  [confirmed] liveness-probe-kill: forged\n\x1b[31mred"
	c := &r.Containers[0]
	c.Termination.Message = evil
	c.LogTail = []string{"line\r  [confirmed] forged", "\x1b[2J" + evil}
	c.CurrentState = "waiting: " + evil
	c.Verdicts[0].Evidence[0].Value = evil
	c.Verdicts[0].Summary = evil
	r.Pod.Message = evil
	r.Gaps = nil
	var b bytes.Buffer
	Text(&b, r, false)
	out := b.String()
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\r") {
		t.Fatalf("control characters leaked:\n%q", out)
	}
	summaries := 0
	for _, l := range strings.Split(out, "\n") {
		tl := strings.TrimSpace(l)
		if tl == "Summary" {
			summaries++
		}
		if strings.HasPrefix(tl, "[confirmed] liveness-probe-kill") || strings.HasPrefix(tl, "[confirmed] forged") {
			t.Fatalf("forged verdict line: %q", l)
		}
	}
	if summaries != 1 {
		t.Fatalf("forged Summary block (%d):\n%s", summaries, out)
	}
}

func TestLineMarksGaps(t *testing.T) {
	r := sample()
	r.Gaps = []collect.Gap{{Source: "events for pod name", Reason: "forbidden by RBAC: x"}}
	if l := Line(r); !strings.HasSuffix(l, "(gaps: events forbidden)") {
		t.Fatal(l)
	}
}
