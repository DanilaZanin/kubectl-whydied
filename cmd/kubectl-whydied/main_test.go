package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

func TestParseArgsInterspersed(t *testing.T) {
	c, pos, err := parseArgs([]string{"mypod", "-n", "prod", "-c", "app", "--previous-logs", "5", "-o", "json", "--window", "10m"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 1 || pos[0] != "mypod" || c.namespace != "prod" || c.container != "app" || c.previousLogs != 5 || c.output != "json" || c.window != 10*time.Minute {
		t.Fatalf("%+v %v", c, pos)
	}
	c, pos, err = parseArgs([]string{"-A", "--restarted-since", "30m"}, io.Discard)
	if err != nil || len(pos) != 0 || !c.allNamespaces || c.restartedSince != 30*time.Minute {
		t.Fatalf("%+v %v %v", c, pos, err)
	}
	if _, _, err = parseArgs([]string{"-o", "yaml"}, io.Discard); err == nil {
		t.Fatal("unknown output format must be rejected")
	}
}

func writeSnapshot(t *testing.T, exit int32, reason string) string {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns", UID: "u1"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}, RestartPolicy: corev1.RestartPolicyAlways},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 1,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: exit, Reason: reason, FinishedAt: metav1.Now()}}}}},
	}
	s := &collect.Snapshot{Version: 1, CollectedAt: time.Now().UTC(), Namespace: "ns", Name: "web", Pod: pod}
	f := filepath.Join(t.TempDir(), "s.json")
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRunFromSnapshotJSON(t *testing.T) {
	f := writeSnapshot(t, 137, "OOMKilled")
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"--from-snapshot", f, "-o", "json"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var rep classify.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Containers) != 1 || rep.Containers[0].Verdicts[0].Kind != classify.KindOOMKill {
		t.Fatalf("%+v", rep)
	}
}

func TestRunTextHasNoColorWhenNotATTY(t *testing.T) {
	f := writeSnapshot(t, 1, "Error")
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"--from-snapshot", f}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := out.String()
	if strings.Contains(s, "\x1b[") {
		t.Error("no ANSI escapes outside a TTY")
	}
	for _, want := range []string{"[confirmed] app-exit", "API reported exitCode=1", "Checked"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\u2014") {
		t.Error("em dash in output")
	}
}

func TestExitCodes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), nil, &out, &errb); code != exitError {
		t.Errorf("no arguments: exit %d, want %d", code, exitError)
	}
	if code := run(context.Background(), []string{"--from-snapshot", "/nonexistent.json"}, &out, &errb); code != exitError {
		t.Errorf("bad snapshot: exit %d, want %d", code, exitError)
	}
	gone := &collect.Snapshot{Version: 1, CollectedAt: time.Now(), Namespace: "ns", Name: "x"}
	f := filepath.Join(t.TempDir(), "gone.json")
	if err := gone.Save(f); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"--from-snapshot", f}, &out, &errb); code != exitNoData {
		t.Errorf("no data at all: exit %d, want %d", code, exitNoData)
	}
	if code := run(context.Background(), []string{"--from-snapshot", writeSnapshot(t, 1, "Error"), "-c", "nope"}, &out, &errb); code != exitError {
		t.Errorf("unknown container: exit %d, want %d", code, exitError)
	}
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &out, io.Discard); code != exitOK || !strings.Contains(out.String(), "kubectl-whydied") {
		t.Fatalf("%d %q", code, out.String())
	}
}
