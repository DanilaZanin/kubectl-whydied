package classify_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
	"github.com/DanilaZanin/kubectl-whydied/test/e2e"
)

var update = flag.Bool("update", false, "rewrite golden report files")

// Each fixture is a snapshot captured by the kind e2e run (pod, owners, events,
// node as the API returned them). The report is compared with a golden file and
// must satisfy the same expectation as the live scenario.
func TestGoldenFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/*.snapshot.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		base := strings.TrimSuffix(filepath.Base(f), ".snapshot.json") // scenario.k8sversion
		scenario := base[:strings.LastIndex(base, ".v")]
		t.Run(base, func(t *testing.T) {
			sc, err := e2e.LoadScenario(filepath.Join("..", "..", "test", "e2e", "scenarios", scenario))
			if err != nil {
				t.Fatal(err)
			}
			snap, err := collect.Load(f)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := classify.Analyze(snap, classify.Options{Window: 5 * 60e9, Container: sc.Target.Container})
			if err != nil {
				t.Fatal(err)
			}
			var known []string
			if snap.Node != nil {
				known = []string{string(snap.Node.UID), snap.Node.Name}
			}
			if err := e2e.Evaluate(sc.Expect, rep, known...); err != nil {
				t.Errorf("fixture does not satisfy the scenario expectation: %v", err)
			}
			if snap.Pod != nil {
				if err := e2e.Validate(rep, e2e.APIFromSnapshot(snap)); err != nil {
					t.Errorf("evidence is not backed by the snapshot: %v", err)
				}
			}
			got, _ := json.MarshalIndent(rep, "", "  ")
			got = append(got, '\n')
			golden := strings.TrimSuffix(f, ".snapshot.json") + ".golden.json"
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden file (run go test ./internal/classify -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("report differs from %s; run go test ./internal/classify -update and review the diff", golden)
			}
		})
	}
}
