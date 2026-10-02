// Package e2e holds the end-to-end scenarios and the expectation checker that
// is shared by the kind harness and the golden-fixture unit tests.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
)

// Step is one imperative action of a scenario. Exactly one field is set.
type Step struct {
	Apply       string   `json:"apply,omitempty"`       // manifest file in the scenario dir
	Kubectl     []string `json:"kubectl,omitempty"`     // kubectl args; -n is added unless noNamespace
	AllowFail   bool     `json:"allowFail,omitempty"`   // ignore a non-zero exit
	NoNamespace bool     `json:"noNamespace,omitempty"` // do not add -n
	Wait        []string `json:"wait,omitempty"`        // kubectl wait args
	CapturePod  string   `json:"capturePod,omitempty"`  // store the first pod of the selector as {{name}} and {{node}}
	Sleep       int      `json:"sleepSeconds,omitempty"`
}

// Target selects the pod to explain. Name and Selector may contain {{vars}}.
type Target struct {
	Name        string `json:"name,omitempty"`
	Selector    string `json:"selector,omitempty"`
	Terminating bool   `json:"terminating,omitempty"` // pick the pod that has a deletionTimestamp
	Container   string `json:"container,omitempty"`
}

// Expect is what the report must satisfy.
type Expect struct {
	Container           string   `json:"container,omitempty"`           // scope verdict search to this container (plus pod level)
	VerdictKind         string   `json:"verdictKind"`                   // required verdict kind
	Confidence          string   `json:"confidence"`                    // required confidence of that verdict
	EvidenceKinds       []string `json:"evidenceKinds,omitempty"`       // evidence kinds that verdict must carry
	ForbidKinds         []string `json:"forbidKinds,omitempty"`         // verdict kinds that must not appear anywhere
	ForbidConfirmedText []string `json:"forbidConfirmedText,omitempty"` // text no confirmed verdict summary may contain
	CompetingContains   string   `json:"competingContains,omitempty"`
	Expectedness        string   `json:"expectedness,omitempty"`
	Role                string   `json:"role,omitempty"`
	RestartDecision     string   `json:"restartDecision,omitempty"`
	Contains            []string `json:"contains,omitempty"` // substrings of the JSON report
	NotContains         []string `json:"notContains,omitempty"`
	NoteContains        string   `json:"noteContains,omitempty"`
}

// Scenario is the parsed expected.json of one scenario directory.
type Scenario struct {
	Name           string `json:"-"`
	Dir            string `json:"-"`
	Description    string `json:"description"`
	Manifest       string `json:"manifest"` // default manifest.yaml
	TimeoutSeconds int    `json:"timeoutSeconds"`
	Steps          []Step `json:"steps,omitempty"`
	Cleanup        []Step `json:"cleanup,omitempty"`
	Target         Target `json:"target"`
	Expect         Expect `json:"expect"`
}

// LoadScenario reads <dir>/expected.json.
func LoadScenario(dir string) (*Scenario, error) {
	b, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	s.Dir, s.Name = dir, filepath.Base(dir)
	if s.Manifest == "" {
		s.Manifest = "manifest.yaml"
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = 180
	}
	return &s, nil
}

// Evaluate checks a report against the expectation and returns the first
// failure, or nil. knownUIDs are the UIDs evidence may legitimately carry
// besides the pod and its owners (for example the node UID or name).
func Evaluate(e Expect, r *classify.Report, knownUIDs ...string) error {
	all := r.AllVerdicts()
	for _, v := range all {
		for _, k := range e.ForbidKinds {
			if v.Kind == k {
				return fmt.Errorf("forbidden verdict kind %q present: %s", k, v.Summary)
			}
		}
		if v.Confidence == classify.Confirmed {
			for _, t := range e.ForbidConfirmedText {
				if strings.Contains(v.Summary, t) {
					return fmt.Errorf("confirmed verdict %q mentions %q: %s", v.Kind, t, v.Summary)
				}
			}
		}
	}
	var scoped []classify.Verdict
	scoped = append(scoped, r.Verdicts...)
	var cont *classify.ContainerReport
	for i := range r.Containers {
		c := &r.Containers[i]
		if e.Container == "" || c.Name == e.Container {
			scoped = append(scoped, c.Verdicts...)
			if cont == nil || e.Container != "" {
				cont = c
			}
		}
	}
	var found *classify.Verdict
	for i := range scoped {
		if scoped[i].Kind == e.VerdictKind {
			found = &scoped[i]
			break
		}
	}
	if found == nil {
		var kinds []string
		for _, v := range scoped {
			kinds = append(kinds, v.Kind+"("+string(v.Confidence)+")")
		}
		return fmt.Errorf("verdict kind %q not found; have %v", e.VerdictKind, kinds)
	}
	if e.Confidence != "" && string(found.Confidence) != e.Confidence {
		return fmt.Errorf("verdict %q has confidence %q, want %q", found.Kind, found.Confidence, e.Confidence)
	}
	for _, k := range e.EvidenceKinds {
		ok := false
		for _, ev := range found.Evidence {
			ok = ok || ev.Kind == k
		}
		if !ok {
			return fmt.Errorf("verdict %q lacks evidence of kind %q", found.Kind, k)
		}
	}
	if e.CompetingContains != "" {
		ok := false
		for _, c := range found.Competing {
			ok = ok || strings.Contains(c, e.CompetingContains)
		}
		if !ok {
			return fmt.Errorf("verdict %q competing explanations %v lack %q", found.Kind, found.Competing, e.CompetingContains)
		}
	}
	if (e.Expectedness != "" || e.Role != "" || e.RestartDecision != "") && cont == nil {
		return fmt.Errorf("no container report to check expectedness/role/restart")
	}
	if e.Expectedness != "" && (cont.Expected == nil || cont.Expected.State != e.Expectedness) {
		return fmt.Errorf("container %s expectedness = %+v, want %q", cont.Name, cont.Expected, e.Expectedness)
	}
	if e.Role != "" && cont.Role != e.Role {
		return fmt.Errorf("container %s role = %q, want %q", cont.Name, cont.Role, e.Role)
	}
	if e.RestartDecision != "" && !containsAny(e.RestartDecision, cont.Restart.Decision) {
		return fmt.Errorf("container %s restart decision = %q, want one of %q", cont.Name, cont.Restart.Decision, e.RestartDecision)
	}
	b, _ := json.Marshal(r)
	for _, s := range e.Contains {
		if !strings.Contains(string(b), s) {
			return fmt.Errorf("report does not contain %q", s)
		}
	}
	for _, s := range e.NotContains {
		if strings.Contains(string(b), s) {
			return fmt.Errorf("report contains forbidden %q", s)
		}
	}
	if e.NoteContains != "" {
		ok := false
		for _, n := range r.Notes {
			ok = ok || strings.Contains(n, e.NoteContains)
		}
		if !ok {
			return fmt.Errorf("notes %v lack %q", r.Notes, e.NoteContains)
		}
	}
	return checkEvidence(r, knownUIDs)
}

// checkEvidence enforces that evidence only references objects tied to this
// pod (by UID) and that event evidence carries a time.
func checkEvidence(r *classify.Report, known []string) error {
	allowed := map[string]bool{"": true, r.Pod.UID: true}
	for _, o := range r.Owners {
		allowed[o.UID] = true
	}
	for _, k := range known {
		allowed[k] = true
	}
	check := func(vs []classify.Verdict) error {
		for _, v := range vs {
			for _, ev := range v.Evidence {
				if r.Pod.Exists && !allowed[ev.UID] {
					return fmt.Errorf("verdict %q evidence %q references uid %q that is not the pod, an owner or the node", v.Kind, ev.Field, ev.UID)
				}
				if ev.Kind == classify.EvEvent && ev.Time == nil {
					return fmt.Errorf("verdict %q event evidence %q has no time", v.Kind, ev.Field)
				}
			}
		}
		return nil
	}
	if err := check(r.Verdicts); err != nil {
		return err
	}
	for _, c := range r.Containers {
		if err := check(c.Verdicts); err != nil {
			return err
		}
	}
	return nil
}

// containsAny reports whether got equals one of the "|" separated options.
func containsAny(options, got string) bool {
	for _, o := range strings.Split(options, "|") {
		if o == got {
			return true
		}
	}
	return false
}
