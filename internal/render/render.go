// Package render prints classify.Report values as text or JSON.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
)

// JSON writes one value (a Report or a list of Reports) as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type painter struct{ on bool }

func (p painter) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) bold(s string) string { return p.wrap("1", s) }
func (p painter) dim(s string) string  { return p.wrap("2", s) }
func (p painter) conf(c classify.Confidence) string {
	s := "[" + string(c) + "]"
	switch c {
	case classify.Confirmed:
		return p.wrap("32", s)
	case classify.Likely:
		return p.wrap("33", s)
	}
	return p.wrap("31", s)
}

// Text writes the human-readable report. color enables ANSI colors.
func Text(w io.Writer, r *classify.Report, color bool) {
	p := painter{color}
	pr := func(f string, a ...any) { fmt.Fprintf(w, f+"\n", a...) }

	pod := r.Pod
	if !pod.Exists {
		pr("%s", p.bold(fmt.Sprintf("Pod %s/%s: not found", pod.Namespace, pod.Name)))
	} else {
		pr("%s", p.bold(fmt.Sprintf("Pod %s/%s", pod.Namespace, pod.Name)))
		pr("  uid=%s node=%s phase=%s restartPolicy=%s", pod.UID, dash(pod.Node), pod.Phase, pod.RestartPolicy)
		if pod.Reason != "" {
			pr("  status.reason=%s message=%q", pod.Reason, pod.Message)
		}
		if pod.DeletionTimestamp != nil {
			pr("  deletionTimestamp=%s", pod.DeletionTimestamp.Format("2006-01-02T15:04:05Z"))
		}
	}
	if len(r.Owners) > 0 {
		var parts []string
		for _, o := range r.Owners {
			s := o.Kind + "/" + o.Name
			if !o.Found {
				s += " (not readable or gone)"
			}
			parts = append(parts, s)
		}
		pr("  owner: %s", strings.Join(parts, " -> "))
	}
	pr("  observed at %s; correlation window %s", r.ObservedAt.Format("2006-01-02T15:04:05Z"), r.Window)

	summary(w, p, r)
	if len(r.Verdicts) > 0 {
		pr("")
		pr("%s", p.bold("Pod"))
		for _, v := range r.Verdicts {
			verdict(w, p, v, "  ")
		}
	}
	for _, c := range r.Containers {
		pr("")
		pr("%s", p.bold(fmt.Sprintf("Container %s (%s)", c.Name, c.Role)))
		pr("  state: %s; restartCount=%d (as reported now; may have been reset)", c.CurrentState, c.RestartCount)
		if t := c.Termination; t != nil {
			pr("  explained instance: %s, containerID=%s", t.Source, dash(t.ContainerID))
			line := fmt.Sprintf("  API reported exitCode=%d", t.ExitCode)
			if t.Reason != "" {
				line += " reason=" + t.Reason
			}
			if t.Signal != 0 {
				line += fmt.Sprintf(" signal=%d", t.Signal)
			}
			pr("%s", line)
			if t.StartedAt != nil || t.FinishedAt != nil {
				pr("  started %s, finished %s", ts(t.StartedAt), ts(t.FinishedAt))
			}
			if t.Message != "" {
				pr("  message: %s", t.Message)
			}
		}
		if c.Expected != nil {
			pr("  stop expected for this role: %s: %s", c.Expected.State, c.Expected.Why)
		}
		pr("  restart: policy=%s decision=%s: %s", c.Restart.Policy, c.Restart.Decision, c.Restart.Detail)
		for _, e := range c.Restart.Evidence {
			pr("    - %s", evidence(e))
		}
		for _, v := range c.Verdicts {
			verdict(w, p, v, "  ")
		}
		if len(c.LogTail) > 0 {
			which := "logs of this instance"
			if c.LogsPrevious {
				which = "previous logs"
			}
			pr("  %s (last %d lines):", which, len(c.LogTail))
			for _, l := range c.LogTail {
				pr("    | %s", l)
			}
		}
	}
	if len(r.Context) > 0 {
		pr("")
		pr("%s", p.bold("Context (no verdict is drawn from these)"))
		for _, e := range r.Context {
			pr("  - %s", evidence(e))
		}
	}
	if len(r.Notes) > 0 {
		pr("")
		for _, n := range r.Notes {
			pr("note: %s", n)
		}
	}
	pr("")
	pr("%s", p.bold("Checked"))
	for _, c := range r.Checked {
		pr("  - %s", c)
	}
	if len(r.Gaps) > 0 {
		pr("%s", p.bold("Gaps (not evidence)"))
		for _, g := range r.Gaps {
			pr("  - %s: %s", g.Source, g.Reason)
		}
	}
}

func verdict(w io.Writer, p painter, v classify.Verdict, ind string) {
	fmt.Fprintf(w, "%s%s %s: %s\n", ind, p.conf(v.Confidence), v.Kind, v.Summary)
	for _, c := range v.Competing {
		fmt.Fprintf(w, "%s  %s %s\n", ind, p.dim("caveat:"), c)
	}
	for _, e := range v.Evidence {
		fmt.Fprintf(w, "%s  - %s\n", ind, evidence(e))
	}
}

func evidence(e classify.Evidence) string {
	s := fmt.Sprintf("[%s] %s %s", e.Kind, e.Object, e.Field)
	if e.Value != "" {
		s += " = " + quote(e.Value)
	}
	if e.Time != nil {
		s += " @ " + e.Time.Format("2006-01-02T15:04:05Z")
	}
	if e.UID != "" {
		s += " (uid " + e.UID + ")"
	}
	if e.Note != "" {
		s += " [" + e.Note + "]"
	}
	return s
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t\n\"") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func ts(t *time.Time) string {
	if t == nil {
		return "unknown"
	}
	return t.Format("2006-01-02T15:04:05Z")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Line renders a one-line verdict for list mode.
func Line(r *classify.Report) string {
	name := r.Pod.Namespace + "/" + r.Pod.Name
	c, v, ok := r.Headline()
	if !ok {
		return name + ": no data"
	}
	if c != "" {
		name += " " + c
	}
	return fmt.Sprintf("%s: [%s] %s: %s", name, v.Confidence, v.Kind, v.Summary)
}

// summary prints one headline per scope before the detailed evidence.
func summary(w io.Writer, p painter, r *classify.Report) {
	var lines []string
	for _, v := range r.Verdicts {
		lines = append(lines, fmt.Sprintf("  %s pod: %s: %s", p.conf(v.Confidence), v.Kind, v.Summary))
	}
	for _, c := range r.Containers {
		if len(c.Verdicts) == 0 {
			continue
		}
		v := c.Verdicts[0]
		lines = append(lines, fmt.Sprintf("  %s %s: %s: %s", p.conf(v.Confidence), c.Name, v.Kind, v.Summary))
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.bold("Summary"))
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
