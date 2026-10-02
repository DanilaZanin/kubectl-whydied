package classify

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func mt(t metav1.Time) *time.Time { return tp(t.Time) }

func fmtTime(t *time.Time) string {
	if t == nil {
		return "unknown time"
	}
	return t.UTC().Format(time.RFC3339)
}

// eventTimes returns first and last occurrence of an (aggregated) event.
func eventTimes(e *corev1.Event) (first, last time.Time) {
	first = e.FirstTimestamp.Time
	if first.IsZero() {
		first = e.EventTime.Time
	}
	last = e.LastTimestamp.Time
	if last.IsZero() && e.Series != nil {
		last = e.Series.LastObservedTime.Time
	}
	if last.IsZero() {
		last = e.EventTime.Time
	}
	if last.IsZero() {
		last = first
	}
	if first.IsZero() {
		first = last
	}
	return first, last
}

func eventCount(e *corev1.Event) int32 {
	c := e.Count
	if e.Series != nil && e.Series.Count > c {
		c = e.Series.Count
	}
	if c == 0 {
		c = 1
	}
	return c
}

// covers reports whether t lies inside [first-w, last+w] of the event.
func covers(e *corev1.Event, t time.Time, w time.Duration) bool {
	if t.IsZero() {
		return false
	}
	f, l := eventTimes(e)
	if f.IsZero() {
		return false
	}
	return !t.Before(f.Add(-w)) && !t.After(l.Add(w))
}

func evEvent(e *corev1.Event) Evidence {
	f, l := eventTimes(e)
	ev := Evidence{
		Kind:   EvEvent,
		Object: fmt.Sprintf("%s %s/%s", e.InvolvedObject.Kind, nsOrNone(e.InvolvedObject.Namespace), e.InvolvedObject.Name),
		UID:    string(e.InvolvedObject.UID),
		Field:  "event " + e.Reason,
		Value:  e.Message,
		Time:   tp(l),
		Count:  eventCount(e),
	}
	if e.InvolvedObject.FieldPath != "" {
		ev.Note = "fieldPath=" + e.InvolvedObject.FieldPath
	}
	if e.InvolvedObject.UID == "" && e.InvolvedObject.Kind == "Pod" {
		extra := "event has no involvedObject.uid; matched by pod name and by time (not before the pod was created)"
		if ev.Note != "" {
			ev.Note += "; " + extra
		} else {
			ev.Note = extra
		}
	}
	if eventCount(e) > 1 {
		ev.FirstTime = tp(f)
		extra := fmt.Sprintf("event repeated %d times (aggregated; first %s, last %s)", eventCount(e), fmtTime(tp(f)), fmtTime(tp(l)))
		if ev.Note != "" {
			ev.Note += "; " + extra
		} else {
			ev.Note = extra
		}
	}
	return ev
}

func nsOrNone(ns string) string {
	if ns == "" {
		return "-"
	}
	return ns
}

// containerOfEvent extracts the container name from a fieldPath such as
// spec.containers{app}; it returns "" when the event is not container scoped.
func containerOfEvent(e *corev1.Event) string {
	fp := e.InvolvedObject.FieldPath
	i := strings.Index(fp, "{")
	j := strings.LastIndex(fp, "}")
	if i < 0 || j < i {
		return ""
	}
	return fp[i+1 : j]
}

func podObj(p *corev1.Pod) string { return fmt.Sprintf("Pod %s/%s", p.Namespace, p.Name) }

func podEv(p *corev1.Pod, kind, field, value string, t *time.Time) Evidence {
	return Evidence{Kind: kind, Object: podObj(p), UID: string(p.UID), Field: field, Value: value, Time: t}
}

func containerSpec(p *corev1.Pod, name string) (spec *corev1.Container, role string) {
	for i := range p.Spec.InitContainers {
		if p.Spec.InitContainers[i].Name == name {
			c := &p.Spec.InitContainers[i]
			if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				return c, "sidecar"
			}
			return c, "init"
		}
	}
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == name {
			return &p.Spec.Containers[i], "regular"
		}
	}
	for i := range p.Spec.EphemeralContainers {
		if p.Spec.EphemeralContainers[i].Name == name {
			ec := p.Spec.EphemeralContainers[i]
			return &corev1.Container{Name: ec.Name, Image: ec.Image}, "ephemeral"
		}
	}
	return nil, "regular"
}

// effectivePolicy returns the restart policy that applies to a container.
func effectivePolicy(p *corev1.Pod, c *corev1.Container, role string) string {
	if c != nil && c.RestartPolicy != nil {
		return string(*c.RestartPolicy)
	}
	if role == "sidecar" {
		return "Always"
	}
	if p.Spec.RestartPolicy == "" {
		return string(corev1.RestartPolicyAlways)
	}
	return string(p.Spec.RestartPolicy)
}

func podTerminal(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

func disruptionTarget(p *corev1.Pod) *corev1.PodCondition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == corev1.DisruptionTarget {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

var signalNames = map[int]string{
	1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
	9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
	16: "SIGSTKFLT", 17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP", 21: "SIGTTIN", 22: "SIGTTOU",
	23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ", 26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO",
	30: "SIGPWR", 31: "SIGSYS",
}

func signalName(n int) string {
	if s, ok := signalNames[n]; ok {
		return s
	}
	return fmt.Sprintf("signal %d", n)
}

// Match levels of an event against one container instance.
const (
	matchNone  = iota // the event lies entirely outside the instance's lifetime
	matchSpans        // an aggregated event spans the instance, but no known occurrence is inside it
	matchExact        // the first or the last occurrence lies inside the instance's lifetime
)

// instanceMatch tells how an (aggregated) event relates to the instance that
// ended with term. Only the first and the last occurrence have known times, and
// both are real occurrences, so an endpoint inside [start, finish] confirms the
// link. An event wholly before the start belongs to an earlier instance; wholly
// after the end, to a later one. Timestamps have one-second resolution, hence the slack.
func instanceMatch(e *corev1.Event, term *corev1.ContainerStateTerminated) int {
	if term == nil || term.FinishedAt.IsZero() {
		return matchNone
	}
	first, last := eventTimes(e)
	if last.IsZero() {
		return matchNone
	}
	slack := time.Second
	start := term.StartedAt.Time
	if start.IsZero() {
		start = term.FinishedAt.Add(-time.Minute)
	}
	lo, hi := start.Add(-slack), term.FinishedAt.Add(slack)
	in := func(t time.Time) bool { return !t.Before(lo) && !t.After(hi) }
	switch {
	case in(first) || in(last):
		return matchExact
	case first.Before(lo) && last.After(hi) && eventCount(e) > 2:
		return matchSpans
	}
	return matchNone
}
