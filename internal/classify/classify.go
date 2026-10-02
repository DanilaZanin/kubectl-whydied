package classify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

// DefaultWindow is the default correlation window between a termination and events.
const DefaultWindow = 2 * time.Minute

// Options controls classification.
type Options struct {
	Window    time.Duration
	Container string // restrict container reports ("" = all)
}

type analysis struct {
	s   *collect.Snapshot
	o   Options
	pod *corev1.Pod

	podEvents   []*corev1.Event // involvedObject.uid == pod UID
	ownerEvents []*corev1.Event
	hpaEvents   []*corev1.Event
	nodeEvents  []*corev1.Event
	otherUIDs   map[string]int // events for the same pod name but another UID
	nameEvents  []*corev1.Event
	noUIDEvents []*corev1.Event // context only, never evidence for a verdict

	gaps []collect.Gap

	eventsDenied string // non-empty when the pod events could not be read: "RBAC" or "error"
}

// Analyze classifies a snapshot. It never mutates it.
func Analyze(s *collect.Snapshot, o Options) (*Report, error) {
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	a := &analysis{s: s, o: o, pod: s.Pod, otherUIDs: map[string]int{}}
	a.gaps = append(a.gaps, s.Gaps...)
	a.sortEvents()
	for _, g := range s.Gaps {
		if g.Source == "events for pod name" {
			a.eventsDenied = "error"
			if strings.Contains(g.Reason, "forbidden") {
				a.eventsDenied = "RBAC"
			}
		}
	}

	r := &Report{ObservedAt: s.CollectedAt, Window: o.Window.String(), Verdicts: []Verdict{}, Containers: []ContainerReport{}}
	r.Pod = PodInfo{Namespace: s.Namespace, Name: s.Name, Exists: s.Pod != nil}
	for _, ow := range s.Owners {
		r.Owners = append(r.Owners, OwnerInfo{Kind: ow.Kind, Name: ow.Name, UID: string(ow.UID), Found: ow.Found})
	}

	if a.pod == nil {
		a.gone(r)
		r.Checked = a.checked()
		r.Gaps = a.gaps
		return r, nil
	}
	p := a.pod
	r.Pod.UID = string(p.UID)
	r.Pod.Phase = string(p.Status.Phase)
	r.Pod.Reason, r.Pod.Message = p.Status.Reason, p.Status.Message
	r.Pod.Node = p.Spec.NodeName
	if p.Status.StartTime != nil {
		r.Pod.StartTime = mt(*p.Status.StartTime)
	}
	if p.DeletionTimestamp != nil {
		r.Pod.DeletionTimestamp = mt(*p.DeletionTimestamp)
	}
	r.Pod.RestartPolicy = string(p.Spec.RestartPolicy)

	if o.Container != "" {
		found := false
		for _, ref := range collect.AllStatuses(p) {
			found = found || ref.Status.Name == o.Container
		}
		for _, c := range p.Spec.InitContainers {
			found = found || c.Name == o.Container
		}
		for _, c := range p.Spec.Containers {
			found = found || c.Name == o.Container
		}
		for _, c := range p.Spec.EphemeralContainers {
			found = found || c.Name == o.Container
		}
		if !found {
			return nil, fmt.Errorf("container %q not found in pod %s/%s", o.Container, p.Namespace, p.Name)
		}
	}

	if vs := a.podVerdicts(); vs != nil {
		r.Verdicts = vs
	}
	for _, ref := range collect.AllStatuses(p) {
		if o.Container != "" && ref.Status.Name != o.Container {
			continue
		}
		r.Containers = append(r.Containers, a.container(ref))
	}
	// Containers that are in the spec but have no status yet (pod not started).
	have := map[string]bool{}
	for _, ref := range collect.AllStatuses(p) {
		have[ref.Status.Name] = true
	}
	var missing []ContainerReport
	for _, c := range p.Spec.InitContainers {
		if !have[c.Name] && (o.Container == "" || o.Container == c.Name) {
			_, role := containerSpec(p, c.Name)
			missing = append(missing, a.specOnly(c.Name, role))
		}
	}
	for _, c := range p.Spec.Containers {
		if !have[c.Name] && (o.Container == "" || o.Container == c.Name) {
			missing = append(missing, a.specOnly(c.Name, "regular"))
		}
	}
	r.Containers = append(missing[:len(missing):len(missing)], r.Containers...)
	a.attachLogs(r)
	r.Context = a.nodeContext()
	for _, e := range a.noUIDEvents {
		ev := evEvent(e)
		ev.Note = "context only: this event has no involvedObject.uid, so it cannot be tied to this pod by identity; matched by name and by time not before the pod was created"
		r.Context = append(r.Context, ev)
	}
	r.Notes = a.notes()
	a.eventGaps(r)
	r.Checked = a.checked()
	r.Gaps = a.gaps
	return r, nil
}

func (a *analysis) sortEvents() {
	owners := map[string]bool{}
	for _, ow := range a.s.Owners {
		owners[string(ow.UID)] = true
	}
	hpas := map[string]bool{}
	for _, h := range a.s.HPAs {
		hpas[string(h.UID)] = true
	}
	for i := range a.s.Events {
		e := &a.s.Events[i]
		uid := string(e.InvolvedObject.UID)
		switch {
		case e.InvolvedObject.Kind == "Pod" && e.InvolvedObject.Name == a.s.Name:
			a.nameEvents = append(a.nameEvents, e)
			switch {
			case a.pod == nil:
			case uid == string(a.pod.UID):
				a.podEvents = append(a.podEvents, e)
			case uid == "":
				// Some controllers (for example the taint manager) emit events without
				// involvedObject.uid. A name and a time bound cannot prove they belong to
				// this pod (a name can be reused), so they are shown as context only and
				// never support a verdict.
				if _, l := eventTimes(e); !l.Before(a.pod.CreationTimestamp.Time) {
					a.noUIDEvents = append(a.noUIDEvents, e)
				} else {
					a.otherUIDs["(no uid, older than this pod)"]++
				}
			default:
				a.otherUIDs[uid]++
			}
		case e.InvolvedObject.Kind == "Node":
			a.nodeEvents = append(a.nodeEvents, e)
		case hpas[uid]:
			a.hpaEvents = append(a.hpaEvents, e)
		case owners[uid]:
			a.ownerEvents = append(a.ownerEvents, e)
		}
	}
	byTime := func(es []*corev1.Event) {
		sort.SliceStable(es, func(i, j int) bool {
			_, li := eventTimes(es[i])
			_, lj := eventTimes(es[j])
			return li.Before(lj)
		})
	}
	byTime(a.podEvents)
	byTime(a.ownerEvents)
	byTime(a.hpaEvents)
	byTime(a.nodeEvents)
	byTime(a.nameEvents)
}

func (a *analysis) notes() []string {
	var out []string
	if len(a.otherUIDs) > 0 {
		var uids []string
		n := 0
		for u, c := range a.otherUIDs {
			uids = append(uids, u)
			n += c
		}
		sort.Strings(uids)
		out = append(out, fmt.Sprintf("%d event(s) for a pod with the same name but a different UID were ignored (UIDs: %s). They belong to an earlier or later pod, not this one.", n, strings.Join(uids, ", ")))
	}
	return out
}

func (a *analysis) checked() []string {
	c := []string{"pod status and spec"}
	if a.pod != nil {
		if a.eventsDenied != "" {
			c = append(c, "events: not readable ("+a.eventsDenied+"); causes that only an event can prove were not evaluated")
		} else {
			c = append(c, "events by involvedObject.uid for the pod ("+fmt.Sprint(len(a.podEvents))+" found)")
		}
		if len(a.s.Owners) > 0 {
			var parts []string
			for _, o := range a.s.Owners {
				parts = append(parts, o.Kind+"/"+o.Name)
			}
			c = append(c, "owner chain and owner events: "+strings.Join(parts, " -> "))
		} else {
			c = append(c, "owner chain (pod has no controller)")
		}
		if a.s.Node != nil {
			c = append(c, "node conditions, taints, labels and node events (current state only)")
		}
		if len(a.s.Logs) > 0 {
			c = append(c, "previous container logs")
		}
	} else {
		if a.eventsDenied != "" {
			c = append(c, "events: not readable ("+a.eventsDenied+")")
		} else {
			c = append(c, "events by pod name ("+fmt.Sprint(len(a.nameEvents))+" found)")
		}
	}
	return c
}

// gone builds the report for a pod that no longer exists.
func (a *analysis) gone(r *Report) {
	v := Verdict{
		Kind:       KindPodGone,
		Confidence: NoData,
		Summary:    "pod not found; its status history is not available from the API",
		Competing:  []string{"the pod was deleted by a user, a controller, preemption, eviction or garbage collection; none of that is recorded once the object is gone"},
	}
	uids := map[string]bool{}
	start := 0
	if len(a.nameEvents) > 12 {
		start = len(a.nameEvents) - 12
	}
	for _, e := range a.nameEvents {
		uids[string(e.InvolvedObject.UID)] = true
	}
	for _, e := range a.nameEvents[start:] {
		v.Evidence = append(v.Evidence, evEvent(e))
	}
	if len(a.nameEvents) > 0 {
		var l []string
		for u := range uids {
			l = append(l, u)
		}
		sort.Strings(l)
		r.Notes = append(r.Notes, fmt.Sprintf("%d event(s) still reference this pod name (UIDs: %s); they are listed as evidence and do not identify a cause by themselves", len(a.nameEvents), strings.Join(l, ", ")))
		if len(l) > 1 {
			r.Notes = append(r.Notes, "more than one UID used this pod name; events from different pods may be mixed")
		}
	} else if a.eventsDenied == "" {
		a.gaps = append(a.gaps, collect.Gap{Source: "events", Reason: "no events reference this pod name; events expire after about one hour by default"})
	}
	r.Verdicts = []Verdict{v}
}

func (a *analysis) eventGaps(r *Report) {
	if len(a.podEvents) > 0 || a.eventsDenied != "" {
		return
	}
	for _, c := range r.Containers {
		if c.Termination != nil {
			a.gaps = append(a.gaps, collect.Gap{Source: "events", Reason: "no events found for this pod UID; events expire after about one hour by default and can be dropped under load, so causes that only an event can prove are unknown"})
			return
		}
	}
}

func (a *analysis) attachLogs(r *Report) {
	for i := range r.Containers {
		c := &r.Containers[i]
		l, ok := a.s.Logs[c.Name]
		if !ok {
			continue
		}
		c.LogTail = l.Lines
		c.LogsPrevious = l.Previous
		c.LogNote = "the logs API returns no container ID: these lines are associated with the explained instance by position (previous or current container) and are an assumption"
		switch {
		case a.pod != nil && l.PodUID != "" && l.PodUID != string(a.pod.UID):
			a.gaps = append(a.gaps, collect.Gap{Source: "logs/" + c.Name, Reason: "logs were read for a different pod UID than this pod; they may belong to another instance"})
		case c.Termination == nil, l.ContainerID != c.Termination.ContainerID, l.Source != "" && l.Source != c.Termination.Source:
			a.gaps = append(a.gaps, collect.Gap{Source: "logs/" + c.Name, Reason: "logs were read for a different instance (containerID or source differs from the explained termination); they may belong to another instance"})
		}
	}
}

func (a *analysis) nodeContext() []Evidence {
	n := a.s.Node
	if n == nil {
		return nil
	}
	obj := "Node " + n.Name
	var out []Evidence
	for _, t := range n.Spec.Taints {
		out = append(out, Evidence{Kind: EvNodeMeta, Object: obj, UID: string(n.UID), Field: "spec.taints", Value: fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect), Note: "context only; current state, no history"})
	}
	if n.Spec.Unschedulable {
		out = append(out, Evidence{Kind: EvNodeMeta, Object: obj, UID: string(n.UID), Field: "spec.unschedulable", Value: "true", Note: "node is cordoned (current state only); cordon alone does not evict pods"})
	}
	interesting := []string{"cloud.google.com/gke-preemptible", "cloud.google.com/gke-spot", "karpenter.sh/", "eks.amazonaws.com/capacityType", "node.kubernetes.io/instance-type", "topology.kubernetes.io/"}
	var keys []string
	for k := range n.Labels {
		for _, p := range interesting {
			if strings.HasPrefix(k, p) {
				keys = append(keys, k)
				break
			}
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, Evidence{Kind: EvNodeMeta, Object: obj, UID: string(n.UID), Field: "metadata.labels[" + k + "]", Value: n.Labels[k], Note: "context only; provider attribution is not done in v0.1"})
	}
	keys = keys[:0]
	for k := range n.Annotations {
		if strings.HasPrefix(k, "cluster-autoscaler.kubernetes.io/") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, Evidence{Kind: EvNodeMeta, Object: obj, UID: string(n.UID), Field: "metadata.annotations[" + k + "]", Value: n.Annotations[k], Note: "context only"})
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			continue
		}
		if c.Type != corev1.NodeReady && c.Status != corev1.ConditionTrue {
			continue
		}
		out = append(out, Evidence{Kind: EvNodeCondition, Object: obj, UID: string(n.UID), Field: "status.conditions[" + string(c.Type) + "]", Value: fmt.Sprintf("%s: %s", c.Status, c.Message), Time: mt(c.LastTransitionTime), Note: "current state only; node conditions have no history"})
	}
	return out
}
