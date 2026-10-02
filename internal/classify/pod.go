package classify

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func (a *analysis) podEventsWithReason(reasons ...string) []*corev1.Event {
	var out []*corev1.Event
	for _, e := range a.podEvents {
		for _, r := range reasons {
			if e.Reason == r {
				out = append(out, e)
			}
		}
	}
	return out
}

func (a *analysis) podVerdicts() []Verdict {
	p := a.pod
	var vs []Verdict
	attributed := false

	if v, ok := a.disruption(); ok {
		vs = append(vs, v)
		attributed = true
	}
	if v, ok := a.taintCancelled(); ok {
		vs = append(vs, v)
	}
	if cd, ok := a.controllerDelete(); ok {
		vs = append(vs, cd)
		attributed = true
		vs = append(vs, a.scaleReason(cd)...)
	}
	if p.DeletionTimestamp != nil && !attributed {
		vs = append(vs, a.unattributedDeletion())
	}
	if v, ok := a.nodeNotReady(); ok {
		vs = append(vs, v)
	}
	if evs := a.podEventsWithReason("SandboxChanged"); len(evs) > 0 {
		v := Verdict{Kind: KindSandboxChanged, Confidence: Confirmed,
			Summary: "the kubelet reported that the pod sandbox changed and that it will kill and recreate the pod's containers; this is a restart trigger independent of the containers' own exit codes"}
		for _, e := range evs {
			v.Evidence = append(v.Evidence, evEvent(e))
		}
		vs = append(vs, v)
	}
	if p.Status.Reason != "" && !attributed && p.Status.Reason != "Evicted" && p.Status.Reason != "Preempting" {
		vs = append(vs, Verdict{Kind: KindPodStatusReason, Confidence: Confirmed,
			Summary: "the pod status carries a reason set by the kubelet or a controller (quoted verbatim); the API does not explain it further",
			Evidence: []Evidence{
				podEv(p, EvPodStatus, "status.reason", p.Status.Reason, nil),
				podEv(p, EvPodStatus, "status.message", p.Status.Message, nil),
			}})
	}
	return vs
}

func (a *analysis) disruption() (Verdict, bool) {
	p := a.pod
	cond := condition(p, corev1.DisruptionTarget)
	if cond != nil && cond.Status != corev1.ConditionTrue {
		cond = nil
	}
	statusReason := p.Status.Reason
	preempted := a.podEventsWithReason("Preempted")

	var ev []Evidence
	if cond != nil {
		e := podEv(p, EvPodCondition, "status.conditions[DisruptionTarget]", fmt.Sprintf("status=%s reason=%s message=%q", cond.Status, cond.Reason, cond.Message), mt(cond.LastTransitionTime))
		ev = append(ev, e)
	}
	if statusReason != "" {
		ev = append(ev, podEv(p, EvPodStatus, "status.reason", statusReason, nil))
		if p.Status.Message != "" {
			ev = append(ev, podEv(p, EvPodStatus, "status.message", p.Status.Message, nil))
		}
	}
	condReason := ""
	if cond != nil {
		condReason = cond.Reason
	}
	msg := p.Status.Message
	if msg == "" && cond != nil {
		msg = cond.Message
	}
	note := "the DisruptionTarget condition shows a disruption was initiated; it does not by itself guarantee the disruption completed"

	v := Verdict{Confidence: Confirmed}
	switch {
	case condReason == "PreemptionByScheduler" || (cond == nil && len(preempted) > 0):
		v.Kind = KindPreemptScheduler
		v.Summary = "the scheduler preempted this pod to make room for a higher-priority pod"
		for _, e := range preempted {
			ev = append(ev, evEvent(e))
		}
	case condReason == "DeletionByTaintManager":
		v.Kind = KindTaintEviction
		v.Summary = "the taint manager deleted this pod because of a NoExecute taint it does not tolerate"
		for _, e := range a.podEventsWithReason("TaintManagerEviction") {
			ev = append(ev, evEvent(e))
		}
	case condReason == "EvictionByEvictionAPI":
		v.Kind = KindEvictionAPI
		v.Summary = "the pod was evicted through the Eviction API (this is what kubectl drain uses; the caller is not recorded)"
		v.Competing = []string{"any client can call the Eviction API: kubectl drain, a cluster autoscaler, an operator; the API does not name the caller"}
	case condReason == "DeletionByPodGC":
		v.Kind = KindPodGC
		v.Summary = "pod garbage collection deleted this pod (for example because its node no longer exists)"
	case statusReason == "Evicted":
		switch {
		case strings.Contains(msg, "EmptyDir volume") && strings.Contains(msg, "exceeds the limit"),
			strings.Contains(msg, "exceeded its local ephemeral storage limit"),
			strings.Contains(msg, "ephemeral local storage usage exceeds the total limit"):
			v.Kind = KindEvictionStorage
			v.Summary = "the kubelet evicted the pod because it exceeded a local storage limit (message quoted verbatim); this does not require node DiskPressure"
		case strings.Contains(msg, "The node was low on resource"):
			v.Kind = KindEvictionNodePress
			v.Summary = "the kubelet evicted the pod under node resource pressure (message quoted verbatim)"
			if n := a.s.Node; n != nil {
				for _, c := range n.Status.Conditions {
					if (c.Type == corev1.NodeMemoryPressure || c.Type == corev1.NodeDiskPressure || c.Type == corev1.NodePIDPressure) && c.Status == corev1.ConditionTrue {
						ev = append(ev, Evidence{Kind: EvNodeCondition, Object: "Node " + n.Name, UID: string(n.UID), Field: "status.conditions[" + string(c.Type) + "]", Value: string(c.Status) + ": " + c.Message, Time: mt(c.LastTransitionTime), Note: "current state only; node conditions have no history"})
					}
				}
			}
		default:
			v.Kind = KindKubeletTermination
			v.Summary = "the kubelet evicted the pod (status.reason=Evicted); the message is quoted verbatim"
		}
		for _, e := range a.podEventsWithReason("Evicted") {
			ev = append(ev, evEvent(e))
		}
	case statusReason == "Preempting":
		v.Kind = KindPreemptKubelet
		v.Summary = "the kubelet preempted this pod to admit a critical pod (kubelet admission preemption, not the scheduler)"
		for _, e := range a.podEventsWithReason("Preempting") {
			ev = append(ev, evEvent(e))
		}
	case condReason == "TerminationByKubelet":
		v.Kind = KindKubeletTermination
		v.Summary = "the kubelet initiated termination of this pod (DisruptionTarget reason TerminationByKubelet: node-pressure eviction, node shutdown or kubelet preemption); the message is quoted verbatim"
	default:
		return Verdict{}, false
	}
	if cond != nil && v.Kind != KindKubeletTermination {
		v.Competing = append(v.Competing, note)
	}
	v.Evidence = ev
	return v, true
}

func (a *analysis) taintCancelled() (Verdict, bool) {
	evs := a.podEventsWithReason("TaintManagerEviction")
	if len(evs) == 0 || a.pod.DeletionTimestamp != nil {
		return Verdict{}, false
	}
	last := evs[len(evs)-1]
	if !strings.HasPrefix(last.Message, "Cancelling deletion") {
		return Verdict{}, false
	}
	return Verdict{Kind: KindTaintCancelled, Confidence: Confirmed,
		Summary:  "the taint manager cancelled a pending deletion of this pod (the taint was removed or tolerated); this event is not a death",
		Evidence: []Evidence{evEvent(last)}}, true
}

func containsWord(msg, w string) bool {
	isName := func(b byte) bool {
		return b == '-' || b == '.' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
	}
	for i := 0; ; {
		j := strings.Index(msg[i:], w)
		if j < 0 {
			return false
		}
		s, e := i+j, i+j+len(w)
		if (s == 0 || !isName(msg[s-1])) && (e == len(msg) || !isName(msg[e])) {
			return true
		}
		i = s + 1
	}
}

func (a *analysis) controllerDelete() (Verdict, bool) {
	p := a.pod
	for i := len(a.ownerEvents) - 1; i >= 0; i-- {
		e := a.ownerEvents[i]
		if e.Reason != "SuccessfulDelete" || !containsWord(e.Message, p.Name) {
			continue
		}
		if _, l := eventTimes(e); l.Before(p.CreationTimestamp.Time) {
			continue
		}
		ev := []Evidence{evEvent(e)}
		for _, ref := range p.OwnerReferences {
			if ref.UID == e.InvolvedObject.UID {
				ev = append(ev, podEv(p, EvOwner, "metadata.ownerReferences", fmt.Sprintf("%s/%s uid=%s controller=true", ref.Kind, ref.Name, ref.UID), nil))
			}
		}
		return Verdict{Kind: KindControllerDelete, Confidence: Confirmed,
			Summary:   fmt.Sprintf("%s %s issued a delete for this pod (its SuccessfulDelete event names the pod)", e.InvolvedObject.Kind, e.InvolvedObject.Name),
			Competing: []string{"why the controller scaled down (rollout, manual scale, HPA) is not part of this event; it is reported separately only when its own evidence exists"},
			Evidence:  ev}, true
	}
	return Verdict{}, false
}

func (a *analysis) scaleReason(cd Verdict) []Verdict {
	var out []Verdict
	var rsRev, depRev string
	var dep string
	for _, o := range a.s.Owners {
		switch o.Kind {
		case "ReplicaSet":
			rsRev = o.Revision
		case "Deployment":
			depRev, dep = o.Revision, o.Name
		}
	}
	rs, err1 := strconv.Atoi(rsRev)
	dr, err2 := strconv.Atoi(depRev)
	if err1 == nil && err2 == nil && rs < dr {
		v := Verdict{Kind: KindScaleRollout, Confidence: Likely,
			Summary:   fmt.Sprintf("the pod's ReplicaSet is revision %d while Deployment %s is at revision %d: consistent with a rollout replacing old pods", rs, dep, dr),
			Competing: []string{"an old-revision ReplicaSet can also be scaled down for other reasons; the revision numbers alone do not show who started the change"}}
		for _, o := range a.s.Owners {
			if o.Kind == "ReplicaSet" || o.Kind == "Deployment" {
				v.Evidence = append(v.Evidence, Evidence{Kind: EvOwner, Object: fmt.Sprintf("%s %s/%s", o.Kind, a.s.Namespace, o.Name), UID: string(o.UID), Field: "metadata.annotations[deployment.kubernetes.io/revision]", Value: o.Revision})
			}
		}
		for _, e := range a.ownerEvents {
			if e.Reason == "ScalingReplicaSet" {
				v.Evidence = append(v.Evidence, evEvent(e))
			}
		}
		out = append(out, v)
	}
	// HPA evidence: SuccessfulRescale near the delete event.
	if len(cd.Evidence) > 0 && cd.Evidence[0].Time != nil {
		var hits []Evidence
		for _, e := range a.hpaEvents {
			if e.Reason == "SuccessfulRescale" && covers(e, *cd.Evidence[0].Time, a.o.Window) {
				hits = append(hits, evEvent(e))
			}
		}
		if len(hits) > 0 {
			out = append(out, Verdict{Kind: KindScaleHPA, Confidence: Likely,
				Summary:   "a HorizontalPodAutoscaler targeting the Deployment reported a rescale within the correlation window of the delete",
				Competing: []string{"a manual scale at the same time is not distinguishable"},
				Evidence:  hits})
		}
	}
	return out
}

func (a *analysis) unattributedDeletion() Verdict {
	p := a.pod
	ev := []Evidence{podEv(p, EvPodStatus, "metadata.deletionTimestamp", fmtTime(mt(*p.DeletionTimestamp)), mt(*p.DeletionTimestamp))}
	if p.DeletionGracePeriodSeconds != nil {
		ev = append(ev, podEv(p, EvPodStatus, "metadata.deletionGracePeriodSeconds", fmt.Sprint(*p.DeletionGracePeriodSeconds), nil))
	}
	return Verdict{Kind: KindDeletionUnattrib, Confidence: Likely,
		Summary: "the pod is being deleted (metadata.deletionTimestamp is set) and no controller event, DisruptionTarget condition or eviction status names a cause; consistent with a direct client delete (for example kubectl delete), but the API does not record who asked",
		Competing: []string{
			"a controller or operator that does not emit a SuccessfulDelete event",
			"events expired (about one hour by default); the API server audit log is not readable by this tool",
		},
		Evidence: ev}
}

func (a *analysis) nodeNotReady() (Verdict, bool) {
	n := a.s.Node
	if n == nil {
		return Verdict{}, false
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue {
			v := Verdict{Kind: KindNodeNotReady, Confidence: Confirmed,
				Summary:   fmt.Sprintf("node %s reports Ready=%s since %s (current state only); this shows the node is unobservable or unhealthy, not that this container stopped", n.Name, c.Status, fmtTime(mt(c.LastTransitionTime))),
				Competing: []string{"the containers may still be running on the node; node conditions have no history, so earlier flaps are not visible"},
				Evidence: []Evidence{{Kind: EvNodeCondition, Object: "Node " + n.Name, UID: string(n.UID), Field: "status.conditions[Ready]",
					Value: fmt.Sprintf("%s: %s", c.Status, c.Message), Time: mt(c.LastTransitionTime), Note: "current state only"}}}
			for _, e := range a.nodeEvents {
				if e.Reason == "NodeNotReady" {
					v.Evidence = append(v.Evidence, evEvent(e))
				}
			}
			return v, true
		}
	}
	return Verdict{}, false
}
