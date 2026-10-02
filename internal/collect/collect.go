package collect

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	maxLogBytes     = 64 * 1024
	maxOwnerDepth   = 4
	revisionAnnoKey = "deployment.kubernetes.io/revision"
)

// Options controls one collection run.
type Options struct {
	Namespace    string
	Pod          string
	Container    string // restrict logs to this container ("" = all)
	PreviousLogs int    // tail lines of the explained instance's logs (0 = off)
	Now          func() time.Time
}

// Collect gathers the Snapshot for one pod. A missing pod is not an error: the
// Snapshot then carries Pod == nil and whatever events still reference the name.
// Forbidden and similar read errors become Gaps.
func Collect(ctx context.Context, cs kubernetes.Interface, o Options) (*Snapshot, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	s := &Snapshot{Version: SnapshotVersion, CollectedAt: now().UTC(), Namespace: o.Namespace, Name: o.Pod}

	pod, err := cs.CoreV1().Pods(o.Namespace).Get(ctx, o.Pod, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		s.Gaps = append(s.Gaps, Gap{"pod/" + o.Pod, "not found: the pod no longer exists in the API; its status history is not available"})
	case err != nil:
		return nil, fmt.Errorf("get pod %s/%s: %w", o.Namespace, o.Pod, err)
	default:
		stripPod(pod)
		s.Pod = pod
	}

	// Events that reference this pod name (any UID; the classifier matches by UID).
	s.addEvents(ctx, cs, o.Namespace, "involvedObject.kind=Pod,involvedObject.name="+o.Pod, "events for pod name")

	if s.Pod != nil {
		s.collectOwners(ctx, cs)
		s.collectNode(ctx, cs)
		if o.PreviousLogs > 0 {
			s.collectLogs(ctx, cs, o)
		}
	}
	return s, nil
}

func stripPod(p *corev1.Pod) {
	p.ManagedFields = nil
}

func (s *Snapshot) gap(source string, err error) {
	reason := err.Error()
	switch {
	case apierrors.IsForbidden(err):
		reason = "forbidden by RBAC: " + reason
	case apierrors.IsNotFound(err):
		reason = "not found: " + reason
	}
	s.Gaps = append(s.Gaps, Gap{Source: source, Reason: reason})
}

func (s *Snapshot) addEvents(ctx context.Context, cs kubernetes.Interface, ns, fieldSelector, source string) {
	l, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{FieldSelector: fieldSelector})
	if err != nil {
		s.gap(source, err)
		return
	}
	for i := range l.Items {
		e := l.Items[i]
		e.ManagedFields = nil
		s.Events = append(s.Events, e)
	}
}

func (s *Snapshot) collectOwners(ctx context.Context, cs kubernetes.Interface) {
	ns := s.Namespace
	meta := s.Pod.ObjectMeta
	for depth := 0; depth < maxOwnerDepth; depth++ {
		ref := controllerRef(meta.OwnerReferences)
		if ref == nil {
			return
		}
		o := Owner{Kind: ref.Kind, APIVersion: ref.APIVersion, Name: ref.Name, UID: ref.UID}
		var next metav1.ObjectMeta
		var err error
		switch ref.Kind {
		case "ReplicaSet":
			obj, e := cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
			err = e
			if e == nil {
				next, o.Replicas = obj.ObjectMeta, obj.Spec.Replicas
			}
		case "Deployment":
			obj, e := cs.AppsV1().Deployments(ns).Get(ctx, ref.Name, metav1.GetOptions{})
			err = e
			if e == nil {
				next, o.Replicas = obj.ObjectMeta, obj.Spec.Replicas
			}
		case "StatefulSet":
			obj, e := cs.AppsV1().StatefulSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
			err = e
			if e == nil {
				next, o.Replicas = obj.ObjectMeta, obj.Spec.Replicas
			}
		case "DaemonSet":
			obj, e := cs.AppsV1().DaemonSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
			err = e
			if e == nil {
				next = obj.ObjectMeta
			}
		case "Job":
			obj, e := cs.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
			err = e
			if e == nil {
				next = obj.ObjectMeta
			}
		case "CronJob":
			obj, e := cs.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
			err = e
			if e == nil {
				next = obj.ObjectMeta
			}
		default:
			err = fmt.Errorf("owner kind %s is not read by this version", ref.Kind)
		}
		if err != nil {
			s.gap(fmt.Sprintf("owner %s/%s", ref.Kind, ref.Name), err)
			s.Owners = append(s.Owners, o)
			// The owner object may be gone, but events by UID can still exist.
			s.addEvents(ctx, cs, ns, "involvedObject.uid="+string(ref.UID), "events for "+ref.Kind+"/"+ref.Name)
			return
		}
		o.Found = true
		o.Revision = next.Annotations[revisionAnnoKey]
		o.Deleting = next.DeletionTimestamp
		s.Owners = append(s.Owners, o)
		s.addEvents(ctx, cs, ns, "involvedObject.uid="+string(ref.UID), "events for "+ref.Kind+"/"+ref.Name)
		if ref.Kind == "Deployment" {
			s.collectHPAs(ctx, cs, ref.Name)
		}
		meta = next
	}
}

func controllerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}

func (s *Snapshot) collectHPAs(ctx context.Context, cs kubernetes.Interface, deployment string) {
	l, err := cs.AutoscalingV2().HorizontalPodAutoscalers(s.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		s.gap("horizontalpodautoscalers", err)
		return
	}
	for i := range l.Items {
		h := &l.Items[i]
		if h.Spec.ScaleTargetRef.Kind == "Deployment" && h.Spec.ScaleTargetRef.Name == deployment {
			s.HPAs = append(s.HPAs, HPA{Name: h.Name, UID: h.UID, TargetKind: "Deployment", TargetName: deployment})
			s.addEvents(ctx, cs, s.Namespace, "involvedObject.uid="+string(h.UID), "events for hpa/"+h.Name)
		}
	}
}

func (s *Snapshot) collectNode(ctx context.Context, cs kubernetes.Interface) {
	name := s.Pod.Spec.NodeName
	if name == "" {
		return
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		s.gap("node/"+name, err)
	} else {
		n.ManagedFields = nil
		n.Status.Images = nil
		n.Status.VolumesInUse = nil
		n.Status.VolumesAttached = nil
		s.Node = n
	}
	// Kubelet node events use the node name as involvedObject.uid, other
	// controllers use the real UID, so select by kind and name.
	s.addEvents(ctx, cs, metav1.NamespaceAll, "involvedObject.kind=Node,involvedObject.name="+name, "events for node/"+name)
}

func (s *Snapshot) collectLogs(ctx context.Context, cs kubernetes.Interface, o Options) {
	s.Logs = map[string]Logs{}
	before := map[string]string{}
	for _, r := range AllStatuses(s.Pod) {
		before[r.Status.Name] = r.Status.ContainerID + "/" + fmt.Sprint(r.Status.RestartCount)
	}
	for _, r := range AllStatuses(s.Pod) {
		cs0 := r.Status
		if o.Container != "" && cs0.Name != o.Container {
			continue
		}
		term, fromLast := LastTermination(cs0)
		if term == nil {
			continue
		}
		tail := int64(o.PreviousLogs)
		req := cs.CoreV1().Pods(s.Namespace).GetLogs(s.Name, &corev1.PodLogOptions{Container: cs0.Name, Previous: fromLast, TailLines: &tail})
		rc, err := req.Stream(ctx)
		if err != nil {
			s.gap("logs/"+cs0.Name, err)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxLogBytes))
		_ = rc.Close()
		if err != nil {
			s.gap("logs/"+cs0.Name, err)
			continue
		}
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		s.Logs[cs0.Name] = Logs{Previous: fromLast, ContainerID: term.ContainerID, Lines: lines}
	}
	// Re-read the pod: if an instance changed while logs were being read, the
	// log tail may belong to a different instance than the one explained.
	p2, err := cs.CoreV1().Pods(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if err != nil {
		s.gap("logs recheck", err)
		return
	}
	for _, r := range AllStatuses(p2) {
		if b, ok := before[r.Status.Name]; ok && b != r.Status.ContainerID+"/"+fmt.Sprint(r.Status.RestartCount) {
			s.Gaps = append(s.Gaps, Gap{"logs/" + r.Status.Name,
				"the container instance changed while logs were read (containerID or restartCount differ); the log tail may belong to another instance"})
		}
	}
}

// RestartedPods lists pods that currently show a restart or a previous
// termination and whose last termination finished within since (or has no
// finish time). It only sees pods that still exist in the API.
func RestartedPods(ctx context.Context, cs kubernetes.Interface, namespace string, since time.Duration, now time.Time) ([]corev1.Pod, error) {
	l, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []corev1.Pod
	for i := range l.Items {
		p := l.Items[i]
		if podRestartedSince(&p, since, now) {
			out = append(out, p)
		}
	}
	return out, nil
}

func podRestartedSince(p *corev1.Pod, since time.Duration, now time.Time) bool {
	for _, r := range AllStatuses(p) {
		cs := r.Status
		if cs.RestartCount == 0 && cs.LastTerminationState.Terminated == nil {
			continue
		}
		t, _ := LastTermination(cs)
		if t == nil || t.FinishedAt.IsZero() {
			return true
		}
		if now.Sub(t.FinishedAt.Time) <= since {
			return true
		}
	}
	return false
}
