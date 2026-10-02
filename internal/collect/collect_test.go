package collect

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func ptr[T any](v T) *T { return &v }

func fixtureObjects() []runtime.Object {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "ns", UID: "pod-uid",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-abc", UID: "rs-uid", Controller: ptr(true)}}},
		Spec: corev1.PodSpec{NodeName: "n1"},
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-abc", Namespace: "ns", UID: "rs-uid",
		Annotations:     map[string]string{revisionAnnoKey: "1"},
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "web", UID: "dep-uid", Controller: ptr(true)}}}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns", UID: "dep-uid", Annotations: map[string]string{revisionAnnoKey: "2"}}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", UID: "node-uid"}, Status: corev1.NodeStatus{Images: []corev1.ContainerImage{{Names: []string{"big"}}}}}
	ev := &corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "ns"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1", UID: "pod-uid"}, Reason: "Killing"}
	return []runtime.Object{pod, rs, dep, node, ev}
}

func TestCollectOwnerChainNodeAndEvents(t *testing.T) {
	cs := fake.NewClientset(fixtureObjects()...)
	s, err := Collect(context.Background(), cs, Options{Namespace: "ns", Pod: "web-1", Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Pod == nil || len(s.Owners) != 2 || s.Owners[0].Kind != "ReplicaSet" || s.Owners[1].Kind != "Deployment" {
		t.Fatalf("owner chain: %+v", s.Owners)
	}
	if s.Owners[0].Revision != "1" || s.Owners[1].Revision != "2" {
		t.Errorf("revisions not captured: %+v", s.Owners)
	}
	if s.Node == nil || len(s.Node.Status.Images) != 0 {
		t.Errorf("node must be collected without the image list: %+v", s.Node)
	}
	if len(s.Events) == 0 {
		t.Error("pod event not collected")
	}
}

func TestCollectPodGone(t *testing.T) {
	cs := fake.NewClientset()
	s, err := Collect(context.Background(), cs, Options{Namespace: "ns", Pod: "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Pod != nil || len(s.Gaps) == 0 {
		t.Fatalf("a missing pod is a gap, not an error: %+v", s)
	}
}

func TestForbiddenBecomesGap(t *testing.T) {
	cs := fake.NewClientset(fixtureObjects()...)
	cs.PrependReactor("list", "events", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "events"}, "", nil)
	})
	cs.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "n1", nil)
	})
	s, err := Collect(context.Background(), cs, Options{Namespace: "ns", Pod: "web-1"})
	if err != nil {
		t.Fatalf("RBAC denial must not abort: %v", err)
	}
	var events, node bool
	for _, g := range s.Gaps {
		if g.Source == "events for pod name" {
			events = true
		}
		if g.Source == "node/n1" {
			node = true
		}
	}
	if !events || !node || s.Node != nil || len(s.Events) != 0 {
		t.Fatalf("gaps = %+v", s.Gaps)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	cs := fake.NewClientset(fixtureObjects()...)
	s, _ := Collect(context.Background(), cs, Options{Namespace: "ns", Pod: "web-1"})
	f := filepath.Join(t.TempDir(), "s.json")
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	got, err := Load(f)
	if err != nil || got.Pod == nil || got.Pod.UID != "pod-uid" || len(got.Owners) != 2 {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestRestartedPods(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	mk := func(name string, restarts int32, finished time.Duration, last bool) *corev1.Pod {
		st := corev1.ContainerStatus{Name: "c", RestartCount: restarts}
		if last {
			st.LastTerminationState.Terminated = &corev1.ContainerStateTerminated{FinishedAt: metav1.NewTime(now.Add(-finished))}
		}
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{st}}}
	}
	cs := fake.NewClientset(mk("recent", 2, 5*time.Minute, true), mk("old", 2, 5*time.Hour, true), mk("never", 0, 0, false))
	got, err := RestartedPods(context.Background(), cs, "", time.Hour, now)
	if err != nil || len(got) != 1 || got[0].Name != "recent" {
		t.Fatalf("%v %+v", err, got)
	}
}

// Item 12: an owner that was recreated under the same name is not part of the pod's chain.
func TestRecreatedOwnerIsNotUsed(t *testing.T) {
	objs := fixtureObjects()
	for _, o := range objs {
		if rs, ok := o.(*appsv1.ReplicaSet); ok {
			rs.UID = "new-rs-uid" // the pod's ownerReference still says rs-uid
		}
	}
	s, err := Collect(context.Background(), fake.NewClientset(objs...), Options{Namespace: "ns", Pod: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Owners) != 1 || s.Owners[0].Found || s.Owners[0].Revision != "" || string(s.Owners[0].UID) != "rs-uid" {
		t.Fatalf("the recreated ReplicaSet's data must not be used: %+v", s.Owners)
	}
	found := false
	for _, g := range s.Gaps {
		found = found || (g.Source == "owner ReplicaSet/web-abc" && len(g.Reason) > 0)
	}
	if !found {
		t.Fatalf("recreation must be reported as a gap: %+v", s.Gaps)
	}
}

func podWithLast(id string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "ns", UID: "pod-uid"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app",
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, ContainerID: id}}}}}}
}

// Item 13: logs carry the pod UID, the selected source and containerID; a change
// during collection becomes a gap.
func TestLogsInstanceBinding(t *testing.T) {
	cs := fake.NewClientset(podWithLast("containerd://a"))
	s, _ := Collect(context.Background(), cs, Options{Namespace: "ns", Pod: "web-1", PreviousLogs: 5})
	l, ok := s.Logs["app"]
	if !ok || l.PodUID != "pod-uid" || l.ContainerID != "containerd://a" || l.Source != "lastState.terminated" || !l.Previous {
		t.Fatalf("%+v", s.Logs)
	}
	for _, g := range s.Gaps {
		if g.Source == "logs/app" || g.Source == "logs" {
			t.Fatalf("no change, no gap: %+v", g)
		}
	}

	cs2 := fake.NewClientset(podWithLast("containerd://a"))
	gets := 0
	cs2.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets++
		if gets >= 2 { // the recheck after the logs were read
			return true, podWithLast("containerd://b"), nil
		}
		return false, nil, nil
	})
	s2, _ := Collect(context.Background(), cs2, Options{Namespace: "ns", Pod: "web-1", PreviousLogs: 5})
	changed := false
	for _, g := range s2.Gaps {
		changed = changed || g.Source == "logs/app"
	}
	if !changed {
		t.Fatalf("a containerID change during collection must be a gap: %+v", s2.Gaps)
	}
}
