// Package collect reads everything kubectl-whydied needs from the Kubernetes
// API and packs it into a serializable Snapshot. The classifier never talks to
// the API; it only reads a Snapshot, so every verdict can be replayed offline.
package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// SnapshotVersion is bumped when the Snapshot layout changes.
const SnapshotVersion = 1

// Gap records something that could not be read. Gaps are reported to the user
// and are never treated as evidence.
type Gap struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// Owner is one link in the controller owner chain of the pod.
type Owner struct {
	Kind       string       `json:"kind"`
	APIVersion string       `json:"apiVersion,omitempty"`
	Name       string       `json:"name"`
	UID        types.UID    `json:"uid"`
	Found      bool         `json:"found"`
	Revision   string       `json:"revision,omitempty"` // deployment.kubernetes.io/revision
	Replicas   *int32       `json:"replicas,omitempty"`
	Deleting   *metav1.Time `json:"deletionTimestamp,omitempty"`
}

// HPA is a HorizontalPodAutoscaler that targets one of the owners.
type HPA struct {
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	TargetKind string    `json:"targetKind"`
	TargetName string    `json:"targetName"`
}

// Logs holds an optional tail of container logs.
type Logs struct {
	Previous    bool     `json:"previous"`
	ContainerID string   `json:"containerID,omitempty"`
	Lines       []string `json:"lines,omitempty"`
}

// Snapshot is the complete input of the classifier.
type Snapshot struct {
	Version     int       `json:"version"`
	CollectedAt time.Time `json:"collectedAt"`
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`

	// Pod is nil when the pod no longer exists in the API.
	Pod    *corev1.Pod  `json:"pod,omitempty"`
	Owners []Owner      `json:"owners,omitempty"`
	HPAs   []HPA        `json:"hpas,omitempty"`
	Node   *corev1.Node `json:"node,omitempty"`

	// Events are all events gathered for the pod (by name), its owners, HPAs and node.
	// The classifier matches them by involvedObject.uid itself.
	Events []corev1.Event `json:"events,omitempty"`

	Logs map[string]Logs `json:"logs,omitempty"`
	Gaps []Gap           `json:"gaps,omitempty"`
}

// Load reads a Snapshot from a JSON file.
func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path) //nolint:gosec // user-supplied path is the point
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	return &s, nil
}

// Save writes the Snapshot as indented JSON.
func (s *Snapshot) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644) //nolint:gosec // fixtures are meant to be readable
}

// LastTermination returns the termination of the instance that should be
// explained: state.terminated when set (the instance that just ended), else
// lastState.terminated (the previous instance). fromLast is true for the latter.
func LastTermination(cs *corev1.ContainerStatus) (t *corev1.ContainerStateTerminated, fromLast bool) {
	if cs == nil {
		return nil, false
	}
	if cs.State.Terminated != nil {
		return cs.State.Terminated, false
	}
	if cs.LastTerminationState.Terminated != nil {
		return cs.LastTerminationState.Terminated, true
	}
	return nil, false
}

// AllStatuses returns pointers to all container statuses of the pod, with the
// container kind: "init", "regular" or "ephemeral".
func AllStatuses(p *corev1.Pod) []StatusRef {
	var out []StatusRef
	for i := range p.Status.InitContainerStatuses {
		out = append(out, StatusRef{Kind: "init", Status: &p.Status.InitContainerStatuses[i]})
	}
	for i := range p.Status.ContainerStatuses {
		out = append(out, StatusRef{Kind: "regular", Status: &p.Status.ContainerStatuses[i]})
	}
	for i := range p.Status.EphemeralContainerStatuses {
		out = append(out, StatusRef{Kind: "ephemeral", Status: &p.Status.EphemeralContainerStatuses[i]})
	}
	return out
}

// StatusRef pairs a container status with its kind.
type StatusRef struct {
	Kind   string
	Status *corev1.ContainerStatus
}
