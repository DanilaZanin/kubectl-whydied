// Package classify turns a collect.Snapshot into a Report: verdicts with
// evidence and confidence labels. It never talks to the API.
package classify

import (
	"time"

	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

// Confidence labels. See the README for their exact meaning.
type Confidence string

const (
	// Confirmed means a concrete API fact exists and is quoted verbatim.
	// It never means "proven causal chain".
	Confirmed Confidence = "confirmed"
	// Likely means a documented mechanism explains the facts, but a
	// competing explanation is possible and is named.
	Likely Confidence = "likely"
	// NoData means the API does not carry what would be needed.
	NoData Confidence = "no data"
)

// Verdict kinds. They are stable identifiers used by JSON consumers and tests.
const (
	KindOOMKill            = "oom-kill-reported"
	KindStatusUnknown      = "status-unknown-synthesized"
	KindAppExit            = "app-exit"
	KindExitSignal         = "exit-signal-convention"
	KindStartError         = "container-start-error"
	KindLivenessKill       = "liveness-probe-kill"
	KindStartupKill        = "startup-probe-kill"
	KindPostStartKill      = "poststart-hook-kill"
	KindPostStartFailed    = "poststart-hook-failed"
	KindImagePull          = "image-pull-failure"
	KindNoTermination      = "no-termination"
	KindPreemptScheduler   = "preemption-scheduler"
	KindPreemptKubelet     = "preemption-kubelet-admission"
	KindTaintEviction      = "taint-eviction"
	KindTaintCancelled     = "taint-eviction-cancelled"
	KindEvictionAPI        = "eviction-api"
	KindEvictionNodePress  = "eviction-node-pressure"
	KindEvictionStorage    = "eviction-storage-limit"
	KindKubeletTermination = "kubelet-termination"
	KindPodGC              = "pod-gc"
	KindControllerDelete   = "controller-delete"
	KindScaleRollout       = "scale-reason-rollout"
	KindScaleHPA           = "scale-reason-hpa"
	KindDeletionUnattrib   = "deletion-unattributed"
	KindPodGone            = "pod-gone"
	KindNodeNotReady       = "node-not-ready"
	KindSandboxChanged     = "sandbox-changed"
	KindKilledAfterGrace   = "killed-after-grace"
	KindPodStatusReason    = "pod-status-reason"
	KindNodeOOMCandidate   = "node-oom-candidate"
)

// Evidence kinds.
const (
	EvPodStatus     = "pod-status"
	EvPodSpec       = "pod-spec"
	EvPodCondition  = "pod-condition"
	EvEvent         = "event"
	EvOwner         = "owner"
	EvNodeCondition = "node-condition"
	EvNodeMeta      = "node-meta"
	EvConvention    = "convention"
	EvLog           = "log"
)

// Evidence is one verbatim fact with its source object and time.
type Evidence struct {
	Kind      string     `json:"kind"`
	Object    string     `json:"object"`
	UID       string     `json:"uid,omitempty"`
	Field     string     `json:"field"`
	Value     string     `json:"value,omitempty"`
	Time      *time.Time `json:"time,omitempty"`
	FirstTime *time.Time `json:"firstTime,omitempty"`
	Count     int32      `json:"count,omitempty"`
	Note      string     `json:"note,omitempty"`
}

// Verdict is one explanation with its confidence, evidence and rivals.
type Verdict struct {
	Kind       string     `json:"kind"`
	Confidence Confidence `json:"confidence"`
	Summary    string     `json:"summary"`
	Competing  []string   `json:"competing,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

// Termination is the instance being explained, as the API reports it.
type Termination struct {
	Source      string     `json:"source"` // state.terminated or lastState.terminated
	ContainerID string     `json:"containerID,omitempty"`
	ExitCode    int32      `json:"exitCode"`
	Signal      int32      `json:"signal,omitempty"` // only when the API set it
	Reason      string     `json:"reason,omitempty"`
	Message     string     `json:"message,omitempty"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
}

// Expected values.
const (
	ExpectedYes     = "expected"
	ExpectedNo      = "unexpected"
	ExpectedUnknown = "unknown"
)

// Expectedness says whether the stop is normal for this container role.
type Expectedness struct {
	State string `json:"state"`
	Why   string `json:"why"`
}

// RestartDecision says what the kubelet does (or did) next.
type RestartDecision struct {
	Policy   string `json:"policy"`
	Decision string `json:"decision"` // restarting | back-off | not-restarting | running | unknown
	Detail   string `json:"detail"`

	Evidence []Evidence `json:"evidence,omitempty"`
}

// ContainerReport is the full explanation for one container.
type ContainerReport struct {
	Name         string `json:"name"`
	Role         string `json:"role"` // init | sidecar | regular | ephemeral
	Image        string `json:"image,omitempty"`
	RestartCount int32  `json:"restartCount"`
	CurrentState string `json:"currentState"`

	Termination  *Termination    `json:"termination,omitempty"`
	Previous     *Termination    `json:"previousTermination,omitempty"` // real lastState when state.terminated is synthesized
	Expected     *Expectedness   `json:"expected,omitempty"`
	Restart      RestartDecision `json:"restart"`
	Verdicts     []Verdict       `json:"verdicts"`
	LogTail      []string        `json:"logTail,omitempty"`
	LogsPrevious bool            `json:"logsPrevious,omitempty"`
	LogNote      string          `json:"logNote,omitempty"`
}

// PodInfo is the pod identity block.
type PodInfo struct {
	Namespace         string     `json:"namespace"`
	Name              string     `json:"name"`
	UID               string     `json:"uid,omitempty"`
	Exists            bool       `json:"exists"`
	Phase             string     `json:"phase,omitempty"`
	Reason            string     `json:"reason,omitempty"`
	Message           string     `json:"message,omitempty"`
	Node              string     `json:"node,omitempty"`
	StartTime         *time.Time `json:"startTime,omitempty"`
	DeletionTimestamp *time.Time `json:"deletionTimestamp,omitempty"`
	RestartPolicy     string     `json:"restartPolicy,omitempty"`
}

// OwnerInfo is one link of the owner chain.
type OwnerInfo struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	UID   string `json:"uid"`
	Found bool   `json:"found"`
}

// Report is the complete result for one pod.
type Report struct {
	ObservedAt time.Time         `json:"observedAt"`
	Window     string            `json:"window"`
	Pod        PodInfo           `json:"pod"`
	Owners     []OwnerInfo       `json:"owners,omitempty"`
	Verdicts   []Verdict         `json:"verdicts"`
	Containers []ContainerReport `json:"containers"`
	Context    []Evidence        `json:"context,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
	Checked    []string          `json:"checked"`
	Gaps       []collect.Gap     `json:"gaps,omitempty"`
}

// AllVerdicts returns pod-level verdicts followed by container verdicts.
func (r *Report) AllVerdicts() []Verdict {
	out := append([]Verdict(nil), r.Verdicts...)
	for i := range r.Containers {
		out = append(out, r.Containers[i].Verdicts...)
	}
	return out
}

// HasData reports whether anything other than "no data" was found.
func (r *Report) HasData() bool {
	for _, v := range r.AllVerdicts() {
		if v.Confidence != NoData {
			return true
		}
		if len(v.Evidence) > 0 {
			return true
		}
	}
	return false
}

// Headline returns the most specific verdict for one-line output.
func (r *Report) Headline() (container string, v Verdict, ok bool) {
	if len(r.Verdicts) > 0 {
		return "", r.Verdicts[0], true
	}
	for i := range r.Containers {
		c := &r.Containers[i]
		if c.Termination != nil && len(c.Verdicts) > 0 {
			return c.Name, c.Verdicts[0], true
		}
	}
	for i := range r.Containers {
		if len(r.Containers[i].Verdicts) > 0 {
			return r.Containers[i].Name, r.Containers[i].Verdicts[0], true
		}
	}
	return "", Verdict{}, false
}
