# kubectl-whydied

Explain why a Kubernetes container or pod died or restarted. Every claim carries its evidence
(source object, UID, field or event, timestamp) and a confidence label. No LLM, no guessing.

```
Pod wd-oom/oom
  uid=155643d3-b901-4f5c-948d-852ea48c4ef9 node=wd-1370-3307-worker phase=Running restartPolicy=Always
  observed at 2026-10-02T22:12:53Z; correlation window 5m0s

Summary
  [confirmed] app: oom-kill-reported: the runtime reported an OOM kill for this container instance (API reported exitCode=137, reason=OOMKilled)

Container app (regular)
  state: terminated (exitCode=137, reason=OOMKilled); restartCount=2 (as reported now; may have been reset)
  explained instance: state.terminated, containerID=containerd://51a3ee50f5f496c99082d5b5bdd4aa479a716cf6e7be3c48eb3e23070c9011ea
  API reported exitCode=137 reason=OOMKilled
  started 2026-10-02T22:12:45Z, finished 2026-10-02T22:12:45Z
  stop expected for this role: unexpected: the container stopped with a non-zero exit code while its pod was not being terminated
  restart: policy=Always decision=back-off: restart policy Always restarts this container (with back-off after repeated failures); a recent BackOff event was recorded after this stop, so the next start is delayed (exponential back-off, documented cap 5 minutes); the API does not report the remaining delay
    - [event] Pod wd-oom/oom event BackOff = "Back-off restarting failed container app in pod oom_wd-oom(155643d3-b901-4f5c-948d-852ea48c4ef9)" @ 2026-10-02T22:12:45Z (uid 155643d3-b901-4f5c-948d-852ea48c4ef9) [fieldPath=spec.containers{app}; event repeated 2 times (aggregated; first 2026-10-02T22:12:35Z, last 2026-10-02T22:12:45Z)]
  [confirmed] oom-kill-reported: the runtime reported an OOM kill for this container instance (API reported exitCode=137, reason=OOMKilled)
    caveat: OOM level is unknown: the same reason is reported for a container cgroup limit, a pod-level cgroup limit and node-wide memory exhaustion
    caveat: memory usage at kill time is not available from the API
    - [pod-status] Pod wd-oom/oom status.containerStatuses[app].state.terminated.exitCode = 137 @ 2026-10-02T22:12:45Z (uid 155643d3-b901-4f5c-948d-852ea48c4ef9)
    - [pod-status] Pod wd-oom/oom status.containerStatuses[app].state.terminated.reason = OOMKilled @ 2026-10-02T22:12:45Z (uid 155643d3-b901-4f5c-948d-852ea48c4ef9)
    - [pod-spec] Pod wd-oom/oom spec.containers[app].resources.limits.memory = "spec memory limit 32Mi" (uid 155643d3-b901-4f5c-948d-852ea48c4ef9)
  logs of this instance (last 1 lines; the logs API returns no container ID: these lines are associated with the explained instance by position (previous or current container) and are an assumption):
    | allocating

Checked
  - pod status and spec
  - events by involvedObject.uid for the pod (5 found)
  - owner chain (pod has no controller)
  - node conditions, taints, labels and node events (current state only)
  - previous container logs
```

Real output of `kubectl whydied --from-snapshot internal/classify/testdata/oom.v1.37.0.snapshot.json -c app --window 5m --no-color`. The snapshot is in this repository: it was captured from the `oom` e2e scenario on kind v1.37.0 (a container with a 32Mi limit that allocates until it is killed). Nothing was edited.

## Why

Kubernetes tells you an exit code, a one-word reason, and events that expire after an hour. People grep
events, read `kubectl describe`, and guess. The pain is old and well documented:

- [kubernetes/kubernetes#81723](https://github.com/kubernetes/kubernetes/issues/81723): no clear reason why a pod was killed or restarted
- [Stack Overflow 48932943](https://stackoverflow.com/questions/48932943): tracking OOMKilled
- [r/sre discussion](https://www.reddit.com/r/sre/comments/1s9fo21/)
- [CNCF blog: tracking container restarts and termination events](https://www.cncf.io/blog/2022/08/23/tracking-container-restarts-and-termination-events-in-kubernetes/)

`kubectl-whydied` is deliberately narrow. It reads the pod, its events, its owner chain and its node, and
says what the API can prove. When the API cannot say, it says `no data` and names what is missing.

## Install

```sh
# Go
go install github.com/DanilaZanin/kubectl-whydied/cmd/kubectl-whydied@latest

# Release binary: download the archive for your platform from the GitHub releases page,
# unpack it, and put kubectl-whydied on your PATH. kubectl finds it as `kubectl whydied`.

# Krew: plugins/whydied.yaml is a template with sha256 placeholders. The release workflow
# fills it from the release checksums (scripts/krew-manifest.sh) and attaches whydied.yaml
# to the GitHub release. It is not in the krew index yet; install from the attached file.
```

## Usage

```sh
kubectl whydied POD                       # explain every container of a pod
kubectl whydied POD -n prod -c app        # one container
kubectl whydied POD --previous-logs 20    # add the last 20 log lines of the explained instance
kubectl whydied -A --restarted-since 30m  # one line per recently restarted pod; -o json gives {candidates, reports, failures}
kubectl whydied POD -o json               # machine-readable report
kubectl whydied POD --window 5m           # correlation window between a termination and events (default 2m)
kubectl whydied POD --dump-snapshot s.json   # save everything that was read (for bug reports)
kubectl whydied --from-snapshot s.json       # explain from a saved snapshot, offline
```

Exit codes: `0` a diagnosis was printed, `1` error, `2` no data at all (for example the pod is gone and no
events reference it). Color is used only on a TTY (`NO_COLOR` and `--no-color` turn it off).

Permissions. Required: `get` on pods in the target namespace (a denial ends the command with exit 1);
`list` on pods for `-A` and `--restarted-since` (if every candidate pod fails, the command exits 1 and
prints each failure; an empty selection is reported as such and exits 0).
Optional sources, each reported under **Gaps** when it cannot be read and never treated as evidence:
`list` on events in the pod's namespace, `get` on the pod's node, cluster-wide `list` on events (node events
such as `SystemOOM`), `get` on ReplicaSets, Deployments, StatefulSets, DaemonSets, Jobs and CronJobs,
`list` on HorizontalPodAutoscalers, and `get pods/log` for `--previous-logs`.

## What the labels mean

| Label | Meaning |
| --- | --- |
| `confirmed` | A concrete API fact exists and is quoted verbatim, with object UID, field or event, and time. It is never a causal chain. |
| `likely` | A documented mechanism explains the facts, but a competing explanation is possible. The competing explanation is named in the output. |
| `no data` | The API does not carry what would be needed (events expired, no audit log, RBAC denied, pod gone). The output says what is missing. |

## Cause, how it is proven, confidence

| Cause | How it is proven | Confidence |
| --- | --- | --- |
| OOM kill reported by the runtime | `terminated.reason == OOMKilled` on the explained instance | `confirmed`. The OOM level (container limit, pod cgroup, node) is stated as unknown |
| Application exit, code 0 to 128 | `terminated.exitCode` of the explained instance (`state.terminated`, else `lastState.terminated`) | `confirmed` |
| Exit code 129 to 192 | `128+n` signal convention for Linux signals 1 to 64, labelled as convention; `exit(N)` by the application looks identical. Codes above 192 are reported as plain exit codes | `likely`, competing explanation named |
| Kubelet could not observe the exit | `terminated.reason == ContainerStatusUnknown` (the 137 is synthesized) | `confirmed` fact, cause `no data` |
| Container could not start | `StartError`, `ContainerCannotRun`, `CreateContainerError` reason and message, quoted verbatim | `confirmed` |
| Liveness or startup probe kill | `Killing` event whose message names the probe, with `fieldPath` of this container, and whose time lies within the instance's lifetime (its start to its finish); events from another instance are ignored | `confirmed`, otherwise no verdict |
| postStart hook failed | `FailedPostStartHook` event for this container within the instance's lifetime | `confirmed`; events of another instance are ignored |
| Kill caused by the failed hook | `Killing` event with message `FailedPostStartHook`; recorded before the kill is attempted | `likely`; `confirmed` only when this instance ended inside the window |
| Image cannot be pulled | waiting reason `ErrImagePull`, `ImagePullBackOff`, `InvalidImageName`, with the runtime message | `confirmed` |
| Scheduler preemption initiated | `DisruptionTarget` condition `PreemptionByScheduler` (or a `Preempted` event). The outcome (deleting, terminal phase, or not deleted) is stated as a separate fact | `confirmed` as initiated |
| Kubelet admission preemption | `status.reason == Preempting` | `confirmed` |
| Taint eviction initiated | `DisruptionTarget` reason `DeletionByTaintManager`; a later `Cancelling deletion` event is reported as not a death. Taint manager events carry no pod UID, so they are context only | `confirmed` as initiated |
| Eviction API (kubectl drain) initiated | `DisruptionTarget` reason `EvictionByEvictionAPI`; the caller is not recorded | `confirmed` as initiated |
| Node-pressure eviction | `status.reason == Evicted` with `The node was low on resource` message; node pressure conditions shown as current state | `confirmed` |
| Local storage limit eviction | `Evicted` with an emptyDir or ephemeral-storage limit message; no DiskPressure needed | `confirmed` |
| Pod garbage collection initiated | `DisruptionTarget` reason `DeletionByPodGC` | `confirmed` as initiated |
| Controller deleted the pod | `SuccessfulDelete` event on an owner (ReplicaSet, StatefulSet, Job) that names the pod and is not older than the pod | `confirmed` |
| Why the controller scaled down: rollout | pod's ReplicaSet revision is lower than the Deployment revision | `likely` |
| Why the controller scaled down: HPA | `SuccessfulRescale` event of an HPA that targets the Deployment, inside the window | `likely` |
| Direct delete | `deletionTimestamp` set and no other attribution; deleter is not in the API | `likely`, deleter unknown |
| Killed after the grace period | exit 137 at or after the grace period of the trigger: `deletionGracePeriodSeconds` (when still non-zero) for deletions, the probe's own or the pod's `terminationGracePeriodSeconds` for probe kills; unknown grace gives no verdict | `likely`, OOM, external SIGKILL and `exit(137)` named as competing |
| Node not ready | node `Ready` condition not `True` (current state only) | `confirmed` as node state; says nothing about the container |
| Sandbox changed | `SandboxChanged` event | `confirmed` as a restart trigger |
| Node OOM candidate | `SystemOOM` node event inside the window; it names a process, not a pod | `likely` candidate only |
| Pod no longer exists | 404 on the pod; events that still reference the name are listed | `no data` |
| Anything else | nothing in the API matches | `no data`, with the list of what was checked |

## Limits

- **Events expire.** The API server keeps events for about an hour by default. After that, causes that only an event can prove become `no data`.
- **No audit log.** Who deleted a pod, who called the Eviction API, who scaled a Deployment is not in the pod or its events. A direct delete is reported as `likely`, deleter unknown.
- **Current state only.** Pod status and node conditions have no history. `restartCount` is shown as reported now and can have been reset. `--restarted-since` sees only pods that still exist in the API.
- **Exit codes are not intent.** The tool prints `API reported exitCode=N`. Decoding `128+n` as a signal is labelled as convention. An application that calls `exit(137)` looks exactly like a SIGKILL, and the output says so. The `signal` field is shown only when the API set it.
- **OOM level is unknown.** `OOMKilled` is confirmed as "the runtime reported an OOM kill". Whether it was the container limit, a pod cgroup or node-wide pressure is not in the API. The tool never tells you to raise a limit as a fact.
- **Node OOM and cloud paths are not classified in v0.1.** A `SystemOOM` node event is shown as a candidate only, because it names a process, not a pod. GKE preemptible and spot nodes, Karpenter, cluster-autoscaler and spot termination handlers are shown as context lines from node labels, taints and annotations, with no verdict drawn from them.
- **Probe failures.** A probe kill is confirmed only when a `Killing` event names the probe and the container. The reason of each individual probe failure is shown as context. Event `count` is shown as "event repeated N times", never as consecutive failures.
- **Grace period.** "Killed after the grace period" is never computed from guesses. It appears as `likely` only when the grace of the trigger is known: the non-zero `deletionGracePeriodSeconds` for a deletion, or the probe's own (else the pod's) `terminationGracePeriodSeconds` for a probe kill. Once the kubelet has zeroed `deletionGracePeriodSeconds`, the grace used is unknown and no verdict is drawn. Competing explanations are listed.
- **kind cannot reproduce everything.** See the table below.

## Verification

Verdicts are not mocked. `test/e2e` creates a pinned kind cluster, applies a real failure scenario from
`test/e2e/scenarios/<name>/`, waits until the failure is observable, runs the binary with `-o json`, and
checks the confidence label, the verdict kind, the evidence kinds and that every evidence line references the
pod, an owner or the node by UID. The same scenarios run on two node images (v1.31.12 and v1.37.0).
Pod, event and node JSON captured from those runs are the golden fixtures of the classifier unit tests.

| Scenario | What happens | Verdict kind | Confidence | v1.31.12 | v1.37.0 |
| --- | --- | --- | --- | --- | --- |
| `crashloop-backoff` | waits for a real CrashLoopBackOff (4th restart) and requires the back-off decision | `app-exit` | `confirmed` | pass | pass |
| `drain` | kubectl drain evicts the pod through the Eviction API; the pod ignores SIGTERM so it stays visible while terminating | `eviction-api` | `confirmed` | pass | pass |
| `evict-storage` | the pod writes more than the emptyDir sizeLimit; the kubelet evicts it (no DiskPressure needed) | `eviction-storage-limit` | `confirmed` | pass | pass |
| `exit0` | restartPolicy Never, exit code 0: a normal completion | `app-exit` | `confirmed` | pass | pass |
| `exit1` | application exits with code 1 and the kubelet restarts it (CrashLoopBackOff) | `app-exit` | `confirmed` | pass | pass |
| `exit137-app` | NEGATIVE: the application itself calls exit(137); the API cannot tell that from SIGKILL, so no verdict may claim SIGKILL as confirmed | `exit-signal-convention` | `likely` | pass | pass |
| `exit2` | application exits with code 2 and the kubelet restarts it (CrashLoopBackOff) | `app-exit` | `confirmed` | pass | pass |
| `external-kill` | a privileged pod with hostPID sends kill -9 to the victim's process: SIGKILL without an OOM report. The API shows exit 137 only | `exit-signal-convention` | `likely` | pass | pass |
| `image-pull` | the image cannot be pulled: ErrImagePull / ImagePullBackOff, message quoted verbatim | `image-pull-failure` | `confirmed` | pass | pass |
| `init-fail` | an init container exits 3; the main container never starts | `app-exit` | `confirmed` | pass | pass |
| `liveness-kill` | liveness probe starts failing; the kubelet kills and restarts the container (Killing event names the probe) | `liveness-probe-kill` | `confirmed` | pass | pass |
| `name-reuse` | NEGATIVE: a pod name is reused by a new pod with a different UID; events and history of the first pod must not be attributed to the second | `no-termination` | `confirmed` | pass | pass |
| `oom` | container exceeds its memory limit; the runtime reports OOMKilled | `oom-kill-reported` | `confirmed` | pass | pass |
| `pod-gone` | the pod was deleted and no longer exists: no data about the cause, events that still reference the name are listed | `pod-gone` | `no data` | pass | pass |
| `poststart-fail` | the postStart hook fails; the kubelet records FailedPostStartHook and kills the container | `poststart-hook-failed` | `confirmed` | pass | pass |
| `preemption` | a high-priority pod does not fit; the scheduler preempts the low-priority pod (DisruptionTarget PreemptionByScheduler) | `preemption-scheduler` | `confirmed` | pass | pass |
| `rollout` | a Deployment rollout: the ReplicaSet deletes the old pod. Delete is confirmed from the SuccessfulDelete event; the rollout reason is likely, from revision numbers | `controller-delete` | `confirmed` | pass | pass |
| `scale-down` | manual kubectl scale: the ReplicaSet deletes a pod. The delete is confirmed; no rollout reason may be claimed | `controller-delete` | `confirmed` | pass | pass |
| `sidecar-stop` | a native sidecar (restartable init container) is stopped when the Job's main container completes; the stop is expected for its role | `exit-signal-convention` | `likely` | pass | pass |
| `sigsegv` | a child of the main process dies by SIGSEGV; the main process exits 139. Signal decoding is convention only | `exit-signal-convention` | `likely` | pass | pass |
| `sigterm` | a child of the main process dies by SIGTERM; the main process exits 143 | `exit-signal-convention` | `likely` | pass | pass |
| `startup-kill` | startup probe never succeeds; the kubelet kills the container (Killing event names the startup probe) | `startup-probe-kill` | `confirmed` | pass | pass |
| `taint-eviction` | a NoExecute taint is added to the node; the taint manager deletes the pod that does not tolerate it | `taint-eviction` | `confirmed` | pass | pass |
| `user-delete` | kubectl delete pod: the pod is terminating; the deleter is not recorded, so the verdict is likely and says so | `deletion-unattributed` | `likely` | pass | pass |

Described by documentation, not covered by e2e: node-level OOM kills, node-pressure eviction (memory,
disk, pid) on a real node, kubelet admission preemption of critical pods, node NotReady and node shutdown,
pod garbage collection, HPA-driven scale-down, `ContainerStatusUnknown`, `SandboxChanged`, and every
cloud or autoscaler path (GKE, EKS, Karpenter, cluster-autoscaler). kind nodes are containers, so an
external `kill -9` reproduces SIGKILL but not a real node OOM, and cloud interruption needs a real cloud.
These paths are covered by unit tests on hand-built objects only.

## Development

```sh
make build       # bin/kubectl-whydied
make vet lint
make test GOTESTFLAGS=-race
make e2e         # needs docker, kind and kubectl; NODE_IMAGE=kindest/node:v1.31.12 to pick a version
make snapshot    # goreleaser snapshot build
```

`WD_E2E_SCENARIOS='oom|exit1'` selects scenarios, `WD_E2E_FIXTURES=dir` stores the snapshots of passing runs,
`WD_E2E_KEEP=1` keeps the cluster. Cluster names start with `wd-`.

## License

MIT, see [LICENSE](LICENSE).
