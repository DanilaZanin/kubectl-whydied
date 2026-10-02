package e2e

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
)

// API is an independently fetched copy of the API state a report was built
// from (kubectl get -o json, not the tool's own collector). Validate checks
// every piece of evidence in a report against it, so an invented field, value,
// time, UID, containerID or container scope cannot pass.
type API struct {
	Pod    map[string]any
	Events []map[string]any
	Node   map[string]any
	Owners map[string]map[string]any // uid -> owner object (ReplicaSet, Deployment, Job, ...)
}

type pathStep struct {
	name string // identifier
	sel  string // optional [selector]
	has  bool
}

func parsePath(p string) []pathStep {
	var out []pathStep
	for i := 0; i < len(p); {
		j := i
		for j < len(p) && p[j] != '.' && p[j] != '[' {
			j++
		}
		st := pathStep{name: p[i:j]}
		if j < len(p) && p[j] == '[' {
			k := strings.IndexByte(p[j:], ']')
			if k < 0 {
				return nil
			}
			st.sel, st.has = p[j+1:j+k], true
			j += k + 1
		}
		out = append(out, st)
		if j < len(p) && p[j] == '.' {
			j++
		}
		i = j
	}
	return out
}

// resolve walks a field path such as status.containerStatuses[app].lastState.terminated.exitCode.
func resolve(obj map[string]any, path string) (any, bool) {
	steps := parsePath(path)
	if len(steps) == 0 {
		return nil, false
	}
	var cur any = obj
	for _, st := range steps {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[st.name]; !ok || cur == nil {
			return nil, false
		}
		if !st.has {
			continue
		}
		switch c := cur.(type) {
		case []any:
			var found any
			for _, it := range c {
				if im, ok := it.(map[string]any); ok && (im["name"] == st.sel || im["type"] == st.sel) {
					found = im
					break
				}
			}
			if found == nil {
				return nil, false
			}
			cur = found
		case map[string]any:
			if cur, ok = c[st.sel]; !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return cur, true
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func nested(m map[string]any, ks ...string) map[string]any {
	cur := m
	for _, k := range ks {
		n, ok := cur[k].(map[string]any)
		if !ok {
			return map[string]any{}
		}
		cur = n
	}
	return cur
}

func eventTime(e map[string]any) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, str(e, "lastTimestamp")); err == nil && !t.IsZero() {
		return t
	}
	if ser := nested(e, "series"); len(ser) > 0 {
		if t, err := time.Parse(time.RFC3339Nano, str(ser, "lastObservedTime")); err == nil {
			return t
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, str(e, "eventTime")); err == nil && !t.IsZero() {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, str(e, "firstTimestamp")); err == nil {
		return t
	}
	return time.Time{}
}

var containerSel = regexp.MustCompile(`^(?:status\.(?:initContainerStatuses|containerStatuses|ephemeralContainerStatuses)|spec\.(?:initContainers|containers|ephemeralContainers))\[([^\]]+)\]`)

// Validate returns the first piece of evidence that the API state does not back.
func Validate(rep *classify.Report, api *API) error {
	podMeta := nested(api.Pod, "metadata")
	podUID := str(podMeta, "uid")
	if rep.Pod.Exists {
		if rep.Pod.UID != podUID || rep.Pod.Name != str(podMeta, "name") || rep.Pod.Namespace != str(podMeta, "namespace") {
			return fmt.Errorf("report pod identity %s/%s uid=%s differs from the API (%s/%s uid=%s)", rep.Pod.Namespace, rep.Pod.Name, rep.Pod.UID, str(podMeta, "namespace"), str(podMeta, "name"), podUID)
		}
	}
	nodeUID, nodeName := str(nested(api.Node, "metadata"), "uid"), str(nested(api.Node, "metadata"), "name")

	check := func(where, container string, ev classify.Evidence) error {
		ctx := fmt.Sprintf("%s evidence %q (%s)", where, ev.Field, ev.Kind)
		switch ev.Kind {
		case classify.EvConvention, classify.EvLog:
			return nil
		case classify.EvPodStatus, classify.EvPodSpec, classify.EvPodCondition:
			if ev.UID != podUID {
				return fmt.Errorf("%s: uid %q is not the pod's %q", ctx, ev.UID, podUID)
			}
			got, ok := resolve(api.Pod, ev.Field)
			if !ok {
				return fmt.Errorf("%s: the field does not exist in the pod object", ctx)
			}
			if sv, isScalar := scalar(got); isScalar && ev.Value != "" && ev.Value != sv &&
				(!strings.HasSuffix(ev.Field, ".resources.limits.memory") || ev.Value != "spec memory limit "+sv) {
				return fmt.Errorf("%s: value %q differs from the API value %q", ctx, ev.Value, sv)
			}
			if err := checkTime(ctx, api.Pod, ev, got); err != nil {
				return err
			}
			if container != "" {
				if m := containerSel.FindStringSubmatch(ev.Field); m != nil && m[1] != container {
					return fmt.Errorf("%s: field belongs to container %q, not %q", ctx, m[1], container)
				}
			}
		case classify.EvOwner:
			if strings.HasPrefix(ev.Field, "metadata.ownerReferences") {
				if ev.UID != podUID {
					return fmt.Errorf("%s: uid %q is not the pod's", ctx, ev.UID)
				}
				if _, ok := resolve(api.Pod, ev.Field); !ok {
					return fmt.Errorf("%s: not present on the pod", ctx)
				}
				return nil
			}
			obj, ok := api.Owners[ev.UID]
			if !ok {
				return fmt.Errorf("%s: uid %q is not an owner object in the API", ctx, ev.UID)
			}
			got, ok := resolve(obj, ev.Field)
			if !ok {
				return fmt.Errorf("%s: the field does not exist on the owner object", ctx)
			}
			if sv, isScalar := scalar(got); isScalar && ev.Value != sv {
				return fmt.Errorf("%s: value %q differs from the API value %q", ctx, ev.Value, sv)
			}
		case classify.EvNodeCondition, classify.EvNodeMeta:
			if ev.UID != nodeUID {
				return fmt.Errorf("%s: uid %q is not the node's %q", ctx, ev.UID, nodeUID)
			}
			got, ok := resolve(api.Node, ev.Field)
			if !ok {
				return fmt.Errorf("%s: the field does not exist in the node object", ctx)
			}
			if err := checkNodeValue(ctx, ev, got); err != nil {
				return err
			}
			if err := checkTime(ctx, api.Node, ev, got); err != nil {
				return err
			}
		case classify.EvEvent:
			reason := strings.TrimPrefix(ev.Field, "event ")
			if ev.Time == nil {
				return fmt.Errorf("%s: event evidence has no time", ctx)
			}
			for _, e := range api.Events {
				io := nested(e, "involvedObject")
				if str(e, "reason") != reason || str(e, "message") != ev.Value {
					continue
				}
				if str(io, "uid") != ev.UID && (str(io, "kind") != "Node" || ev.UID != nodeName) {
					continue
				}
				if !eventTime(e).Equal(ev.Time.UTC()) {
					continue
				}
				if fp := str(io, "fieldPath"); fp != "" && !strings.Contains(ev.Note, "fieldPath="+fp) {
					continue
				}
				if container != "" {
					if fp := str(io, "fieldPath"); fp != "" && !strings.Contains(fp, "{"+container+"}") {
						return fmt.Errorf("%s: the event is about %s, not container %q", ctx, fp, container)
					}
				}
				return nil
			}
			return fmt.Errorf("%s: no API event with that reason, message, involved uid and time %s", ctx, ev.Time.UTC().Format(time.RFC3339))
		default:
			return fmt.Errorf("%s: unknown evidence kind", ctx)
		}
		return nil
	}

	for _, v := range rep.Verdicts {
		for _, ev := range v.Evidence {
			if err := check("pod verdict "+v.Kind, "", ev); err != nil {
				return err
			}
		}
	}
	for _, ev := range rep.Context {
		if err := check("context", "", ev); err != nil {
			return err
		}
	}
	for _, c := range rep.Containers {
		if rep.Pod.Exists {
			if err := checkTermination(api, c); err != nil {
				return err
			}
		}
		for _, v := range c.Verdicts {
			for _, ev := range v.Evidence {
				if err := check("container "+c.Name+" verdict "+v.Kind, c.Name, ev); err != nil {
					return err
				}
			}
		}
		for _, ev := range c.Restart.Evidence {
			if err := check("container "+c.Name+" restart", c.Name, ev); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseTime(v any) (time.Time, bool) {
	str, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, str)
	return t, err == nil
}

// checkTime requires the evidence time to come from the API object: the field
// itself when it is a time, or the lastTransitionTime of a condition, or the
// finishedAt of a terminated state.
func checkTime(ctx string, obj map[string]any, ev classify.Evidence, got any) error {
	if ev.Time == nil {
		return nil
	}
	var cands []time.Time
	if t, ok := parseTime(got); ok {
		cands = append(cands, t)
	}
	if m, ok := got.(map[string]any); ok {
		if t, ok := parseTime(m["lastTransitionTime"]); ok {
			cands = append(cands, t)
		}
	}
	if i := strings.LastIndex(ev.Field, "."); i > 0 {
		if parent, ok := resolve(obj, ev.Field[:i]); ok {
			if pm, ok := parent.(map[string]any); ok {
				for _, k := range []string{"finishedAt", "lastTransitionTime"} {
					if t, ok := parseTime(pm[k]); ok {
						cands = append(cands, t)
					}
				}
			}
		}
	}
	for _, c := range cands {
		if c.Equal(ev.Time.UTC()) {
			return nil
		}
	}
	return fmt.Errorf("%s: time %s is not backed by the API object (candidates %v)", ctx, ev.Time.UTC().Format(time.RFC3339), cands)
}

func checkNodeValue(ctx string, ev classify.Evidence, got any) error {
	switch {
	case ev.Field == "spec.taints":
		list, _ := got.([]any)
		for _, it := range list {
			m, _ := it.(map[string]any)
			if fmt.Sprintf("%s=%s:%s", str(m, "key"), str(m, "value"), str(m, "effect")) == ev.Value {
				return nil
			}
		}
		return fmt.Errorf("%s: no taint %q on the node", ctx, ev.Value)
	case strings.HasPrefix(ev.Field, "status.conditions["):
		m, _ := got.(map[string]any)
		if want := fmt.Sprintf("%s: %s", str(m, "status"), str(m, "message")); ev.Value != want {
			return fmt.Errorf("%s: value %q differs from the API condition %q", ctx, ev.Value, want)
		}
	default:
		if sv, ok := scalar(got); ok && ev.Value != sv {
			return fmt.Errorf("%s: value %q differs from the API value %q", ctx, ev.Value, sv)
		}
	}
	return nil
}

// checkTermination compares the reported instance with the API: the source
// field exists and the containerID and exit code match.
func checkTermination(api *API, c classify.ContainerReport) error {
	if c.Termination == nil {
		return nil
	}
	for _, list := range []string{"initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"} {
		got, ok := resolve(api.Pod, fmt.Sprintf("status.%s[%s].%s", list, c.Name, c.Termination.Source))
		if !ok {
			continue
		}
		m, _ := got.(map[string]any)
		if id := str(m, "containerID"); id != c.Termination.ContainerID {
			return fmt.Errorf("container %s: reported containerID %q differs from the API %q", c.Name, c.Termination.ContainerID, id)
		}
		if code, _ := m["exitCode"].(float64); int32(code) != c.Termination.ExitCode {
			return fmt.Errorf("container %s: reported exitCode %d differs from the API %v", c.Name, c.Termination.ExitCode, m["exitCode"])
		}
		return nil
	}
	return fmt.Errorf("container %s: %s does not exist in the pod status", c.Name, c.Termination.Source)
}

func toMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

// APIFromSnapshot builds an API view from a saved snapshot. It is the same
// data the classifier saw, so it only proves internal consistency; the kind
// harness uses an API view fetched independently with kubectl instead.
func APIFromSnapshot(s *collect.Snapshot) *API {
	a := &API{Pod: toMap(s.Pod), Node: toMap(s.Node), Owners: map[string]map[string]any{}}
	for i := range s.Events {
		a.Events = append(a.Events, toMap(&s.Events[i]))
	}
	for _, o := range s.Owners {
		anno := map[string]any{}
		if o.Revision != "" {
			anno["deployment.kubernetes.io/revision"] = o.Revision
		}
		a.Owners[string(o.UID)] = map[string]any{"metadata": map[string]any{"uid": string(o.UID), "name": o.Name, "annotations": anno}}
	}
	return a
}

// instanceKey identifies the container instances in an API view: pod UID, and
// per container the restart count, the container IDs of the current and the
// previous termination and the start of a running instance. If it changes
// between two reads, a CrashLoop restart happened in between.
func instanceKey(api *API) string {
	if len(api.Pod) == 0 {
		return "gone"
	}
	var parts []string
	parts = append(parts, str(nested(api.Pod, "metadata"), "uid"))
	for _, list := range []string{"initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"} {
		items, _ := nested(api.Pod, "status")[list].([]any)
		for _, it := range items {
			m, _ := it.(map[string]any)
			rc, _ := m["restartCount"].(float64)
			parts = append(parts, fmt.Sprintf("%s|%v|%s|%s|%s", str(m, "name"), rc,
				str(nested(m, "state", "terminated"), "containerID"),
				str(nested(m, "lastState", "terminated"), "containerID"),
				str(nested(m, "state", "running"), "startedAt")))
		}
	}
	return strings.Join(parts, ";")
}
