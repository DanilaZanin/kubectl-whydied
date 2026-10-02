//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
)

const (
	defaultNodeImage = "kindest/node:v1.37.0"
	busyboxImage     = "busybox:1.37"
	kindConfig       = `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
`
)

var (
	kubeconfig  string
	binPath     string
	clusterName string
	k8sLabel    string
)

func sh(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if kubeconfig != "" {
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func must(t testing.TB, out string, err error, what string) string {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v\n%s", what, err, out)
	}
	return out
}

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	ctx := context.Background()
	img := os.Getenv("WD_E2E_NODE_IMAGE")
	if img == "" {
		img = defaultNodeImage
	}
	k8sLabel = os.Getenv("WD_E2E_K8S")
	if k8sLabel == "" {
		k8sLabel = strings.TrimPrefix(strings.SplitN(strings.SplitN(img, "@", 2)[0], ":", 2)[1], "")
	}
	tmp, err := os.MkdirTemp("", "wd-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	binPath = os.Getenv("WD_E2E_BIN")
	if binPath == "" {
		binPath = filepath.Join(tmp, "kubectl-whydied")
		root, _ := filepath.Abs("../..")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/kubectl-whydied")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
			return 1
		}
	}

	clusterName = "wd-" + strings.NewReplacer(".", "", "v", "").Replace(strings.SplitN(k8sLabel, "@", 2)[0]) + "-" + strconv.Itoa(os.Getpid()%10000)
	kubeconfig = filepath.Join(tmp, "kubeconfig")
	cfg := filepath.Join(tmp, "kind.yaml")
	_ = os.WriteFile(cfg, []byte(kindConfig), 0o644)

	if out, err := sh(ctx, "docker", "image", "inspect", busyboxImage); err != nil {
		if out2, err2 := sh(ctx, "docker", "pull", busyboxImage); err2 != nil {
			fmt.Fprintf(os.Stderr, "cannot get %s: %v\n%s%s", busyboxImage, err2, out, out2)
			return 1
		}
	}
	if existing := os.Getenv("WD_E2E_CLUSTER"); existing != "" {
		// Development shortcut: reuse a cluster that is already running and never delete it.
		clusterName = existing
		out, err := sh(ctx, "kind", "export", "kubeconfig", "--name", existing, "--kubeconfig", kubeconfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kind export kubeconfig: %v\n%s", err, out)
			return 1
		}
		return m.Run()
	}
	fmt.Printf("creating kind cluster %s from %s\n", clusterName, img)
	if out, err := sh(ctx, "kind", "create", "cluster", "--name", clusterName, "--image", img, "--config", cfg, "--kubeconfig", kubeconfig, "--wait", "180s"); err != nil {
		fmt.Fprintf(os.Stderr, "kind create failed: %v\n%s", err, out)
		_, _ = sh(ctx, "kind", "delete", "cluster", "--name", clusterName)
		return 1
	}
	if os.Getenv("WD_E2E_KEEP") == "" {
		defer func() {
			out, err := sh(ctx, "kind", "delete", "cluster", "--name", clusterName)
			fmt.Printf("kind delete cluster %s: err=%v %s\n", clusterName, err, strings.TrimSpace(out))
		}()
	}
	if err := loadImage(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}

// loadImage puts busybox into every kind node. "kind load" fails when Docker uses
// the containerd image store (multi-platform manifests), so fall back to a pull
// inside the nodes. WD_E2E_REGISTRY_MIRROR (for example mirror.gcr.io) is a
// local testing aid for Docker Hub rate limits.
func loadImage(ctx context.Context) error {
	out, err := sh(ctx, "kind", "load", "docker-image", busyboxImage, "--name", clusterName)
	if err == nil {
		return nil
	}
	fmt.Printf("kind load docker-image failed, pulling inside the nodes: %s\n", strings.TrimSpace(out))
	nodes, err := sh(ctx, "kind", "get", "nodes", "--name", clusterName)
	if err != nil {
		return fmt.Errorf("kind get nodes: %w\n%s", err, nodes)
	}
	canonical := "docker.io/library/" + busyboxImage
	src := canonical
	if m := os.Getenv("WD_E2E_REGISTRY_MIRROR"); m != "" {
		src = m + "/library/" + busyboxImage
	}
	for _, n := range strings.Fields(nodes) {
		if o, err := sh(ctx, "docker", "exec", n, "ctr", "--namespace=k8s.io", "images", "pull", src); err != nil {
			return fmt.Errorf("pull %s in %s: %w\n%s", src, n, err, o)
		}
		if src != canonical {
			if o, err := sh(ctx, "docker", "exec", n, "ctr", "--namespace=k8s.io", "images", "tag", "--force", src, canonical); err != nil {
				return fmt.Errorf("tag in %s: %w\n%s", n, err, o)
			}
		}
	}
	return nil
}

func TestScenarios(t *testing.T) {
	dirs, err := filepath.Glob("scenarios/*/expected.json")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	filter := regexp.MustCompile(os.Getenv("WD_E2E_SCENARIOS"))
	for _, d := range dirs {
		dir := filepath.Dir(d)
		name := filepath.Base(dir)
		if !filter.MatchString(name) {
			continue
		}
		t.Run(name, func(t *testing.T) { runScenario(t, dir) })
	}
}

type env struct {
	t    *testing.T
	ns   string
	vars map[string]string
	sc   *Scenario
}

func (e *env) sub(s string) string {
	for k, v := range e.vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func (e *env) subAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = e.sub(s)
	}
	return out
}

func (e *env) kubectl(ctx context.Context, noNS bool, args ...string) (string, error) {
	if !noNS {
		args = append([]string{"-n", e.ns}, args...)
	}
	return sh(ctx, "kubectl", args...)
}

// apply renders {{vars}} in a manifest and applies it.
func (e *env) apply(ctx context.Context, file string) {
	b, err := os.ReadFile(filepath.Join(e.sc.Dir, file))
	if err != nil {
		e.t.Fatal(err)
	}
	tmp := filepath.Join(e.t.TempDir(), file)
	if err := os.WriteFile(tmp, []byte(e.sub(string(b))), 0o644); err != nil {
		e.t.Fatal(err)
	}
	out, err := e.kubectl(ctx, false, "apply", "-f", tmp)
	must(e.t, out, err, "kubectl apply "+file)
}

func (e *env) firstPod(ctx context.Context, sel string) (name, node string) {
	out, err := e.kubectl(ctx, false, "get", "pods", "-l", sel, "-o", `jsonpath={range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}`)
	if err != nil {
		return "", ""
	}
	f := strings.Fields(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	if len(f) == 0 {
		return "", ""
	}
	if len(f) == 1 {
		return f[0], ""
	}
	return f[0], f[1]
}

func (e *env) step(ctx context.Context, s Step) {
	e.t.Helper()
	switch {
	case s.Apply != "":
		e.apply(ctx, s.Apply)
	case len(s.Kubectl) > 0:
		out, err := e.kubectl(ctx, s.NoNamespace, e.subAll(s.Kubectl)...)
		if err != nil && !s.AllowFail {
			e.t.Fatalf("kubectl %v: %v\n%s", s.Kubectl, err, out)
		}
	case len(s.Wait) > 0:
		out, err := e.kubectl(ctx, false, append([]string{"wait"}, e.subAll(s.Wait)...)...)
		must(e.t, out, err, "kubectl wait")
	case s.CapturePod != "":
		deadline := time.Now().Add(60 * time.Second)
		for {
			n, node := e.firstPod(ctx, e.sub(e.sc.Target.Selector))
			if n != "" && node != "" {
				e.vars[s.CapturePod], e.vars["node"] = n, node
				return
			}
			if time.Now().After(deadline) {
				e.t.Fatalf("capturePod: no pod for selector %q", e.sc.Target.Selector)
			}
			time.Sleep(2 * time.Second)
		}
	case s.Sleep > 0:
		time.Sleep(time.Duration(s.Sleep) * time.Second)
	}
}

func (e *env) resolveTarget(ctx context.Context) string {
	tg := e.sc.Target
	if tg.Name != "" {
		return e.sub(tg.Name)
	}
	sel := e.sub(tg.Selector)
	if tg.Terminating {
		out, err := e.kubectl(ctx, false, "get", "pods", "-l", sel, "-o", `jsonpath={range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}`)
		if err != nil {
			return ""
		}
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) == 2 {
				return f[0]
			}
		}
		return ""
	}
	n, _ := e.firstPod(ctx, sel)
	return n
}

func runScenario(t *testing.T, dir string) {
	sc, err := LoadScenario(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e := &env{t: t, ns: "wd-" + sc.Name, vars: map[string]string{}, sc: sc}
	e.vars["ns"] = e.ns
	// Half of the worker's allocatable CPU, for the preemption scenario.
	if out, err := sh(ctx, "kubectl", "get", "nodes", "-l", "!node-role.kubernetes.io/control-plane", "-o", "jsonpath={.items[0].status.allocatable.cpu}"); err == nil {
		if cpus, err := strconv.ParseFloat(strings.TrimSpace(out), 64); err == nil {
			e.vars["cpu60"] = fmt.Sprintf("%dm", int(cpus*600))
		} else if strings.HasSuffix(strings.TrimSpace(out), "m") {
			m, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(out), "m"))
			e.vars["cpu60"] = fmt.Sprintf("%dm", m*6/10)
		}
	}
	out, err := sh(ctx, "kubectl", "create", "namespace", e.ns)
	must(t, out, err, "create namespace")
	defer func() {
		for _, s := range sc.Cleanup {
			e.step(ctx, s)
		}
		_, _ = sh(ctx, "kubectl", "delete", "namespace", e.ns, "--wait=false")
	}()

	e.apply(ctx, sc.Manifest)
	for _, s := range sc.Steps {
		e.step(ctx, s)
	}

	deadline := time.Now().Add(time.Duration(sc.TimeoutSeconds) * time.Second)
	var last string
	for {
		pod := e.resolveTarget(ctx)
		if pod != "" {
			rep, raw, err := runTool(ctx, e, pod)
			if err == nil {
				if err = Evaluate(sc.Expect, rep, e.knownUIDs(ctx, rep)...); err == nil {
					requireStable(ctx, t, e)
					t.Logf("PASS on k8s %s: pod %s\n%s", k8sLabel, pod, raw)
					saveFixture(ctx, t, e, e.resolveTarget(ctx))
					return
				}
			}
			last = fmt.Sprintf("pod %s: %v", pod, err)
			if raw != "" {
				last += "\n" + raw
			}
		} else {
			last = "target pod not found yet"
		}
		if time.Now().After(deadline) {
			desc, _ := e.kubectl(ctx, false, "describe", "pods")
			evs, _ := e.kubectl(ctx, false, "get", "events", "--sort-by=.lastTimestamp")
			t.Fatalf("scenario did not reach the expected state in %ds: %s\n--- describe pods\n%s\n--- events\n%s", sc.TimeoutSeconds, last, desc, evs)
		}
		time.Sleep(3 * time.Second)
	}
}

// requireStable runs the tool three more times, five seconds apart. The
// expectation must hold every time: polling until it matches first would
// otherwise hide a verdict that is wrong in a transient state.
func requireStable(ctx context.Context, t *testing.T, e *env) {
	t.Helper()
	for i := 1; i <= 3; i++ {
		time.Sleep(5 * time.Second)
		pod := e.resolveTarget(ctx)
		if pod == "" {
			t.Fatalf("stability check %d/3: target pod disappeared", i)
		}
		rep, raw, err := runTool(ctx, e, pod)
		if err == nil {
			err = Evaluate(e.sc.Expect, rep, e.knownUIDs(ctx, rep)...)
		}
		if err != nil {
			t.Fatalf("stability check %d/3 failed for pod %s: %v\n%s", i, pod, err, raw)
		}
	}
}

func (e *env) knownUIDs(ctx context.Context, rep *classify.Report) []string {
	if rep.Pod.Node == "" {
		return nil
	}
	out, _ := sh(ctx, "kubectl", "get", "node", rep.Pod.Node, "-o", "jsonpath={.metadata.uid}")
	return []string{strings.TrimSpace(out), rep.Pod.Node}
}

func runTool(ctx context.Context, e *env, pod string) (*classify.Report, string, error) {
	args := []string{"-n", e.ns, "-o", "json", "--window", "5m"}
	if c := e.sc.Target.Container; c != "" {
		args = append(args, "-c", c)
	}
	args = append(args, pod)
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && (!errors.As(err, &ee) || ee.ExitCode() != 2) {
		return nil, stderr.String(), fmt.Errorf("tool failed: %w", err)
	}
	var rep classify.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return nil, stdout.String(), fmt.Errorf("bad json: %w", err)
	}
	return &rep, stdout.String(), nil
}

// saveFixture stores the snapshot of the passing state when WD_E2E_FIXTURES is set.
func saveFixture(ctx context.Context, t *testing.T, e *env, pod string) {
	dir := os.Getenv("WD_E2E_FIXTURES")
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	file := filepath.Join(dir, fmt.Sprintf("%s.%s.snapshot.json", e.sc.Name, strings.SplitN(k8sLabel, "@", 2)[0]))
	args := []string{"-n", e.ns, "-o", "json", "--window", "5m", "--previous-logs", "10", "--dump-snapshot", file}
	if c := e.sc.Target.Container; c != "" {
		args = append(args, "-c", c)
	}
	args = append(args, pod)
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	if out, err := cmd.CombinedOutput(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 {
			t.Logf("fixture capture failed: %v\n%s", err, out)
		}
	}
}
