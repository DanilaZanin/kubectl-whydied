// Command kubectl-whydied explains why a Kubernetes container or pod died or
// restarted, with the evidence for every claim and a confidence label.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/DanilaZanin/kubectl-whydied/internal/classify"
	"github.com/DanilaZanin/kubectl-whydied/internal/collect"
	"github.com/DanilaZanin/kubectl-whydied/internal/render"
)

var (
	version = "dev"
	commit  = "none"
)

const usage = `kubectl whydied explains why a container or pod died or restarted.

Usage:
  kubectl whydied POD [-n NAMESPACE] [-c CONTAINER] [flags]
  kubectl whydied -A --restarted-since 30m
  kubectl whydied -n NAMESPACE --restarted-since 30m

Flags:
`

// Exit codes: 0 diagnosis printed, 1 error, 2 no data at all.
const (
	exitOK     = 0
	exitError  = 1
	exitNoData = 2
)

type config struct {
	namespace      string
	container      string
	allNamespaces  bool
	restartedSince time.Duration
	previousLogs   int
	window         time.Duration
	output         string
	kubeconfig     string
	kubeContext    string
	noColor        bool
	fromSnapshot   string
	dumpSnapshot   string
	showVersion    bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// parseArgs allows flags before and after the pod name, like kubectl does.
func parseArgs(args []string, stderr io.Writer) (*config, []string, error) {
	c := &config{}
	fs := flag.NewFlagSet("kubectl-whydied", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.namespace, "n", "", "namespace (default: from kubeconfig)")
	fs.StringVar(&c.namespace, "namespace", "", "namespace (default: from kubeconfig)")
	fs.StringVar(&c.container, "c", "", "explain only this container")
	fs.StringVar(&c.container, "container", "", "explain only this container")
	fs.BoolVar(&c.allNamespaces, "A", false, "list restarted pods in all namespaces")
	fs.BoolVar(&c.allNamespaces, "all-namespaces", false, "list restarted pods in all namespaces")
	fs.DurationVar(&c.restartedSince, "restarted-since", 0, "list pods whose last termination is newer than this (pods currently in the API only)")
	fs.IntVar(&c.previousLogs, "previous-logs", 0, "include the last N log lines of the explained container instance")
	fs.DurationVar(&c.window, "window", classify.DefaultWindow, "correlation window between a termination and events")
	fs.StringVar(&c.output, "o", "text", "output format: text or json")
	fs.StringVar(&c.output, "output", "text", "output format: text or json")
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	fs.StringVar(&c.kubeContext, "context", "", "kubeconfig context to use")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colored output")
	fs.StringVar(&c.fromSnapshot, "from-snapshot", "", "analyze a snapshot file instead of a live cluster")
	fs.StringVar(&c.dumpSnapshot, "dump-snapshot", "", "write the collected snapshot to this file (for bug reports and test fixtures)")
	fs.BoolVar(&c.showVersion, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}

	var pos []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		rest = rest[1:]
	}
	if c.output != "text" && c.output != "json" {
		return nil, nil, fmt.Errorf("unknown output format %q (use text or json)", c.output)
	}
	return c, pos, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c, pos, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if c.showVersion {
		fmt.Fprintf(stdout, "kubectl-whydied %s (%s)\n", version, commit)
		return exitOK
	}
	list := c.allNamespaces || c.restartedSince > 0
	switch {
	case len(pos) > 1:
		fmt.Fprintln(stderr, "error: expected one POD argument")
		return exitError
	case len(pos) == 0 && c.fromSnapshot == "" && !list:
		fmt.Fprint(stderr, usage)
		return exitError
	case len(pos) == 1 && list:
		fmt.Fprintln(stderr, "error: POD cannot be combined with -A or --restarted-since")
		return exitError
	}
	copts := classify.Options{Window: c.window, Container: c.container}

	if c.fromSnapshot != "" {
		snap, err := collect.Load(c.fromSnapshot)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		return single(snap, copts, c, stdout, stderr)
	}

	cs, ns, err := client(c)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if list {
		return listMode(ctx, cs, ns, copts, c, stdout, stderr)
	}
	snap, err := collect.Collect(ctx, cs, collect.Options{Namespace: ns, Pod: pos[0], Container: c.container, PreviousLogs: c.previousLogs})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return single(snap, copts, c, stdout, stderr)
}

func client(c *config) (kubernetes.Interface, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if c.kubeconfig != "" {
		rules.ExplicitPath = c.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: c.kubeContext}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	rc, err := cc.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}
	ns := c.namespace
	if ns == "" {
		if ns, _, err = cc.Namespace(); err != nil || ns == "" {
			ns = "default"
		}
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, "", err
	}
	return cs, ns, nil
}

func single(snap *collect.Snapshot, copts classify.Options, c *config, stdout, stderr io.Writer) int {
	if c.dumpSnapshot != "" {
		if err := snap.Save(c.dumpSnapshot); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
	}
	rep, err := classify.Analyze(snap, copts)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if c.output == "json" {
		if err := render.JSON(stdout, rep); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
	} else {
		render.Text(stdout, rep, useColor(c, stdout))
	}
	if !rep.HasData() {
		return exitNoData
	}
	return exitOK
}

func listMode(ctx context.Context, cs kubernetes.Interface, ns string, copts classify.Options, c *config, stdout, stderr io.Writer) int {
	scope := ns
	if c.allNamespaces {
		scope = ""
	}
	since := c.restartedSince
	if since <= 0 {
		since = 24 * time.Hour * 365
	}
	now := time.Now()
	pods, err := collect.RestartedPods(ctx, cs, scope, since, now)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	reports := []*classify.Report{}
	var failures []listFailure
	for i := range pods {
		p := &pods[i]
		snap, err := collect.Collect(ctx, cs, collect.Options{Namespace: p.Namespace, Pod: p.Name})
		if err == nil {
			var rep *classify.Report
			if rep, err = classify.Analyze(snap, copts); err == nil {
				reports = append(reports, rep)
				continue
			}
		}
		failures = append(failures, listFailure{Pod: p.Namespace + "/" + p.Name, Error: err.Error()})
	}
	// Every candidate failing is an error, not an empty result.
	code := exitOK
	if len(pods) > 0 && len(reports) == 0 {
		code = exitError
	}
	if c.output == "json" {
		if err := render.JSON(stdout, listResult{ObservedAt: now.UTC(), Candidates: len(pods), Reports: reports, Failures: failures}); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		return code
	}
	if len(pods) == 0 {
		fmt.Fprintf(stdout, "no pods with a restart or previous termination in the last %s (only pods currently in the API are visible)\n", since)
		return exitOK
	}
	for _, r := range reports {
		fmt.Fprintln(stdout, render.Line(r))
	}
	for _, f := range failures {
		fmt.Fprintf(stdout, "%s: diagnosis failed: %s\n", f.Pod, f.Error)
	}
	if len(failures) > 0 {
		fmt.Fprintf(stderr, "error: %d of %d candidate pods could not be diagnosed\n", len(failures), len(pods))
	}
	fmt.Fprintln(stdout, "\nRun 'kubectl whydied POD -n NAMESPACE' for evidence. Only pods currently in the API are listed; restartCount may have been reset.")
	return code
}

type listFailure struct {
	Pod   string `json:"pod"`
	Error string `json:"error"`
}

// listResult is the JSON of list mode. Failures are kept apart from an empty
// selection: Candidates counts the pods that matched.
type listResult struct {
	ObservedAt time.Time          `json:"observedAt"`
	Candidates int                `json:"candidates"`
	Reports    []*classify.Report `json:"reports"`
	Failures   []listFailure      `json:"failures"`
}

func useColor(c *config, w io.Writer) bool {
	if c.noColor || os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
