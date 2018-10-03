// Note: must be built using "-tags netgo" to enforce Go DNS resolver, which allows for properly static linking,
// but more importantly appears necessary for DNS resolution using a customer dialer.  Without netgo, the first name
// resolution uses our custom Dial method, and thereafter it uses the system resolv.conf settings.  Bug?
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/api"
	prometheus "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// retry runs f once every interval until it returns nil or ctx is done.
func retry(ctx context.Context, interval time.Duration, f func(context.Context) error) error {
	ticker := time.NewTicker(interval)

	err := f(ctx)
	for err != nil {
		select {
		case <-ticker.C:
			err = f(ctx)
		case <-ctx.Done():
			return fmt.Errorf("timed out, last error: %v", err)
		}
	}
	return err
}

// getServiceEndpoints returns the single endpoint corresponding to a DNS SRV record,
// as an ip:port string value.  If there is not exactly one endpoint in DNS, an error
// is returned.
// resolver may be nil in which case the system default resolver is used.
func getServiceEndpoint(ctx context.Context, resolver *net.Resolver, svcName string) (string, error) {
	endpoints, err := getServiceEndpoints(ctx, resolver, svcName)
	if err != nil {
		return "", fmt.Errorf("can't resolve service %q: %v", svcName, err)
	}
	if len(endpoints) != 1 {
		return "", fmt.Errorf("expected exactly one endpoint for service %q, got: %v", svcName, endpoints)
	}
	return endpoints[0], nil
}

// getServiceEndpoints returns the endpoints corresponding to a DNS SRV record,
// as a list of ip:port string values.
// resolver may be nil in which case the system default resolver is used.
func getServiceEndpoints(ctx context.Context, resolver *net.Resolver, svcName string) ([]string, error) {
	var (
		endpoints  []string
		srvRecords []*net.SRV
		ips        []net.IPAddr
		err        error
	)

	_, srvRecords, err = resolver.LookupSRV(ctx, "", "", svcName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve SRV records for %q: %v", svcName, err)
	}

	for _, srvRecord := range srvRecords {
		ips, err = resolver.LookupIPAddr(ctx, srvRecord.Target[:len(srvRecord.Target)-1])
		if err != nil || len(ips) != 1 {
			return nil, fmt.Errorf("failed to resolve exactly one A record for %q (got %v): %v", srvRecord.Target, ips, err)
		}

		ep := fmt.Sprintf("%s:%d", ips[0].IP, srvRecord.Port)
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

type (
	PromTemplateVars struct {
		Services []ServiceTemplateVars
	}

	ServiceTemplateVars struct {
		ServiceName string
		Endpoints   []string
	}
)

func getConntestTemplate() *template.Template {
	tmpl := `
{{- range .Names }}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {{.}}
  labels:
    k8s-app: {{.}}
spec:
  selector:
    matchLabels:
      name: {{.}}
  template:
    metadata:
      labels:
        name: {{.}}
    spec:
      containers:
      - name: blackbox-exporter
        image: prom/blackbox-exporter:v0.12.0
        ports:
        - containerPort: 9115
---
apiVersion: v1
kind: Service
metadata:
  name: {{.}}
spec:
  selector:
    name: {{.}}
  clusterIP: None
  ports:
  - name: http
    protocol: TCP
    port: 80
    targetPort: 9115
{{- end }}`

	return template.Must(template.New("conntest").Parse(tmpl))
}

func getPromCfgConfigMapTemplate() *template.Template {
	tmpl := `---
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app: prometheus
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 5s
      scrape_timeout: 2s
    scrape_configs:
  {{- range $svcidx, $svc := .Services }}
    {{- range $epidx, $endpoint := $svc.Endpoints }}
    - job_name: 'blackbox-svc{{ $svcidx }}-host{{ $epidx }}'
      metrics_path: /probe
      params:
        module: [http_2xx]  # Look for a HTTP 200 response.
      dns_sd_configs:
        - names:
          {{- range $.Services }}
          - {{ .ServiceName }}
          {{- end }}
      relabel_configs:
        # 1. Take the host:port of the current target (coming from DNS service discovery via dns_sd_config)
        # and save it in __param_target.  This will ensure that 'target=host:port' will be provided in the
        # HTTP arguments to blackbox.
        - source_labels: [__address__]
          target_label: __param_target
        # 2. Set instance to the current target, because we're about to overwrite __address__ and that's what
        # would be used if instance were not set.
        - source_labels: [__param_target]
          target_label: instance
        # 3. Set __address__, the endpoint Prometheus will actually hit, to the blackbox_exporter we're testing.
        - target_label: __address__
          replacement: {{ $endpoint }}
    {{- end }}
  {{- end }}`

	return template.Must(template.New("promcfg").Parse(tmpl))
}

// getPrometheusTemplate returns manifests that create a service and deployment both named 'prometheus'.
// The Prometheus instance reads its configuration from a configmap created elsewhere named
// 'prometheus-config' with a key 'prometheus.yml'.
// The template takes as input a struct with field .NodePort which specifies the service's nodePort.
func getPrometheusTemplate() *template.Template {
	tmpl := `---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: prometheus
  name: prometheus
spec:
  ports:
    - name: http
      port: 80
      protocol: TCP
      targetPort: 9090
      nodePort: {{ .NodePort }}
  selector:
    app: prometheus
  type: NodePort
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  labels:
    app: prometheus
  name: prometheus
spec:
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
        - name: prometheus
          image: prom/prometheus:v2.4.2
          args:
            - --storage.tsdb.retention=4h
            - --config.file=/etc/config/prometheus.yml
            - --web.console.libraries=/etc/prometheus/console_libraries
            - --web.console.templates=/etc/prometheus/consoles
            - --web.enable-lifecycle
          ports:
            - containerPort: 9090
          volumeMounts:
            - name: config-volume
              mountPath: /etc/config
      volumes:
        - name: config-volume
          configMap:
            name: prometheus-config
`
	return template.Must(template.New("prometheus").Parse(tmpl))
}

// reloadPromConfig takes advantage of the reload endpoint
// (see https://prometheus.io/docs/prometheus/latest/configuration/configuration)
// that's available unless disabled via the --web.enable-lifecycle=false option.
func reloadPromConfig(ctx context.Context, endpoint string) error {
	log.Printf("asking prometheus to reload its config")
	dest := url.URL{Scheme: "http", Host: endpoint, Path: "/-/reload"}
	req, err := http.NewRequest(http.MethodPost, dest.String(), strings.NewReader(""))
	if err != nil {
		return fmt.Errorf("failed creating a POST request for dest=%s: %v", dest.String(), err)
	}
	_, err = http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed POSTing a reload request to prometheus: %v", err)
	}
	return nil
}

// applyManifests invokes kubectl to apply manifests to the Kubernetes cluster.
func applyManifests(ctx context.Context, yaml string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error applying manifests: %v (output: %s)", err, out)
	}
	return nil
}

func createPrometheusService(ctx context.Context, promport int) error {
	log.Printf("creating prometheus service")
	var buf bytes.Buffer
	getPrometheusTemplate().Execute(&buf, struct{ NodePort int }{promport})
	return applyManifests(ctx, buf.String())
}

func createConntestService(ctx context.Context, svcNames []string) error {
	log.Printf("creating conntest service")
	var buf bytes.Buffer
	getConntestTemplate().Execute(&buf, struct{ Names []string }{svcNames})
	return applyManifests(ctx, buf.String())
}

// getPromConfig generates a Prometheus configmap string based on the given
// svcNames: every endpoint from each service will be both a source and a target
// for every other endpoint.  We assume that each service is backed by a daemonset,
// thus given S svcNames and H worker nodes, there will be N=S*H pods/endpoints and
// N*N targets all told.
// Because getPromConfig may be called right after deploying the services
// given in svcNames, the pods may still be in the process of being created,
// DNS names may still be rolling out, etc., so we'll continue to poll DNS
// until we see pods for all hosts/services.  An error is returned if the context
// becomes done before that happens.
func (c checker) getPromConfig(ctx context.Context, resolver *net.Resolver, svcNames []string) (string, error) {
	log.Printf("building prometheus config")

	var tmplvars PromTemplateVars
	for _, svcName := range svcNames {
		svcvars := ServiceTemplateVars{ServiceName: svcName}
		err := retry(ctx, time.Second, func(ctx context.Context) error {
			endpoints, err := getServiceEndpoints(ctx, resolver, svcName+"."+c.svcDomain)
			if err != nil {
				return err
			}
			if len(endpoints) < c.numHosts {
				return fmt.Errorf("expected %d endpoints, got %d", c.numHosts, len(endpoints))
			}
			svcvars.Endpoints = endpoints
			return nil
		})
		if err != nil {
			return "", err
		}
		tmplvars.Services = append(tmplvars.Services, svcvars)
	}

	var buf bytes.Buffer
	getPromCfgConfigMapTemplate().Execute(&buf, tmplvars)
	return buf.String(), nil
}

// deployOrDie creates N instances of the conntest service/daemonset, each named by
// an element in svcNames.  It then builds a Prometheus configuration for querying
// each pod conntest pod to report its connectivity to every other pod.  The
// prometheus config is written to a configmap.
// Next it queries DNS to see if there's already a prometheus service, and if so
// sends it a command to reload its configuration.  If a prometheus service
// doesn't already exist, one is created.
// Returns the host:port of the prometheus service.
func (c *checker) deploy(ctx context.Context) error {
	err := createConntestService(ctx, c.svcNames)
	if err != nil {
		return fmt.Errorf("Error creating conntest services and daemonsets: %v", err)
	}

	cfgmap, err := c.getPromConfig(ctx, c.resolver, c.svcNames)
	if err != nil {
		return fmt.Errorf("Error building prometheus config: %v", err)
	}

	err = applyManifests(ctx, cfgmap)
	if err != nil {
		return fmt.Errorf("Error writing prometheus config: %v", err)
	}

	// Is there already a prometheus service running from an earlier invocation?
	// Just make sure it has the right config.
	c.promEndpoint, _ = getServiceEndpoint(ctx, c.resolver, c.prometheusDnsName())
	if c.promEndpoint != "" {
		// TODO verify config is loaded before moving on: it doesn't break anything not to,
		// but doing so may help when diagnosing problems.
		return reloadPromConfig(ctx, c.promEndpoint)
	}

	err = createPrometheusService(ctx, c.promPort)
	if err != nil {
		return fmt.Errorf("Error creating prometheus service and deployment: %v", err)
	}

	err = retry(ctx, time.Second, func(ctx context.Context) error {
		var localerr error
		c.promEndpoint, localerr = getServiceEndpoint(ctx, c.resolver, c.prometheusDnsName())
		return localerr
	})
	if err != nil {
		return fmt.Errorf("Error getting prometheus endpoint: %v", err)
	}
	return nil
}

// queryPrometheus connects to the Prometheus HTTP API at prometheusEndpoint and executes the given
// query.  If the result is an instant vector with a single value equal to expected, return nil.
// Otherwise return an error.
func queryPrometheus(ctx context.Context, prometheusEndpoint string, query string, expected int) error {
	queryURL := &url.URL{Scheme: "http", Host: prometheusEndpoint}
	client, err := api.NewClient(api.Config{Address: queryURL.String()})
	if err != nil {
		return err
	}

	api := prometheus.NewAPI(client)
	val, err := api.Query(ctx, query, time.Now())
	if err != nil {
		return err
	}

	// I'd like to just use go-cmp here, but the model.Vector and model.Sample types define Equal(),
	// and all the go-cmp options like transformers and ignorers that would allow us to only compare
	// sample values (and not timestamps or metric names) have a lower priority than Equal().
	var values []float64
	if vect, ok := val.(model.Vector); ok {
		for _, sample := range vect {
			values = append(values, float64(sample.Value))
		}
	}
	expectedFloats := []float64{float64(expected)}
	if diff := cmp.Diff(values, expectedFloats); diff != "" {
		return fmt.Errorf("got unexpected result from query %q, diff: %s", query, diff)
	}
	return nil
}

func (c config) prometheusDnsName() string {
	return "prometheus" + "." + c.svcDomain
}

func (c checker) checkConnectivity(ctx context.Context) error {
	if c.promEndpoint == "" {
		var err error
		c.promEndpoint, err = getServiceEndpoint(ctx, c.resolver, c.prometheusDnsName())
		if err != nil {
			return fmt.Errorf("Error getting prometheus endpoint: %v", err)
		}
	}

	numpods := c.numHosts * len(c.svcNames)
	expectedResult := numpods * numpods
	return retry(ctx, time.Second, func(ctx context.Context) error {
		return queryPrometheus(ctx, c.promEndpoint, "sum(probe_success)", expectedResult)
	})
}

type config struct {
	resolver  *net.Resolver
	numHosts  int
	svcNames  []string
	promPort  int
	svcDomain string
}

type checker struct {
	config
	promEndpoint string
}

func main() {
	var (
		flagResolver  = flag.String("resolver", "", "DNS resolver to use (host:port), empty for system default")
		flagPromPort  = flag.Int("promport", 31000, "NodePort for Prometheus service to listen on")
		flagNumHosts  = flag.Int("numhosts", 3, "Number of worker nodes in cluster")
		flagQueryOnly = flag.Bool("queryonly", false, "Only do query, instead of deploying and then querying")
		flagTimeout   = flag.Duration("timeout", 2*time.Minute, "Total time limit, prometheus query will be retried until it passes or time runs out")
		flagSvcDomain = flag.String("svcdomain", "default.svc.cluster.local", "DNS domain to find services in")
	)

	flag.CommandLine.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] svc1 svc2 ... svcN\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	mainctx, cancel := context.WithTimeout(context.Background(), *flagTimeout)
	defer cancel()

	var resolver *net.Resolver
	if *flagResolver != "" {
		resolver = &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", *flagResolver)
			},
		}
	}

	if len(flag.Args()) < 1 {
		flag.CommandLine.Usage()
		os.Exit(1)
	}

	chk := checker{
		config: config{
			resolver:  resolver,
			numHosts:  *flagNumHosts,
			svcNames:  flag.Args(),
			promPort:  *flagPromPort,
			svcDomain: *flagSvcDomain,
		},
	}

	if !*flagQueryOnly {
		err := chk.deploy(mainctx)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	log.Printf("querying prometheus to verify cross-pod connectivity")
	err := chk.checkConnectivity(mainctx)
	if err != nil {
		log.Fatalf("%v", err)
	} else {
		log.Printf("verified connectivity across all pods")
	}
}
