// Inspect-only Coraza sidecar. Unix socket, CRS 4.25 LTS.
// Ferroada never links this binary; a panic here cannot kill the data plane.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const defaultSocket = "/run/coraza/waf.sock"

type inspectRequest struct {
	Method   string         `json:"method"`
	URI      string         `json:"uri"`
	Protocol string         `json:"protocol"`
	Headers  [][]string     `json:"headers"`
	BodyB64  string         `json:"body_b64"`
	ClientIP string         `json:"client_ip"`
	Policy   *inspectPolicy `json:"policy,omitempty"`
}

type inspectPolicy struct {
	BlockingParanoia      int      `json:"blocking_paranoia"`
	ExecutingParanoia     int      `json:"executing_paranoia"`
	AnomalyScoreThreshold int      `json:"anomaly_score_threshold"`
	ExcludeParameters     []string `json:"exclude_parameters"`
}

type inspectResponse struct {
	Action  string `json:"action"`
	RuleIDs []uint `json:"rule_ids,omitempty"`
	Score   int    `json:"score,omitempty"`
	Msg     string `json:"msg,omitempty"`
}

const (
	hdrBlocking   = "x-ferroada-l1-blocking-paranoia"
	hdrExecuting  = "x-ferroada-l1-executing-paranoia"
	hdrThreshold  = "x-ferroada-l1-anomaly-threshold"
	policyRuleMin = 10009
	policyRuleMax = 10020
)

func main() {
	check := flag.Bool("check", false, "probe /readyz on the socket and exit")
	flag.Parse()
	socket := os.Getenv("WAF_SOCKET")
	if socket == "" {
		socket = defaultSocket
	}
	if *check {
		if err := readyCheck(socket); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	waf, err := newWAF()
	if err != nil {
		log.Fatalf("failed to load Coraza/CRS: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/inspect", func(w http.ResponseWriter, r *http.Request) {
		handleInspect(w, r, waf)
	})

	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		log.Fatalf("cannot clear stale socket %s: %v", socket, err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalf("listen %s: %v", socket, err)
	}
	if err := os.Chmod(socket, 0o666); err != nil {
		log.Fatalf("chmod %s: %v", socket, err)
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("coraza sidecar listening on %s (CRS 4.25 LTS)", socket)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
	_ = os.Remove(socket)
}

func newWAF() (coraza.WAF, error) {
	// CRS 4.25 @coraza.conf-recommended uses SecRequestBodyJsonDepthLimit,
	// which Coraza 3.3.3 does not implement. Keep the body-access subset
	// that 3.3.3 accepts. SecRuleEngine On: CRS 949 denies when the blocking
	// score crosses the threshold. Executing (detection) paranoia is a
	// separate TX var — rules above blocking_paranoia still run, they just
	// do not add to the blocking score. Per-request values arrive as
	// X-Ferroada-L1-* headers (stripped from the client, set from JSON).
	directives := `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecRule REQUEST_HEADERS:Content-Type "@rx (?:application/(?:soap\+|)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^application/x-www-form-urlencoded" "id:200007,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
Include @crs-setup.conf.example
SecAction "id:10009,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:x-ferroada-l1-blocking-paranoia,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:x-ferroada-l1-executing-paranoia,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:x-ferroada-l1-anomaly-threshold"
SecRule REQUEST_HEADERS:x-ferroada-l1-blocking-paranoia "@rx ^([1-4])$" "id:10010,phase:1,pass,nolog,t:none,capture,setvar:tx.blocking_paranoia_level=%{TX.1}"
SecRule REQUEST_HEADERS:x-ferroada-l1-executing-paranoia "@rx ^([1-4])$" "id:10011,phase:1,pass,nolog,t:none,capture,setvar:tx.detection_paranoia_level=%{TX.1}"
SecRule REQUEST_HEADERS:x-ferroada-l1-anomaly-threshold "@rx ^([1-9][0-9]{0,4})$" "id:10012,phase:1,pass,nolog,t:none,capture,setvar:tx.inbound_anomaly_score_threshold=%{TX.1}"
Include @owasp_crs/REQUEST-901-INITIALIZATION.conf
Include @owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf
Include @owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf
Include @owasp_crs/REQUEST-913-SCANNER-DETECTION.conf
Include @owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include @owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf
Include @owasp_crs/REQUEST-922-MULTIPART-ATTACK.conf
Include @owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include @owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include @owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include @owasp_crs/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include @owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include @owasp_crs/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include @owasp_crs/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf
Include @owasp_crs/REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf
Include @owasp_crs/RESPONSE-950-DATA-LEAKAGES.conf
Include @owasp_crs/RESPONSE-951-DATA-LEAKAGES-SQL.conf
Include @owasp_crs/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
Include @owasp_crs/RESPONSE-953-DATA-LEAKAGES-PHP.conf
Include @owasp_crs/RESPONSE-954-DATA-LEAKAGES-IIS.conf
Include @owasp_crs/RESPONSE-955-WEB-SHELLS.conf
Include @owasp_crs/RESPONSE-956-DATA-LEAKAGES-RUBY.conf
Include @owasp_crs/RESPONSE-959-BLOCKING-EVALUATION.conf
Include @owasp_crs/RESPONSE-980-CORRELATION.conf
SecRule TX:DETECTION_INBOUND_ANOMALY_SCORE "@ge 0" "id:10020,phase:2,pass,log,t:none,msg:'ferroada_score blocking=%{tx.blocking_inbound_anomaly_score} detection=%{tx.detection_inbound_anomaly_score}'"
`
	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(directives),
	)
}

func handleInspect(w http.ResponseWriter, r *http.Request, waf coraza.WAF) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	if r.Method != http.MethodPost {
		http.Error(w, `{"action":"deny","msg":"method"}`, http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, inspectResponse{Action: "deny", Msg: "body"})
		return
	}
	var req inspectRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, inspectResponse{Action: "deny", Msg: "json"})
		return
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URI == "" {
		req.URI = "/"
	}
	if req.Protocol == "" {
		req.Protocol = "HTTP/1.1"
	}
	policy := resolvePolicy(req.Policy)
	req.URI = stripQueryParams(req.URI, policy.ExcludeParameters)
	rawBody := stripBody(decodeBody(req.BodyB64), req.Headers, policy.ExcludeParameters)

	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	clientHost, clientPort := splitHostPort(req.ClientIP)
	tx.ProcessConnection(clientHost, clientPort, "127.0.0.1", 80)
	tx.ProcessURI(req.URI, req.Method, req.Protocol)
	for _, header := range req.Headers {
		if len(header) < 2 || header[0] == "" {
			continue
		}
		if isPolicyHeader(header[0]) {
			continue
		}
		tx.AddRequestHeader(header[0], header[1])
	}
	tx.AddRequestHeader(hdrBlocking, fmt.Sprintf("%d", policy.BlockingParanoia))
	tx.AddRequestHeader(hdrExecuting, fmt.Sprintf("%d", policy.ExecutingParanoia))
	tx.AddRequestHeader(hdrThreshold, fmt.Sprintf("%d", policy.AnomalyScoreThreshold))
	if it := tx.ProcessRequestHeaders(); it != nil {
		writeInspect(w, tx, it)
		return
	}
	if len(rawBody) > 0 {
		if it, _, err := tx.WriteRequestBody(rawBody); err != nil {
			writeJSON(w, http.StatusOK, inspectResponse{Action: "deny", Msg: "body write"})
			return
		} else if it != nil {
			writeInspect(w, tx, it)
			return
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		writeJSON(w, http.StatusOK, inspectResponse{Action: "deny", Msg: "body process"})
		return
	} else if it != nil {
		writeInspect(w, tx, it)
		return
	}
	writeInspect(w, tx, nil)
}

func writeInspect(w http.ResponseWriter, tx types.Transaction, it *types.Interruption) {
	ids := uniqueRuleIDs(tx, it)
	score := anomalyScore(tx, it)
	if it != nil {
		msg := it.Data
		if msg == "" {
			msg = it.Action
		}
		writeJSON(w, http.StatusOK, inspectResponse{
			Action:  "deny",
			RuleIDs: ids,
			Score:   score,
			Msg:     msg,
		})
		return
	}
	writeJSON(w, http.StatusOK, inspectResponse{
		Action:  "allow",
		RuleIDs: ids,
		Score:   score,
	})
}

func uniqueRuleIDs(tx types.Transaction, it *types.Interruption) []uint {
	seen := map[int]struct{}{}
	var ids []uint
	add := func(id int) {
		if !reportableRuleID(id) {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, uint(id))
	}
	if it != nil {
		add(it.RuleID)
	}
	for _, matched := range tx.MatchedRules() {
		add(matched.Rule().ID())
	}
	return ids
}

func isPolicyHeader(name string) bool {
	n := strings.ToLower(name)
	return n == hdrBlocking || n == hdrExecuting || n == hdrThreshold
}

func clampParanoia(value, fallback int) int {
	if value < 1 || value > 4 {
		return fallback
	}
	return value
}

func clampThreshold(value, fallback int) int {
	if value < 1 || value > 10000 {
		return fallback
	}
	return value
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	n := 0
	if _, err := fmt.Sscanf(raw, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func resolvePolicy(raw *inspectPolicy) inspectPolicy {
	blocking := clampParanoia(envInt("CRS_BLOCKING_PARANOIA", 1), 1)
	executing := envInt("CRS_EXECUTING_PARANOIA", 0)
	threshold := clampThreshold(envInt("CRS_ANOMALY_INBOUND", 5), 5)
	var params []string
	if raw != nil {
		blocking = clampParanoia(raw.BlockingParanoia, blocking)
		if raw.ExecutingParanoia != 0 {
			executing = clampParanoia(raw.ExecutingParanoia, executing)
		}
		threshold = clampThreshold(raw.AnomalyScoreThreshold, threshold)
		params = raw.ExcludeParameters
	}
	if executing < blocking {
		executing = blocking
	}
	executing = clampParanoia(executing, blocking)
	return inspectPolicy{
		BlockingParanoia:      blocking,
		ExecutingParanoia:     executing,
		AnomalyScoreThreshold: threshold,
		ExcludeParameters:     params,
	}
}

func paramExcluded(key string, names []string) bool {
	for _, name := range names {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func reportableRuleID(id int) bool {
	if id <= 0 {
		return false
	}
	if id >= policyRuleMin && id <= policyRuleMax {
		return false
	}
	if id >= 200000 && id < 201000 {
		return false
	}
	if id >= 900000 && id < 910000 {
		return false
	}
	if id >= 949000 && id != 949110 && id != 949111 {
		return false
	}
	if id >= 959000 {
		return false
	}
	return true
}

func stripQueryParams(uri string, names []string) string {
	if len(names) == 0 {
		return uri
	}
	path, query, ok := strings.Cut(uri, "?")
	if !ok {
		return uri
	}
	var kept []string
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		key, _, _ := strings.Cut(pair, "=")
		if paramExcluded(key, names) {
			continue
		}
		kept = append(kept, pair)
	}
	if len(kept) == 0 {
		return path
	}
	return path + "?" + strings.Join(kept, "&")
}

func headerMediaType(headers [][]string) string {
	for _, header := range headers {
		if len(header) < 2 {
			continue
		}
		if strings.EqualFold(header[0], "content-type") {
			media, _, _ := strings.Cut(header[1], ";")
			return strings.ToLower(strings.TrimSpace(media))
		}
	}
	return ""
}

func stripBody(body []byte, headers [][]string, names []string) []byte {
	if len(names) == 0 || len(body) == 0 {
		return body
	}
	media := headerMediaType(headers)
	switch {
	case media == "application/x-www-form-urlencoded":
		var kept []string
		for _, pair := range strings.Split(string(body), "&") {
			if pair == "" {
				continue
			}
			key, _, _ := strings.Cut(pair, "=")
			if paramExcluded(key, names) {
				continue
			}
			kept = append(kept, pair)
		}
		return []byte(strings.Join(kept, "&"))
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		var object map[string]json.RawMessage
		if err := json.Unmarshal(body, &object); err != nil {
			return body
		}
		for key := range object {
			if paramExcluded(key, names) {
				delete(object, key)
			}
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return body
		}
		return encoded
	default:
		return body
	}
}

func parseScoreToken(text, prefix string) (int, bool) {
	i := strings.Index(text, prefix)
	if i < 0 {
		return 0, false
	}
	rest := text[i+len(prefix):]
	n := 0
	if _, err := fmt.Sscanf(rest, "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

func anomalyScore(tx types.Transaction, it *types.Interruption) int {
	blocking, detection := 0, 0
	if it != nil {
		if n, ok := parseScoreToken(it.Data, "Total Score: "); ok {
			blocking = n
		}
	}
	for _, matched := range tx.MatchedRules() {
		msg := matched.Message()
		if n, ok := parseScoreToken(msg, "Total Score: "); ok {
			blocking = n
		}
		if strings.Contains(msg, "ferroada_score") {
			if n, ok := parseScoreToken(msg, "blocking="); ok {
				blocking = n
			}
			if n, ok := parseScoreToken(msg, "detection="); ok {
				detection = n
			}
		}
	}
	if blocking > 0 {
		return blocking
	}
	return detection
}

func decodeBody(b64 string) []byte {
	if b64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	return raw
}

func splitHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if addr == "" {
			return "0.0.0.0", 0
		}
		return addr, 0
	}
	n := 0
	_, _ = fmt.Sscanf(port, "%d", &n)
	return host, n
}

func writeJSON(w http.ResponseWriter, status int, body inspectResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func readyCheck(socket string) error {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
	resp, err := client.Get("http://coraza/readyz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz HTTP %d", resp.StatusCode)
	}
	return nil
}
