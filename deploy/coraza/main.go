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
	"syscall"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const defaultSocket = "/run/coraza/waf.sock"

type inspectRequest struct {
	Method   string     `json:"method"`
	URI      string     `json:"uri"`
	Protocol string     `json:"protocol"`
	Headers  [][]string `json:"headers"`
	BodyB64  string     `json:"body_b64"`
	ClientIP string     `json:"client_ip"`
}

type inspectResponse struct {
	Action  string `json:"action"`
	RuleIDs []uint `json:"rule_ids,omitempty"`
	Msg     string `json:"msg,omitempty"`
}

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
	// DetectionOnly in @coraza.conf-recommended would never interrupt.
	// SecRuleEngine On is enforcement, not PR 12 paranoia/shadow knobs.
	directives := `
Include @coraza.conf-recommended
SecRuleEngine On
SecResponseBodyAccess Off
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
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
		tx.AddRequestHeader(header[0], header[1])
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		writeDeny(w, tx, it)
		return
	}
	rawBody := decodeBody(req.BodyB64)
	if len(rawBody) > 0 {
		if it, _, err := tx.WriteRequestBody(rawBody); err != nil {
			writeJSON(w, http.StatusOK, inspectResponse{Action: "deny", Msg: "body write"})
			return
		} else if it != nil {
			writeDeny(w, tx, it)
			return
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		writeJSON(w, http.StatusOK, inspectResponse{Action: "deny", Msg: "body process"})
		return
	} else if it != nil {
		writeDeny(w, tx, it)
		return
	}
	writeJSON(w, http.StatusOK, inspectResponse{Action: "allow"})
}

func writeDeny(w http.ResponseWriter, tx types.Transaction, it *types.Interruption) {
	ids := uniqueRuleIDs(tx, it)
	msg := it.Data
	if msg == "" {
		msg = it.Action
	}
	writeJSON(w, http.StatusOK, inspectResponse{
		Action:  "deny",
		RuleIDs: ids,
		Msg:     msg,
	})
}

func uniqueRuleIDs(tx types.Transaction, it *types.Interruption) []uint {
	seen := map[int]struct{}{}
	var ids []uint
	add := func(id int) {
		if id <= 0 {
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
