package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestStripQueryAndFormParams(t *testing.T) {
	got := stripQueryParams("/login?user=a&password=1%27+OR+1%3D1&ok=1", []string{"password"})
	if got != "/login?user=a&ok=1" {
		t.Fatalf("query: %s", got)
	}
	body := stripBody(
		[]byte("user=a&password=evil&ok=1"),
		[][]string{{"content-type", "application/x-www-form-urlencoded"}},
		[]string{"password"},
	)
	if string(body) != "user=a&ok=1" {
		t.Fatalf("form: %s", body)
	}
}

func TestResolvePolicyExecutingNotEqualBlocking(t *testing.T) {
	p := resolvePolicy(&inspectPolicy{
		BlockingParanoia:      1,
		ExecutingParanoia:     4,
		AnomalyScoreThreshold: 5,
	})
	if p.BlockingParanoia == p.ExecutingParanoia {
		t.Fatalf("executing must differ from blocking: %+v", p)
	}
	if p.ExecutingParanoia != 4 || p.BlockingParanoia != 1 {
		t.Fatalf("got %+v", p)
	}
	raised := resolvePolicy(&inspectPolicy{ExecutingParanoia: 1, BlockingParanoia: 3, AnomalyScoreThreshold: 5})
	if raised.ExecutingParanoia < raised.BlockingParanoia {
		t.Fatalf("executing raised to blocking: %+v", raised)
	}
}

func testWAF(t *testing.T) coraza.WAF {
	t.Helper()
	// Mini ruleset so tests do not depend on CRS embed path separators.
	directives := `
SecRuleEngine On
SecRequestBodyAccess On
SecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.detection_inbound_anomaly_score=0"
SecAction "id:10009,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:x-ferroada-l1-blocking-paranoia,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:x-ferroada-l1-executing-paranoia,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:x-ferroada-l1-anomaly-threshold"
SecRule REQUEST_HEADERS:x-ferroada-l1-blocking-paranoia "@rx ^([1-4])$" "id:10010,phase:1,pass,nolog,t:none,capture,setvar:tx.blocking_paranoia_level=%{TX.1}"
SecRule REQUEST_HEADERS:x-ferroada-l1-executing-paranoia "@rx ^([1-4])$" "id:10011,phase:1,pass,nolog,t:none,capture,setvar:tx.detection_paranoia_level=%{TX.1}"
SecRule REQUEST_HEADERS:x-ferroada-l1-anomaly-threshold "@rx ^([1-9][0-9]{0,4})$" "id:10012,phase:1,pass,nolog,t:none,capture,setvar:tx.inbound_anomaly_score_threshold=%{TX.1}"
SecRule ARGS "@rx (?i)or 1=1" "id:942100,phase:2,pass,log,msg:'SQL Injection Attack',setvar:'tx.blocking_inbound_anomaly_score=+5'"
SecRule TX:DETECTION_PARANOIA_LEVEL "@ge 4" "id:920274,phase:2,pass,log,msg:'PL4 executing',chain"
	SecRule ARGS "@rx pl4probe" "t:none,setvar:'tx.detection_inbound_anomaly_score=+5'"
SecRule TX:BLOCKING_PARANOIA_LEVEL "@ge 4" "id:920275,phase:2,pass,log,msg:'PL4 blocking',chain"
	SecRule ARGS "@rx pl4probe" "t:none,setvar:'tx.blocking_inbound_anomaly_score=+5'"
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" "id:949110,phase:2,deny,t:none,msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})'"
SecRule TX:DETECTION_INBOUND_ANOMALY_SCORE "@ge 0" "id:10020,phase:2,pass,log,t:none,msg:'ferroada_score blocking=%{tx.blocking_inbound_anomaly_score} detection=%{tx.detection_inbound_anomaly_score}'"
`
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("testWAF: %v", err)
	}
	return waf
}

func TestInspectSQLiDeniesWithRuleIDAndScore(t *testing.T) {
	waf := testWAF(t)
	body, _ := json.Marshal(inspectRequest{
		Method:   "GET",
		URI:      "/search?q=1'+OR+1=1",
		Protocol: "HTTP/1.1",
		Headers: [][]string{
			{"host", "api.example"},
			{"user-agent", "Mozilla/5.0"},
			{"accept", "text/html"},
		},
		ClientIP: "192.0.2.8",
		Policy: &inspectPolicy{
			BlockingParanoia:      1,
			ExecutingParanoia:     1,
			AnomalyScoreThreshold: 5,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/inspect", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handleInspect(rec, req, waf)
	if rec.Code != 200 {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var out inspectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	if out.Action != "deny" {
		t.Fatalf("want deny, got %+v", out)
	}
	if len(out.RuleIDs) == 0 {
		t.Fatalf("expected CRS rule ids, got %+v", out)
	}
	if out.Score < 5 {
		t.Fatalf("expected anomaly score >= 5, got %+v", out)
	}
}

func TestInspectExcludedPasswordDoesNotSeeSQLi(t *testing.T) {
	waf := testWAF(t)
	payload := inspectRequest{
		Method:   "POST",
		URI:      "/login",
		Protocol: "HTTP/1.1",
		Headers: [][]string{
			{"host", "api.example"},
			{"user-agent", "Mozilla/5.0"},
			{"accept", "text/html"},
			{"content-type", "application/x-www-form-urlencoded"},
		},
		BodyB64:  "dXNlcj1hJnBhc3N3b3JkPTEnK09SKzE9MQ==", // user=a&password=1'+OR+1=1
		ClientIP: "192.0.2.8",
		Policy: &inspectPolicy{
			BlockingParanoia:      1,
			ExecutingParanoia:     1,
			AnomalyScoreThreshold: 5,
			ExcludeParameters:     []string{"password"},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/inspect", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handleInspect(rec, req, waf)
	var out inspectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	if out.Action != "allow" {
		t.Fatalf("excluded password SQLi must not deny: %+v", out)
	}
}

func TestInspectCleanPL1Allows(t *testing.T) {
	waf := testWAF(t)
	body, _ := json.Marshal(inspectRequest{
		Method:   "GET",
		URI:      "/",
		Protocol: "HTTP/1.1",
		Headers: [][]string{
			{"host", "api.example"},
			{"user-agent", "Mozilla/5.0"},
			{"accept", "text/html"},
		},
		ClientIP: "192.0.2.8",
		Policy: &inspectPolicy{
			BlockingParanoia:      1,
			ExecutingParanoia:     1,
			AnomalyScoreThreshold: 5,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/inspect", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handleInspect(rec, req, waf)
	var out inspectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	if out.Action != "allow" {
		t.Fatalf("clean PL1 traffic must allow, got %+v", out)
	}
	if rec.Body.String() != "" && strings.Contains(rec.Body.String(), `"action":"deny"`) {
		t.Fatalf("unexpected deny: %s", rec.Body.String())
	}
}

func inspectWithPolicy(t *testing.T, waf coraza.WAF, uri string, blocking, executing int) inspectResponse {
	t.Helper()
	body, _ := json.Marshal(inspectRequest{
		Method:   "GET",
		URI:      uri,
		Protocol: "HTTP/1.1",
		Headers: [][]string{
			{"host", "api.example"},
			{"user-agent", "Mozilla/5.0"},
			{"accept", "text/html"},
		},
		ClientIP: "192.0.2.8",
		Policy: &inspectPolicy{
			BlockingParanoia:      blocking,
			ExecutingParanoia:     executing,
			AnomalyScoreThreshold: 5,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/inspect", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handleInspect(rec, req, waf)
	var out inspectResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	return out
}

func TestExecutingParanoiaDoesNotBlockWhenBlockingIsLower(t *testing.T) {
	waf := testWAF(t)
	observe := inspectWithPolicy(t, waf, "/x?q=pl4probe", 1, 4)
	if observe.Action != "allow" {
		t.Fatalf("executing 4 / blocking 1 must allow, got %+v", observe)
	}
	hasExecuting := false
	for _, id := range observe.RuleIDs {
		if id == 920274 {
			hasExecuting = true
		}
		if id == 920275 {
			t.Fatalf("blocking-PL4 rule must not fire: %+v", observe)
		}
	}
	if !hasExecuting {
		t.Fatalf("executing PL4 rule must match, got %+v", observe)
	}
	block := inspectWithPolicy(t, waf, "/x?q=pl4probe", 4, 4)
	if block.Action != "deny" {
		t.Fatalf("blocking 4 must deny the same probe, got %+v", block)
	}
}

func TestReportableRuleIDDropsSetupNoise(t *testing.T) {
	if reportableRuleID(900990) || reportableRuleID(901200) || reportableRuleID(949059) || reportableRuleID(10020) {
		t.Fatal("setup/helper ids must not appear in inspect rule_ids")
	}
	if !reportableRuleID(942100) || !reportableRuleID(949110) {
		t.Fatal("attack and blocking-eval ids must be reported")
	}
}
