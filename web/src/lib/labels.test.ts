import assert from "node:assert/strict";
import { test } from "node:test";
import { eventAction } from "./labels";

test("eventAction does not stamp observations as blocked", () => {
  assert.deepEqual(eventAction("waf_monitor"), { label: "observado", kind: "observed" });
  assert.deepEqual(eventAction("waf_l1_shadow"), { label: "observado", kind: "observed" });
  assert.deepEqual(eventAction("openapi_observe"), { label: "observado", kind: "observed" });
  assert.deepEqual(eventAction("protocol_monitor"), { label: "observado", kind: "observed" });
  assert.deepEqual(eventAction("dlp_skip"), { label: "observado", kind: "observed" });
  assert.deepEqual(eventAction("https_redirect"), { label: "redirecionado", kind: "other" });
  assert.deepEqual(eventAction("policy_reload"), { label: "política", kind: "other" });
  assert.deepEqual(eventAction("policy_reload_rejected"), { label: "recusado", kind: "blocked" });
});

test("eventAction keeps blocks and DLP distinct", () => {
  assert.deepEqual(eventAction("sqli"), { label: "bloqueado", kind: "blocked" });
  assert.deepEqual(eventAction("dlp"), { label: "DLP", kind: "dlp" });
  assert.deepEqual(eventAction("range_removed"), { label: "DLP", kind: "dlp" });
  assert.deepEqual(eventAction("dlp_partial_block"), { label: "bloqueado", kind: "blocked" });
});
