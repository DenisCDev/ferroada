import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { getMetrics, unavailableMetrics } from "./get-metrics";
import { metricsResultSchema } from "./types";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");

const LIVE = {
  requests_total: 7,
  blocked: { sqli: 1 },
  https_redirect: 0,
  waf_inspection: {
    complete: 7,
    truncated: 0,
    unsupported_encoding: 0,
    unsupported_content_type: 0,
  },
  waf_monitored: 0,
  dlp: { cpf_masked: 0, tokens_masked: 0 },
  recent_events: [] as [],
};

const saved = {
  url: process.env.FERROADA_URL,
  token: process.env.FERROADA_TOKEN,
  demo: process.env.FERROADA_ALLOW_DEMO,
};

afterEach(() => {
  restoreEnv("FERROADA_URL", saved.url);
  restoreEnv("FERROADA_TOKEN", saved.token);
  restoreEnv("FERROADA_ALLOW_DEMO", saved.demo);
});

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer(handler);
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("server did not bind a port"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((done, fail) => {
            server.closeAllConnections();
            server.close((err) => (err ? fail(err) : done()));
          }),
      });
    });
  });
}

test("unavailableMetrics is zeros, not demo, and matches the schema", () => {
  const payload = unavailableMetrics();
  assert.equal(payload.requests_total, 0);
  assert.equal(payload.demo, false);
  assert.equal(payload.unavailable, true);
  assert.equal(JSON.stringify(payload).includes("12840"), false);
  assert.equal(metricsResultSchema.safeParse(payload).success, true);
});

test("HTTP 401 keeps zeros and names the proxy token", async () => {
  delete process.env.FERROADA_ALLOW_DEMO;
  const { url, close } = await listen((_req, res) => {
    res.statusCode = 401;
    res.end("nope");
  });
  process.env.FERROADA_URL = url;
  try {
    const payload = await getMetrics();
    assert.equal(payload.demo, false);
    assert.equal(payload.unavailable, true);
    assert.equal(payload.requests_total, 0);
    assert.equal(payload.demo_reason, "unauthorized");
    assert.equal(JSON.stringify(payload).includes("12840"), false);
  } finally {
    await close();
  }
});

test("HTTP 503 does not invent 12840", async () => {
  delete process.env.FERROADA_ALLOW_DEMO;
  const { url, close } = await listen((_req, res) => {
    res.statusCode = 503;
    res.end("down");
  });
  process.env.FERROADA_URL = url;
  try {
    const payload = await getMetrics();
    assert.equal(payload.demo, false);
    assert.equal(payload.unavailable, true);
    assert.equal(payload.requests_total, 0);
    assert.equal(JSON.stringify(payload).includes("12840"), false);
  } finally {
    await close();
  }
});

test("timeout does not invent 12840", { timeout: 10_000 }, async () => {
  delete process.env.FERROADA_ALLOW_DEMO;
  const { url, close } = await listen(() => {
    // hang until the client aborts
  });
  process.env.FERROADA_URL = url;
  try {
    const payload = await getMetrics();
    assert.equal(payload.demo, false);
    assert.equal(payload.unavailable, true);
    assert.equal(payload.requests_total, 0);
    assert.equal(JSON.stringify(payload).includes("12840"), false);
  } finally {
    await close();
  }
});

test("FERROADA_ALLOW_DEMO=true is the only path to 12840", async () => {
  process.env.FERROADA_ALLOW_DEMO = "true";
  const { url, close } = await listen((_req, res) => {
    res.statusCode = 503;
    res.end("down");
  });
  process.env.FERROADA_URL = url;
  try {
    const payload = await getMetrics();
    assert.equal(payload.demo, true);
    assert.equal(payload.unavailable, false);
    assert.equal(payload.requests_total, 12840);
    assert.equal(payload.demo_reason, "unavailable");
  } finally {
    await close();
  }
});

test("a live proxy payload is not marked unavailable", async () => {
  delete process.env.FERROADA_ALLOW_DEMO;
  const { url, close } = await listen((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(LIVE));
  });
  process.env.FERROADA_URL = url;
  try {
    const payload = await getMetrics();
    assert.equal(payload.demo, false);
    assert.equal(payload.unavailable, false);
    assert.equal(payload.requests_total, 7);
    assert.equal(payload.blocked.sqli, 1);
  } finally {
    await close();
  }
});

test("web/.env.example lists the four canonical keys", () => {
  const text = readFileSync(join(webRoot, ".env.example"), "utf8");
  for (const key of ["FERROADA_URL", "FERROADA_TOKEN", "FERROADA_WEB_TOKEN", "FERROADA_ALLOW_DEMO"]) {
    assert.match(text, new RegExp(`^${key}=`, "m"));
  }
  assert.match(text, /^FERROADA_ALLOW_DEMO=false$/m);
  assert.equal(text.includes("# FERROADA_TOKEN="), false);
});

test("next.config.ts has no /proxy-metrics rewrite", () => {
  const text = readFileSync(join(webRoot, "next.config.ts"), "utf8");
  assert.equal(text.includes("proxy-metrics"), false);
  assert.equal(text.includes("rewrites"), false);
});
