import { spawn } from "node:child_process";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(webRoot, "..", "assets", "dashboard.png");
const envLocal = join(webRoot, ".env.local");
const port = "3199";
const origin = `http://127.0.0.1:${port}`;
const webToken = "screenshot-token-16";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function spawnNext(args) {
  return spawn(process.execPath, ["node_modules/next/dist/bin/next", ...args], {
    cwd: webRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      FERROADA_ALLOW_DEMO: "false",
      FERROADA_WEB_TOKEN: webToken,
      FERROADA_URL: "http://127.0.0.1:9000",
      PORT: port,
    },
  });
}

const previousEnv = existsSync(envLocal) ? readFileSync(envLocal) : null;
writeFileSync(
  envLocal,
  [
    "FERROADA_URL=http://127.0.0.1:9000",
    "FERROADA_ALLOW_DEMO=false",
    `FERROADA_WEB_TOKEN=${webToken}`,
    "",
  ].join("\n"),
);

const build = spawnNext(["build"]);
await new Promise((resolve, reject) => {
  build.on("exit", (code) => {
    if (code === 0) resolve();
    else reject(new Error(`next build saiu ${code}`));
  });
});

const child = spawnNext(["start", "-p", port]);

async function waitReady() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${origin}/`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch {
      await sleep(500);
    }
  }
  throw new Error("next não subiu");
}

try {
  await waitReady();
  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: { width: 1280, height: 980 },
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
  });
  await page.addInitScript((token) => {
    sessionStorage.setItem("ferroada-web-token", token);
  }, webToken);
  await page.goto(`${origin}/`, { waitUntil: "networkidle" });
  await page.getByText("zero de propósito").waitFor({ timeout: 20_000 });
  const body = await page.locator("body").innerText();
  if (body.includes("demonstração") || body.includes("12.840") || body.includes("12840")) {
    throw new Error("screenshot ainda mostra demo");
  }
  await page.screenshot({ path: out, fullPage: false });
  await browser.close();
  process.stdout.write(`saved ${out}\n`);
} finally {
  child.kill();
  if (previousEnv === null) {
    try {
      unlinkSync(envLocal);
    } catch {
      // ignore
    }
  } else {
    writeFileSync(envLocal, previousEnv);
  }
}
