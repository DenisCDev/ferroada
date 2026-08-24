import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(webRoot, "..", "assets", "dashboard.png");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

const child = spawn("npx", ["next", "dev", "-p", "3100"], {
  cwd: webRoot,
  shell: true,
  stdio: "pipe",
});

async function waitReady() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch("http://127.0.0.1:3100/", { signal: AbortSignal.timeout(1000) });
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
  const page = await browser.newPage({ viewport: { width: 1280, height: 980 } });
  await page.goto("http://127.0.0.1:3100/", { waitUntil: "networkidle" });
  await page.screenshot({ path: out, fullPage: false });
  await browser.close();
  process.stdout.write(`saved ${out}\n`);
} finally {
  child.kill();
}
