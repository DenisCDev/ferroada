import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
await page.goto('http://localhost:3333', { waitUntil: 'networkidle' });
await page.waitForTimeout(4000);
await page.screenshot({ path: 'screenshot.png', fullPage: false });
console.log('Saved screenshot.png');
await browser.close();
