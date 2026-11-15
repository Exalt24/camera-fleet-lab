// Loads the hub's dashboard in a real Chromium and checks that the strict Content-Security-Policy (script and style by hash, no
// 'unsafe-inline') blocks nothing the page needs: no CSP violation is reported, the script ran (the state badge left its "..." placeholder
// and the probe strip filled), and the styles were applied (the state badge is coloured by a CSS class, the legend squares come from a
// CSS variable). Local only: it refuses any address that is not 127.0.0.1 or localhost.
//
//   node security/vuln/csp_browser_check.cjs [http://127.0.0.1:8100/] [screenshot.png]      (set PLAYWRIGHT_PATH if `playwright` does not resolve)
const { chromium } = require(process.env.PLAYWRIGHT_PATH || "playwright");

const URL_ = process.argv[2] || "http://127.0.0.1:8100/";
const SHOT = process.argv[3];
if (!/^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(URL_)) throw new Error("refusing a non-local address: " + URL_);

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const violations = [];
  page.on("console", (m) => { if (/content security policy|refused to (apply|execute|load)/i.test(m.text())) violations.push(m.text()); });
  page.on("pageerror", (e) => violations.push("page error: " + e.message));
  await page.goto(URL_, { waitUntil: "load" });
  await page.waitForFunction(() => document.getElementById("state").textContent.trim() !== "...", null, { timeout: 15000 });
  await page.waitForFunction(() => document.querySelectorAll("#cells .cell").length > 0, null, { timeout: 15000 });
  const facts = await page.evaluate(() => {
    const color = (el) => getComputedStyle(el).color;
    const legendDot = getComputedStyle(document.querySelector(".legend .l-up"), "::before").backgroundColor;
    return {
      state: document.getElementById("state").textContent.trim(),
      cells: document.querySelectorAll("#cells .cell").length,
      stateColor: color(document.getElementById("state")),
      legendUpSquare: legendDot,
      whoHidden: getComputedStyle(document.getElementById("who")).display === "none",
      bodyBackground: getComputedStyle(document.body).backgroundColor,
    };
  });
  if (SHOT) await page.screenshot({ path: SHOT, fullPage: true });
  await browser.close();
  console.log(JSON.stringify({ url: URL_, violations, ...facts }, null, 2));
  const styled = facts.bodyBackground === "rgb(11, 16, 32)" && facts.legendUpSquare === "rgb(34, 197, 94)" && facts.whoHidden;
  const ok = violations.length === 0 && facts.cells > 0 && styled;
  console.log(ok ? "PASS: no CSP violation, the script ran and the styles applied" : "FAIL");
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
