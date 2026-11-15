// Drives the IAM stack in a real Chromium and saves a screenshot at each step: the login page, the forced OTP set up, the dashboard
// for an admin, the OTP prompt on an ordinary sign in, the dashboard for a viewer, and the 403 a viewer gets on the admin route.
// It is the browser-level twin of check_iam.py. Local only: it refuses any address that is not 127.0.0.1 or localhost.
//
//   node security/iam/shots.cjs [outdir]          (set PLAYWRIGHT_PATH if `playwright` does not resolve)
//
// Run `python security/iam/check_iam.py --reset-only` first so both sample users are back to "no OTP yet".
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { chromium } = require(process.env.PLAYWRIGHT_PATH || "playwright");

const PROXY = "http://127.0.0.1:4180/";
const OUT = path.resolve(process.argv[2] || path.join(__dirname, "..", "..", "docs", "security", "iam"));
const USERS = { admin: ["admin.sample", "AdminSample-2026"], viewer: ["viewer.sample", "ViewerSample-2026"] };
if (!/^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(PROXY)) throw new Error("refusing a non-local address: " + PROXY);
fs.mkdirSync(OUT, { recursive: true });

function totp(secret, atMs = Date.now()) {
  const counter = Math.floor(atMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac("sha1", Buffer.from(secret, "utf8")).update(buf).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 1000000).padStart(6, "0");
}
const counterNow = () => Math.floor(Date.now() / 1000 / 30);

// Poll for an element in 250 ms steps. When it does not appear, print the URL and the visible text so the failure shows what the
// page really was, then fail. Nothing is clicked on a page that has not shown the element first.
async function seen(page, selector, seconds = 8, state = "visible") {
  for (let i = 0; i < seconds * 4; i++) {
    if (await page.locator(selector).first().isVisible().catch(() => false)) return true;
    if (state === "attached" && (await page.locator(selector).count()) > 0) return true;
    await page.waitForTimeout(250);
  }
  const text = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ").slice(0, 300);
  throw new Error(`"${selector}" not on the page after ${seconds} s. url=${page.url()} text=${text}`);
}

async function signIn(page, who) {
  await page.goto(PROXY);
  await seen(page, "#username");
  await page.fill("#username", USERS[who][0]);
  await page.fill("#password", USERS[who][1]);
}

async function dashboardReady(page) {
  await seen(page, "#who");
  // the state badge shows "..." until the first /status answer arrives
  for (let i = 0; i < 40; i++) {
    const t = ((await page.textContent("#state")) || "...").trim();
    if (t !== "...") return t;
    await page.waitForTimeout(200);
  }
  return "...";
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const results = [];
  const note = (name, ok, detail) => { results.push({ name, ok }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}  [${detail}]`); };
  const shot = async (page, file) => { await page.screenshot({ path: path.join(OUT, file) }); console.log("saved " + file); };
  const ctxOpts = { viewport: { width: 1100, height: 760 }, colorScheme: "dark" };

  // 1. admin: login page, forced OTP set up, dashboard
  const admin = await (await browser.newContext(ctxOpts)).newPage();
  await signIn(admin, "admin");
  await shot(admin, "01-login-page.png");
  note("an unauthenticated visit to the dashboard lands on the Keycloak login", admin.url().startsWith("http://localhost:8180/realms/camera-fleet/"), admin.url().slice(0, 70));
  await admin.click("#kc-login");
  await seen(admin, "#totpSecret", 8, "attached");
  await shot(admin, "02-otp-setup-required.png");
  note("after the password, Keycloak demands OTP set up (the dashboard is not shown)", (await admin.locator("#kc-totp-settings").count()) === 1, admin.url().includes("CONFIGURE_TOTP") ? "required action CONFIGURE_TOTP" : admin.url());
  const secret = await admin.getAttribute("#totpSecret", "value");
  await admin.fill("#totp", totp(secret));
  await admin.click("#saveTOTPBtn");
  const state = await dashboardReady(admin);
  await shot(admin, "03-dashboard-admin.png");
  const who = (await admin.textContent("#who")).trim();
  note("a valid TOTP code reaches the dashboard, and it shows the admin identity", /admin\.sample.*fleet-admin/.test(who) && state !== "...", `${who}; monitor state ${state}`);
  const adminRoute = await admin.goto(PROXY + "admin/probe-config");
  note("the admin can open the admin route", adminRoute.status() === 200, "HTTP " + adminRoute.status());

  // 2. admin again in a fresh browser context: the OTP prompt (OTP is set up now)
  const fresh = await (await browser.newContext(ctxOpts)).newPage();
  await signIn(fresh, "admin");
  await fresh.click("#kc-login");
  await seen(fresh, "#otp");
  await shot(fresh, "04-otp-prompt.png");
  note("an ordinary sign in asks for the code after the password", (await fresh.locator("#otp").count()) === 1, "OTP prompt shown");
  const last = counterNow();
  while (counterNow() <= last) await fresh.waitForTimeout(250);    // Keycloak refuses a code it already accepted
  await fresh.fill("#otp", totp(secret));
  await fresh.click("#kc-login");
  const state2 = await dashboardReady(fresh);
  note("password plus the valid code reaches the dashboard", state2 !== "...", "monitor state " + state2);

  // 3. viewer: enrol, dashboard, then the admin route
  const viewer = await (await browser.newContext(ctxOpts)).newPage();
  await signIn(viewer, "viewer");
  await viewer.click("#kc-login");
  await seen(viewer, "#totpSecret", 8, "attached");
  const vsecret = await viewer.getAttribute("#totpSecret", "value");
  await viewer.fill("#totp", totp(vsecret));
  await viewer.click("#saveTOTPBtn");
  await dashboardReady(viewer);
  await shot(viewer, "05-dashboard-viewer.png");
  const vwho = (await viewer.textContent("#who")).trim();
  note("the viewer's dashboard shows the viewer role only", /viewer\.sample \(fleet-viewer\)/.test(vwho), vwho);
  const vr = await viewer.goto(PROXY + "admin/probe-config");
  await shot(viewer, "06-viewer-admin-route-403.png");
  note("a viewer asking for the admin route gets 403", vr.status() === 403, "HTTP " + vr.status());

  await browser.close();
  const passed = results.filter(r => r.ok).length;
  console.log(`browser checks passed: ${passed} of ${results.length}`);
  process.exit(passed === results.length ? 0 : 1);
})().catch(e => { console.error(e); process.exit(2); });
