// Records the dashboard while the lab is broken two different ways and repaired, then writes demo/work/demo.webm. It takes no
// screenshots on purpose: frames of the clip would repeat the README's GIF. Local only: it refuses to touch anything but the lab on 127.0.0.1.
//   node demo/record.mjs
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_PATH || "C:/Users/Dax/AppData/Roaming/npm/node_modules/playwright");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const URL_ = "http://127.0.0.1:8100/";
if (!URL_.startsWith("http://127.0.0.1")) throw new Error("refusing to record anything but the local lab");
const WORK = path.join(ROOT, "demo", "work");
fs.mkdirSync(WORK, { recursive: true });

const edge = (...args) => {
  try { return execFileSync("docker", ["compose", "exec", "-T", "edge", ...args], { cwd: ROOT, encoding: "utf8" }); }
  catch (e) { return String(e.stdout || "") + String(e.stderr || ""); }
};
const DNAT = ["PREROUTING", "-i", "wg0", "-p", "tcp", "-m", "multiport", "--dports", "8554,8889", "-j", "DNAT", "--to-destination", "10.20.0.10"];
const BLOCK = ["-p", "udp", "--dport", "51820", "-j", "DROP"];

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1280, height: 720 }, colorScheme: "dark",
  recordVideo: { dir: WORK, size: { width: 1280, height: 720 } },
});
const page = await context.newPage();
const caption = (t) => page.evaluate((x) => window.setCaption(x), t);
const hold = (ms) => page.waitForTimeout(ms);
const stateIs = (s) => page.waitForFunction((want) => document.getElementById("state").textContent.trim().toLowerCase() === want, s, { timeout: 90000, polling: 250 });

try {
  await page.goto(URL_, { waitUntil: "domcontentloaded" });
  await stateIs("up");
  await caption("Steady state: the camera's video decodes through a WireGuard tunnel.");
  await hold(6500);

  await caption("Fault 1: the VPN drops. WireGuard UDP is blocked on the site router.");
  edge("iptables", "-I", "OUTPUT", "1", ...BLOCK);
  await stateIs("tunnel down");
  await caption("TUNNEL DOWN: no packet crosses the VPN, so the port and video layers are not even checked.");
  await hold(5500);

  await caption("Unblocked. WireGuard re-handshakes on its own.");
  edge("iptables", "-D", "OUTPUT", ...BLOCK);
  await stateIs("up"); await hold(3500);

  await caption("Fault 2: the NAT rule is removed. The tunnel itself stays healthy.");
  edge("iptables", "-t", "nat", "-D", ...DNAT);
  await stateIs("blocked");
  await caption("BLOCKED: packets cross the VPN but the camera port is silent. A different fault, a different fix.");
  await hold(6500);

  await caption("Restoring the NAT rule.");
  edge("iptables", "-t", "nat", "-A", ...DNAT);
  await stateIs("up");
  await caption("Back to UP. The monitor told the two faults apart from the outside.");
  await hold(4500);
} finally {
  // Leave the lab as it was found, whatever happened above.
  edge("iptables", "-D", "OUTPUT", ...BLOCK);
  if (/No chain|Bad rule|does a matching rule exist/i.test(edge("iptables", "-t", "nat", "-C", ...DNAT))) edge("iptables", "-t", "nat", "-A", ...DNAT);
  await context.close();
  await browser.close();
}
const vids = fs.readdirSync(WORK).filter((f) => f.endsWith(".webm")).map((f) => ({ f, t: fs.statSync(path.join(WORK, f)).mtimeMs })).sort((a, b) => b.t - a.t);
fs.renameSync(path.join(WORK, vids[0].f), path.join(WORK, "demo.webm"));
console.log("recorded", path.join(WORK, "demo.webm"));
