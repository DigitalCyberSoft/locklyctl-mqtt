// Screenshots of the operator console (internal/web/static/index.html) for the
// README, from the made-up data in mock.js: no server, no lock, nothing sent.
//   node tools/screenshots/screenshots.mjs [chrome-binary]
// Needs Node 22 or later and Chrome. Writes docs/screenshots/*.png, and exits
// non-zero when a step doesn't show up or something is wider than a phone's screen.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("../../", import.meta.url).pathname;
const html = readFileSync(join(root, "internal/web/static/index.html"));
const mock = readFileSync(new URL("./mock.js", import.meta.url), "utf8");
const out = join(root, "docs/screenshots");
mkdirSync(out, { recursive: true });

const desktop = { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false };
const phone = { width: 390, height: 844, deviceScaleFactor: 2, mobile: true };
// name, viewport, color scheme, what to show: the lock list with a lock open, or that lock's people
const shots = [
  ["console-desktop", desktop, "light", "lock"],
  ["console-phone", phone, "light", "list"],
  ["console-phone-lock", phone, "dark", "people"],
];

// The page alone, as the server's embedded file system serves it; mock.js answers its API calls.
const server = createServer((req, res) => {
  if (req.url === "/" || req.url === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
  } else {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/`;

const profile = mkdtempSync(join(tmpdir(), "lmq-shots-"));
const chrome = spawn(process.argv[2] || "google-chrome", ["--headless", "--disable-gpu", "--hide-scrollbars",
  "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
const wsUrl = await new Promise((resolve, reject) => {
  let buf = "";
  chrome.stderr.on("data", (d) => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) resolve(m[1]); });
  chrome.on("exit", () => reject(new Error("Chrome exited:\n" + buf)));
  chrome.on("error", reject);
});
const ws = new WebSocket(wsUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let nextId = 0;
const pending = new Map();
ws.addEventListener("message", (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
});
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId;
  pending.set(id, { resolve, reject });
  ws.send(JSON.stringify({ id, method, params, sessionId }));
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failed = 0;
try {
  for (const [name, view, scheme, show] of shots) {
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    const s = (m, p) => send(m, p, sessionId);
    const js = async (expr) => {
      const r = await s("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`${expr}: ${r.exceptionDetails.exception?.description}`);
      return r.result.value;
    };
    const until = async (what, expr) => {
      for (const end = Date.now() + 8000; Date.now() < end; await sleep(100)) if (await js(expr)) return;
      throw new Error(`${name}: ${what} never showed up`);
    };
    await s("Page.enable");
    await s("Emulation.setDeviceMetricsOverride", view);
    await s("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }] });
    await s("Page.addScriptToEvaluateOnNewDocument", { source: mock });
    await s("Page.navigate", { url });
    // Sign in through the page's own form, so the header names the operator.
    await until("the sign-in form", `!document.getElementById("loginView").classList.contains("hidden")`);
    await js(`document.getElementById("luser").value = "admin"; document.getElementById("lpass").value = "x";
      document.getElementById("loginBtn").click(); true`);
    await until("the lock list", `document.querySelectorAll("#locks td.clickable").length >= 5`);
    if (show !== "list") {
      await js(`[...document.querySelectorAll("#locks td.clickable")].find((td) => td.textContent.startsWith("2A Front")).click(); true`);
      await until("the lock's people", `document.querySelectorAll("#people tr").length === 4`);
    }
    if (show === "people") await js(`document.getElementById("lockCard").scrollIntoView({ block: "start" }); true`);
    await sleep(300);
    if (view.mobile) {
      const wide = await js(`[...document.querySelectorAll("body *")].filter((e) => e.offsetParent
        && e.getBoundingClientRect().right > ${view.width} + 1).map((e) => e.tagName + "#" + e.id + "." + e.className).slice(0, 5)`);
      if (wide.length) { failed++; console.log(`FAIL ${name}: wider than the screen: ${wide.join(", ")}`); }
    }
    const { data } = await s("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(out, `${name}.png`), Buffer.from(data, "base64"));
    console.log(`${name}.png  ${view.width}x${view.height}@${view.deviceScaleFactor}x  ${scheme}`);
    await send("Target.closeTarget", { targetId });
  }
} catch (e) {
  failed++;
  console.log("FAIL " + e.message);
} finally {
  ws.close();
  chrome.kill("SIGKILL");
  server.close();
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* already gone */ }
}
process.exit(failed ? 1 : 0);
