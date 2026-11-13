/* Chrome CDP browser regression, Node 22+. No extra browser dependencies.
 * Run against serve_dashboard_fixture.py and a headless Chrome on :9229.
 * All credentials/evidence come from the isolated /tmp fixture, never .env.
 */
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");

const base = "http://127.0.0.1:8765";
let token;
const artifacts = path.resolve("docs/dashboard/screenshots");
fs.mkdirSync(artifacts, { recursive: true });
const results = [];
const errors = [];
const requests = [];
let socket;
let id = 0;
const pending = new Map();
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

async function readyFixture() {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const state = fs.readFileSync("/tmp/netagent-dashboard-qa-state", "utf8").trim();
    const candidate = fs.readFileSync(path.join(state, "token"), "utf8").trim();
    try {
      const response = await fetch(base + "/api/dashboard/v1/healthz", { headers: { Authorization: "Bearer " + candidate }, signal: AbortSignal.timeout(2000) });
      if (response.ok) { token = candidate; return; }
    } catch { /* The isolated fixture may still be starting. */ }
    await pause(100);
  }
  throw new Error("The isolated browser fixture did not become ready");
}

async function send(method, params = {}) {
  const current = ++id;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(current); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
    pending.set(current, { resolve: (r) => { clearTimeout(timer); resolve(r); }, reject });
    socket.send(JSON.stringify({ id: current, method, params }));
  });
}
async function evaluate(expression) {
  const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text + ": " + result.exceptionDetails.exception?.description);
  return result.result.value;
}
async function until(expression, timeout = 12000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await pause(100);
  }
  throw new Error("Browser condition timed out: " + expression);
}
async function navigate(route) {
  await send("Page.navigate", { url: base + route });
  await until(`location.pathname.replace(new RegExp('/$'), '') === ${JSON.stringify(route)} && document.readyState === 'complete' && !!document.querySelector('.page-heading h1')`);
  await until("!document.querySelector('.skeleton')");
  await pause(250);
  assert.equal(await evaluate("document.body.innerText.includes('اطلاعات در دسترس نیست')"), false, route + " shows an API error");
}
async function screenshot(name) {
  const png = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  fs.writeFileSync(path.join(artifacts, name + ".png"), Buffer.from(png.data, "base64"));
}
async function api(route, method = "GET", body) {
  const response = await fetch(base + route, { method, headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  assert.equal(response.ok, true, `${method} ${route} returned ${response.status}`);
  return response.json();
}
async function viewport(width, height) {
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 760 });
}

(async () => {
  await readyFixture();
  const inspect = process.argv.includes("--inspect");
  if (!inspect) {
    const previous = await (await fetch("http://127.0.0.1:9229/json/list")).json();
    for (const tab of previous.filter(t => t.type === "page" && t.url.startsWith(base))) await fetch("http://127.0.0.1:9229/json/close/" + tab.id);
  }
  const target = inspect
    ? (await (await fetch("http://127.0.0.1:9229/json/list")).json()).find(t => t.type === "page" && t.url.startsWith(base))
    : await (await fetch("http://127.0.0.1:9229/json/new?about:blank", { method: "PUT" })).json();
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const handler = pending.get(message.id);
      if (handler) { pending.delete(message.id); message.error ? handler.reject(new Error(message.error.message)) : handler.resolve(message.result); }
    } else if (message.method === "Runtime.exceptionThrown") {
      errors.push(message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text);
    } else if (message.method === "Log.entryAdded" && message.params.entry.level === "error") {
      errors.push(message.params.entry.text);
    } else if (message.method === "Network.requestWillBeSent") {
      requests.push({ method: message.params.request.method, url: message.params.request.url });
    }
  });
  await send("Runtime.enable"); await send("Page.enable"); await send("Network.enable"); await send("Log.enable");
  if (inspect) {
    console.log(await evaluate("({url: location.pathname, text: document.body.innerText.slice(0, 1500)})"));
    socket.close();
    return;
  }
  await send("Page.bringToFront");
  await viewport(1440, 1000);
  const bootstrap = await send("Page.addScriptToEvaluateOnNewDocument", { source: "localStorage.clear(); localStorage.setItem('netagent.theme', 'dark')" });
  await send("Page.navigate", { url: base + "/dashboard/security" });
  await until("!!document.querySelector('#admin-token')");
  await send("Page.removeScriptToEvaluateOnNewDocument", { identifier: bootstrap.identifier });
  assert.equal(await evaluate("document.documentElement.dataset.theme"), "dark");
  await screenshot("login-dark");
  await evaluate(`(() => { const input = document.querySelector('#admin-token'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(token)}); input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await pause(100);
  await evaluate("document.querySelector('.login-form button[type=submit]').click()");
  await until("!!document.querySelector('[role=switch]') && !document.querySelector('[role=switch]').disabled");
  assert.equal(await evaluate("document.documentElement.dir"), "rtl");
  let summary = await api("/api/admin/v1/security-ai");
  assert.equal(summary.auto_enabled, false);
  assert.equal(summary.counts.COMPLETED + summary.counts.PROCESSING + summary.counts.PENDING, 0);
  assert.equal(requests.filter((r) => r.method === "POST").length, 0);
  results.push({ scenario: "login and opening Security preserve default OFF and create zero jobs", passed: true });
  await screenshot("security-dark");

  await evaluate("document.querySelector('.quick-trigger').click()");
  await until("!!document.querySelector('dialog[open] .quick-search')");
  await screenshot("quick-navigation");
  await evaluate("(() => { const input = document.querySelector('.quick-search input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'SECURITY'); input.dispatchEvent(new Event('input', { bubbles: true })); })()");
  await until("document.querySelectorAll('.quick-result').length === 1");
  await evaluate("document.querySelector('.quick-result').click()");
  await until("!document.querySelector('dialog[open]')");
  results.push({ scenario: "quick navigator searches operational destinations and opens Security", passed: true });

  await evaluate("(() => { const input = document.querySelector('.security-search input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, '100%_rule'); input.dispatchEvent(new Event('input', { bubbles: true })); })()");
  await until("!!document.querySelector('button[aria-label=\"تحلیل با هوش مصنوعی هشدار 1\"]') && document.querySelectorAll('.security-table tbody tr').length === 1");
  assert.equal((await api('/api/alerts?q=100%25_rule&include_summary=true')).total, 1);
  assert.equal((await api('/api/admin/v1/security-ai')).counts.PENDING, 0);
  await screenshot("security-archive-search");
  await evaluate("document.querySelector('.filter-context button').click()");
  await until("document.querySelectorAll('.security-table tbody tr').length === 50");
  results.push({ scenario: "global literal search reaches an archived event beyond the first page without analysis", passed: true });

  const alert = (await api("/api/alerts?limit=1")).items[0];
  await evaluate(`document.querySelector('button[aria-label="تحلیل با هوش مصنوعی هشدار ${alert.id}"]').click()`);
  for (let tries = 0; tries < 40; tries++) {
    summary = await api("/api/admin/v1/security-ai");
    if (summary.counts.COMPLETED === 1) break;
    await pause(100);
  }
  assert.equal(summary.counts.COMPLETED, 1);
  assert.equal(summary.counts.PENDING, 0);
  assert.equal(summary.auto_enabled, false);
  await until(`document.querySelector('button[aria-label="تحلیل با هوش مصنوعی هشدار ${alert.id}"]').closest('tr').innerText.includes('تکمیل‌شده')`, 20000);
  await evaluate(`document.querySelector('button[aria-label="تحلیل با هوش مصنوعی هشدار ${alert.id}"]').click()`);
  await until("!!document.querySelector('dialog[open]')");
  assert.equal(await evaluate("document.querySelector('dialog[open]').innerText.includes('تحلیل آزمایشی:')"), true);
  assert.equal(requests.filter((r) => r.method === "POST" && r.url.includes("/analyze")).length, 1);
  await screenshot("security-analysis-dialog");
  await evaluate("document.querySelector('.nav-item').focus()");
  assert.equal(await evaluate("document.activeElement.matches('.nav-item')"), false, "background navigation must be inert while a modal is open");
  for (let i = 0; i < 6; i++) {
    await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
    await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
    // Native dialogs allow focus to reach browser chrome after the last
    // control; page controls behind the dialog must remain unreachable.
    assert.equal(await evaluate("document.activeElement === document.body || !document.hasFocus() || document.querySelector('dialog[open]').contains(document.activeElement)"), true, "dialog focuses a page control outside its modal boundary");
  }
  await send("Page.bringToFront");
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
  await until("!document.querySelector('dialog[open]')");
  results.push({ scenario: "manual OFF analysis processes one event, associates its result and repeated click opens accessible dialog", passed: true });

  await evaluate("document.querySelector('[role=switch]').click()");
  await until("document.querySelector('[role=switch]').getAttribute('aria-checked') === 'true'");
  const fresh = await api("/__qa__/event", "POST", {});
  for (let tries = 0; tries < 40; tries++) {
    summary = await api("/api/admin/v1/security-ai");
    if (summary.counts.COMPLETED === 2) break;
    await pause(100);
  }
  assert.equal(summary.counts.COMPLETED, 2);
  assert.equal((await api(`/api/admin/v1/ai-analyses?alert_ids=${fresh.alert_id}`)).items[0].status, "COMPLETED");
  await evaluate("document.querySelector('[role=switch]').click()");
  await until("document.querySelector('[role=switch]').getAttribute('aria-checked') === 'false'");
  const disabled = await api("/__qa__/event", "POST", {});
  await pause(1500);
  assert.equal((await api(`/api/admin/v1/ai-analyses?alert_ids=${disabled.alert_id}`)).items.length, 0);
  assert.equal((await api("/api/admin/v1/security-ai")).counts.COMPLETED, 2);
  results.push({ scenario: "UI toggle enables only fresh ingestion and OFF prevents the next automatic job", passed: true });

  const routes = ["", "/security", "/agents", "/discovery", "/pending", "/investigations", "/ai-activity", "/ai-knowledge", "/ai-actions", "/settings", "/agents/agt_qa_1", "/agents/agt_qa_3"];
  for (const route of routes) {
    await navigate("/dashboard" + route);
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), true, "Desktop overflow: " + route);
    results.push({ scenario: "desktop navigation " + (route || "/overview"), passed: true });
    if (["", "/agents", "/ai-knowledge"].includes(route)) await screenshot(route === "" ? "overview-dark" : route === "/agents" ? "agents-dark" : "knowledge-dark");
  }
  await navigate("/dashboard");
  await evaluate("document.querySelector('button[aria-label=\"تغییر پوسته\"]').click()");
  await until("document.documentElement.dataset.theme === 'light'");
  await screenshot("overview-light");
  await navigate("/dashboard/security"); await screenshot("security-light");
  for (const route of routes) {
    await navigate("/dashboard" + route);
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), true, "Light theme overflow: " + route);
  }
  results.push({ scenario: "every destination renders in the light theme", passed: true });
  await navigate("/dashboard/agents/agt_qa_1");
  for (const label of ["شبکه", "فعالیت‌ها", "عیب‌یابی", "ترافیک", "کنسول پایتون", "مدیریت"]) {
    await evaluate(`Array.from(document.querySelectorAll('.tab')).find(b => b.textContent === ${JSON.stringify(label)}).click()`);
    await until("!document.querySelector('.skeleton')");
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), true, "Agent workspace overflow: " + label);
    if (label === "کنسول پایتون") {
      assert.equal(await evaluate("getComputedStyle(document.querySelector('.terminal')).direction"), "ltr");
      assert.equal(await evaluate("getComputedStyle(document.querySelector('.terminal-input-row')).display"), "flex");
      await screenshot("console-light");
    }
  }
  results.push({ scenario: "every agent workspace tab opens, with an LTR console and styled input in light theme", passed: true });
  await evaluate("document.querySelector('button[aria-label=\"تغییر پوسته\"]').click()");
  await viewport(390, 844);
  for (const route of routes) {
    await navigate("/dashboard" + route);
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), true, "Mobile overflow: " + route);
    results.push({ scenario: "mobile navigation " + (route || "/overview"), passed: true });
  }
  await navigate("/dashboard/security");
  await screenshot("security-mobile");
  await evaluate("document.querySelector('.security-table').scrollIntoView()");
  await screenshot("security-table-mobile");
  await evaluate("document.querySelector('.nav-menu').click()");
  await until("!!document.querySelector('.sidebar.is-open')");
  assert.equal(await evaluate("document.querySelector('.sidebar nav').querySelectorAll('a').length"), 10);
  await screenshot("mobile-navigation");
  await evaluate("document.querySelector('.sidebar nav a[href=\"/dashboard/ai-knowledge\"]').click()");
  await until("!document.querySelector('.sidebar.is-open') && document.querySelector('.page-heading h1').innerText.includes('حافظه')");
  results.push({ scenario: "mobile drawer exposes every destination and closes after navigation", passed: true });
  for (const width of [768, 1024, 1920]) {
    await viewport(width, 1000);
    await navigate("/dashboard");
    assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), true, "Viewport overflow: " + width);
  }
  results.push({ scenario: "tablet, laptop and wide desktop layouts", passed: true });
  await viewport(1440, 1000);
  await navigate("/dashboard/security");
  await evaluate("document.querySelector('.security-table').scrollIntoView()");
  await screenshot("security-table-dark");
  assert.equal((await fetch(base + "/api/docs")).status, 200);
  assert.equal((await fetch(base + "/api/admin/v1/security-ai")).status, 401);
  // Knowledge expiry bookkeeping must not strand SQLite's transaction or
  // break a later security request after visiting the other workspaces.
  await evaluate(`document.querySelector('button[aria-label="تحلیل با هوش مصنوعی هشدار ${disabled.alert_id}"]').click()`);
  for (let tries = 0; tries < 60; tries++) {
    summary = await api("/api/admin/v1/security-ai");
    if (summary.counts.COMPLETED === 3) break;
    await pause(100);
  }
  assert.equal(summary.counts.COMPLETED, 3);
  assert.equal(summary.counts.PENDING + summary.counts.PROCESSING, 0);
  assert.equal(summary.auto_enabled, false);
  assert.equal((await api(`/api/admin/v1/ai-analyses?alert_ids=${disabled.alert_id}`)).items[0].status, "COMPLETED");
  assert.equal((await api("/api/admin/v1/ai-activity?limit=10")).items.length, 3);
  results.push({ scenario: "manual OFF analysis and AI Activity still work after visiting Knowledge and every workspace", passed: true });
  results.push({ scenario: "Persian docs, API authentication and AI Activity remain operational", passed: true });
  await navigate("/dashboard/security");
  await until(`document.querySelector('button[aria-label="تحلیل با هوش مصنوعی هشدار ${alert.id}"]').closest('tr').innerText.includes('تکمیل‌شده')`);
  const oldJob = (await api(`/api/admin/v1/ai-analyses?alert_ids=${alert.id}`)).items[0].job_id;
  await evaluate(`document.querySelector('button[aria-label="تحلیل با هوش مصنوعی هشدار ${alert.id}"]').click()`);
  await until("!!document.querySelector('dialog[open] .history-trigger')");
  const postsBeforeHistory = requests.filter(r => r.method === 'POST').length;
  await evaluate("document.querySelector('.history-trigger').click()");
  await until("document.querySelector('.history-panel').innerText.includes('تلاش قبلی ثبت نشده')");
  assert.equal(requests.filter(r => r.method === 'POST').length, postsBeforeHistory);
  await evaluate("Array.from(document.querySelector('dialog[open]').querySelectorAll('button')).find(b => b.textContent.includes('تحلیل مجدد')).click()");
  await until("document.querySelector('.history-entry')?.innerText.includes('تحلیل آزمایشی:')", 20000);
  for (let tries = 0; tries < 40; tries++) {
    const current = (await api(`/api/admin/v1/ai-analyses?alert_ids=${alert.id}`)).items[0];
    if (current.job_id !== oldJob && current.status === 'COMPLETED') break;
    await pause(100);
  }
  const current = (await api(`/api/admin/v1/ai-analyses?alert_ids=${alert.id}`)).items[0];
  assert.notEqual(current.job_id, oldJob);
  assert.equal(current.status, 'COMPLETED');
  await until("document.querySelector('dialog[open] .card.card-pad .badge')?.innerText.includes('تکمیل‌شده')", 20000);
  const history = await api(`/api/admin/v1/ai-analyses/${alert.id}/history?limit=20&offset=0`);
  assert.equal(history.total, 1);
  assert.equal(history.items[0].job_id, oldJob);
  assert.equal(history.items[0].alert_id, alert.id);
  summary = await api('/api/admin/v1/security-ai');
  assert.equal(summary.auto_enabled, false);
  assert.equal(summary.counts.COMPLETED, 3);
  assert.equal((await api('/api/admin/v1/ai-activity?limit=10')).items.length, 4);
  assert.equal(requests.filter(r => r.method === 'POST').length, postsBeforeHistory + 1);
  await screenshot('security-history-dark');
  await viewport(390, 844);
  assert.equal(await evaluate("document.querySelector('dialog[open]').scrollWidth <= document.querySelector('dialog[open]').clientWidth + 1"), true, 'History dialog overflow');
  await evaluate("document.querySelector('.history-entry').scrollIntoView({ block: 'center' })");
  await screenshot('security-history-mobile');
  await evaluate("document.querySelector('dialog[open] button[aria-label=\"بستن پنجره\"]').click()");
  results.push({ scenario: "history opens without analysis and explicit reanalysis preserves only the selected event's previous result on desktop and mobile", passed: true });
  await viewport(320, 720);
  for (const route of routes) {
    await navigate('/dashboard' + route);
    assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), true, 'Small mobile overflow: ' + route);
  }
  results.push({ scenario: "every destination retains RTL layout at 320 pixels", passed: true });
  await evaluate("document.querySelector('button[aria-label=\"خروج از داشبورد\"]').click()");
  await until("!!document.querySelector('#admin-token')");
  results.push({ scenario: "logout returns to the login screen", passed: true });
  assert.deepEqual(errors, [], "browser runtime or resource errors");
  fs.writeFileSync(path.resolve("docs/dashboard/browser-verification.json"), JSON.stringify({ timestamp: new Date().toISOString(), browser: (await send("Browser.getVersion")).product, environment: "isolated synthetic evidence/model, real FastAPI and browser", results, errors }, null, 2) + "\n");
  console.log(JSON.stringify({ passed: results.length, runtimeErrors: errors.length, screenshots: artifacts }));
  socket.close();
})().catch((error) => { console.error(error.message); if (socket) socket.close(); process.exitCode = 1; });
