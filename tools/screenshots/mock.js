// A stand-in for the operator API (/admin/api/*) behind the console
// (internal/web/static/index.html), for screenshots without a server or a lock.
// Made-up sample data only. screenshots.mjs loads it before the page's own
// script; it replaces fetch, so nothing leaves the browser. Each reply has the
// fields the real handler sends (internal/api/handlers_admin.go).
(() => {
  const now = Math.floor(Date.UTC(2026, 10, 1, 9, 0) / 1000);
  const day = 86400;
  const accounts = [
    { id: 1, email: "owner@example.com", createdAt: now - 40 * day },
    { id: 2, email: "tenant@example.com", createdAt: now - 12 * day },
  ];
  const lock = (id, name, owner, online, extra = {}) => ({
    id, deviceId: `aa00112233445566778899${(0xc0 + id).toString(16)}`, name, blename: `PGK728WRHK00432${id}`,
    model: "PGK728WRHK", tz: "+8:00", fwv: "1.14.34", ownerAccountId: owner, mqttClientId: `lock-${id}`,
    mqttUsername: `lock-${id}`, online, hidden: false, sortIndex: id, ...extra,
  });
  let locks = [
    lock(1, "2A Front", 1, true),
    lock(2, "2A Office", 1, true),
    lock(3, "3A", 1, false),
    lock(4, "1204", 1, true),
    lock(5, "2C Spare", 1, false, { hidden: true }),
    lock(6, "4C", 2, true, { sortIndex: 0 }),
  ];
  // The last deviceStateCallback values a lock sent (Hub.LastState), and its recent access-log events.
  const states = { 1: { LOCKED_STATUS: "1", MAGNET: "0" }, 2: { LOCKED_STATUS: "1", MAGNET: "0" },
    4: { LOCKED_STATUS: "0", MAGNET: "1" }, 6: { LOCKED_STATUS: "1", MAGNET: "0" } };
  const events = { 1: [{ tm: now - 3600, code: 12, pwdId: 2 }, { tm: now - 7200, code: 12, pwdId: 1 }] };
  const person = (id, lockId, name, userType, dateMode, enabled, extra = {}) => ({
    id, lockId, name, pwdId: id % 10, userId: id % 10, adminId: 0, hasPin: true, userType, dateMode,
    weekMask: dateMode === "weekly" ? 0x1f : 0, multiVerify: 1, enabled, ...extra,
  });
  let people = [
    person(11, 1, "Alex Owner", 0x22, "permanent", true),
    person(12, 1, "Dana", 0x42, "weekly", true),
    person(13, 1, "Cleaner", 0x42, "weekly", false),
    person(14, 1, "Sam (Saturday)", 0x12, "period", true, { startAt: now + 4 * day, endAt: now + 4 * day + 3 * 3600 }),
    person(21, 2, "Alex Owner", 0x22, "permanent", true),
    person(22, 2, "Dana", 0x42, "weekly", true),
    person(31, 3, "Alex Owner", 0x22, "permanent", true),
    person(41, 4, "Alex Owner", 0x22, "permanent", true),
    person(42, 4, "Jordan", 0x22, "permanent", true),
    person(61, 6, "Riley", 0x22, "permanent", true),
  ];
  const pushed = (l) => (l.online ? [true, "pushed to the lock"]
    : [false, "lock offline; change saved and will push when it reconnects"]);
  const ordered = () => [...locks].sort((a, b) => a.ownerAccountId - b.ownerAccountId || a.sortIndex - b.sortIndex);
  const reply = (status, body) => new Response(body === undefined ? null : JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } });

  const routes = [
    ["POST", /^\/admin\/api\/login$/, () => reply(200, { token: "mock-token", username: "admin" })],
    ["GET", /^\/admin\/api\/accounts$/, () => reply(200, { accounts })],
    ["POST", /^\/admin\/api\/accounts$/, (_, b) => {
      const a = { id: accounts.length + 1, email: b.email, createdAt: now };
      accounts.push(a);
      return reply(201, a);
    }],
    ["DELETE", /^\/admin\/api\/accounts\/(\d+)$/, (m) => {
      accounts.splice(accounts.findIndex((a) => a.id === +m[1]), 1);
      locks = locks.filter((l) => l.ownerAccountId !== +m[1]);
      return reply(204);
    }],
    ["GET", /^\/admin\/api\/locks$/, () => reply(200, { locks: ordered() })],
    ["POST", /^\/admin\/api\/locks\/order$/, (_, b) => {
      b.order.forEach((id, i) => { locks.find((l) => l.id === id).sortIndex = i; });
      return reply(204);
    }],
    ["POST", /^\/admin\/api\/locks\/(\d+)\/hidden$/, (m, b) => {
      const l = locks.find((x) => x.id === +m[1]);
      l.hidden = !!b.hidden;
      return reply(200, l);
    }],
    ["GET", /^\/admin\/api\/locks\/(\d+)$/, (m) => {
      const l = locks.find((x) => x.id === +m[1]);
      return reply(200, { ...l, ...(states[l.id] ? { state: states[l.id] } : {}), recentEvents: events[l.id] || [] });
    }],
    ["GET", /^\/admin\/api\/locks\/(\d+)\/people$/, (m) => reply(200, { people: people.filter((p) => p.lockId === +m[1]) })],
    ["POST", /^\/admin\/api\/locks\/(\d+)\/people$/, (m, b) => {
      const l = locks.find((x) => x.id === +m[1]);
      const p = person(100 + people.length, l.id, b.name, b.userType, b.dateMode || "permanent", b.enabled !== false,
        { pwdId: b.pwdId, userId: b.userId, hasPin: !!b.pin });
      people.push(p);
      const [synced, syncDetail] = pushed(l);
      return reply(201, { ...p, synced, syncDetail });
    }],
    ["POST", /^\/admin\/api\/people\/(\d+)\/enabled$/, (m, b) => {
      const p = people.find((x) => x.id === +m[1]);
      p.enabled = !!b.enabled;
      const [synced, syncDetail] = pushed(locks.find((l) => l.id === p.lockId));
      return reply(200, { ...p, synced, syncDetail });
    }],
    ["DELETE", /^\/admin\/api\/people\/(\d+)$/, (m) => {
      people = people.filter((p) => p.id !== +m[1]);
      return reply(204);
    }],
  ];

  window.fetch = async (url, opt = {}) => {
    const path = new URL(url, location.href).pathname;
    const method = (opt.method || "GET").toUpperCase();
    const body = opt.body ? JSON.parse(opt.body) : {};
    for (const [verb, re, handle] of routes) {
      const m = verb === method && re.exec(path);
      if (m) return handle(m, body);
    }
    return reply(404, { error: `the mock has no ${method} ${path}` });
  };
})();
