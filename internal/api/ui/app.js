"use strict";

const root = document.getElementById("app");

const ROLE_LABELS = {
  backup_admin: "Backup admin",
  backup_operator: "Backup scheduler",
  restore_operator: "Restore operator",
  security_officer: "Security officer",
  auditor: "Auditor",
  directory_admin: "Directory admin (helpdesk)",
};

const ROLE_HINTS = {
  backup_admin: "Takes snapshots and can delete them once their lock expires",
  backup_operator: "Service account that takes scheduled snapshots",
  restore_operator: "Previews and runs restores",
  security_officer: "Approves privileged restores and reviews flagged snapshots",
  auditor: "Reads snapshots and the audit log",
  directory_admin: "Manages users and groups, has no access to backups",
};

const OP_LABELS = {
  create_user: "Create user",
  update_user: "Restore user details",
  create_group: "Create group",
  update_group: "Restore group settings",
  add_member: "Add to group",
  remove_member: "Remove from group",
  delete_group: "Delete group",
  delete_user: "Delete user",
};

// Singular and plural phrasing for the preview summary, in execution order.
const OP_COUNTS = [
  ["create_user", "user to create", "users to create"],
  ["update_user", "user to update", "users to update"],
  ["create_group", "group to create", "groups to create"],
  ["update_group", "group to update", "groups to update"],
  ["add_member", "membership to add", "memberships to add"],
  ["remove_member", "membership to remove", "memberships to remove"],
  ["delete_group", "group to delete", "groups to delete"],
  ["delete_user", "user to delete", "users to delete"],
];

const NAV = [
  { route: "snapshots", label: "Snapshots", perm: "snapshot:read" },
  { route: "directory", label: "Directory", perm: "directory:read" },
  { route: "restore", label: "Restore", perm: "restore:plan" },
  { route: "approvals", label: "Approvals", perm: "snapshot:read" },
  { route: "audit", label: "Audit log", perm: "audit:read" },
];

const state = {
  token: loadToken(),
  me: null,
  health: { dev: false, source: "" },
  devAccounts: [],
  flash: null,
  pendingApprovals: 0,
  restore: freshRestore(),
};

function freshRestore() {
  return {
    snapshot: "", scope: "all", mode: "merge",
    users: new Set(), groups: new Set(),
    plan: null, pending: null, result: null,
  };
}

/* ---------- small helpers ---------- */

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function when(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

function can(perm) {
  return !!state.me && state.me.permissions.includes(perm);
}

function statusLabel(s) {
  return s === "suspicious" ? "Flagged" : "Clean";
}

function shortHash(h) {
  return h ? h.slice(0, 12) : "";
}

function loadToken() {
  try { return sessionStorage.getItem("idvault-token") || ""; } catch { return ""; }
}

function saveToken(t) {
  try {
    if (t) sessionStorage.setItem("idvault-token", t);
    else sessionStorage.removeItem("idvault-token");
  } catch { /* storage blocked: token lives for this page only */ }
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (state.token) opts.headers.Authorization = "Bearer " + state.token;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  return { status: res.status, ok: res.ok, data };
}

function errorText(r) {
  return (r.data && r.data.error) || `Request failed with status ${r.status}`;
}

function flash(kind, html) {
  state.flash = { kind, html };
}

/* ---------- routing ---------- */

function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query] = raw.split("?");
  const parts = path.split("/").filter(Boolean);
  return { name: parts[0] || "", arg: parts[1] || "", params: new URLSearchParams(query || "") };
}

let appNavigation = false;

// go keeps any flash message; clicking a link yourself clears it.
function go(hash) {
  if (location.hash === hash) {
    render();
  } else {
    appNavigation = true;
    location.hash = hash;
  }
}

window.addEventListener("hashchange", () => {
  if (!appNavigation) state.flash = null;
  appNavigation = false;
  render();
});

/* ---------- boot and sign in ---------- */

async function boot() {
  const h = await api("GET", "/healthz");
  if (h.ok) state.health = h.data;
  if (state.health.dev) {
    const p = await api("GET", "/v1/dev/principals");
    if (p.ok) state.devAccounts = p.data;
  }
  if (state.token) await loadMe();
  render();
}

async function loadMe() {
  const r = await api("GET", "/v1/whoami");
  if (r.ok) {
    state.me = r.data;
  } else {
    state.me = null;
    state.token = "";
    saveToken("");
  }
}

async function signIn(token) {
  state.token = token;
  await loadMe();
  if (!state.me) {
    flash("bad", "That token wasn't accepted. Check it and try again.");
    render();
    return;
  }
  saveToken(token);
  state.restore = freshRestore();
  state.flash = null;
  const first = NAV.find((n) => can(n.perm));
  go(first ? "#/" + first.route : "#/");
}

function signOut() {
  state.token = "";
  state.me = null;
  saveToken("");
  state.restore = freshRestore();
  state.flash = null;
  history.replaceState(null, "", location.pathname);
  render();
}

function viewSignIn() {
  const accounts = state.devAccounts.map((p) => `
    <button type="button" data-action="dev-signin" data-name="${esc(p.name)}">
      <strong>${esc(p.name)}</strong>
      <span class="r">${esc(ROLE_LABELS[p.roles[0]] || p.roles[0])}. ${esc(ROLE_HINTS[p.roles[0]] || "")}</span>
    </button>`).join("");

  return `
  <div class="signin">
    <div class="panel">
      <h1>Sign in to idvault</h1>
      <p class="hint">Backups of ${esc(state.health.source || "your directory")}</p>
      ${state.flash ? `<div class="notice ${state.flash.kind}"><p>${state.flash.html}</p></div>` : ""}
      <form data-form="token">
        <label class="field">
          <span>API token</span>
          <input type="password" name="token" autocomplete="off" required>
          <span class="hint">The server prints one token per account the first time it starts.</span>
        </label>
        <button class="primary" type="submit">Sign in</button>
      </form>
      ${state.health.dev ? `
        <h2 style="margin-top:1.75rem">Dev accounts</h2>
        <p class="hint">This server was started with <code>-dev</code>, so you can sign in as any sample account.</p>
        <div class="accounts">${accounts}</div>` : ""}
    </div>
    <p class="hint"><a href="/privacy">Privacy</a> &nbsp; <a href="/terms">Terms</a></p>
  </div>`;
}

/* ---------- frame ---------- */

function frame(route, body) {
  const links = NAV.filter((n) => can(n.perm)).map((n) => {
    const count = n.route === "approvals" && state.pendingApprovals && can("restore:approve")
      ? `<span class="count" title="Waiting for approval">${state.pendingApprovals}</span>` : "";
    const current = route === n.route ? ' aria-current="page"' : "";
    return `<a href="#/${n.route}"${current}>${esc(n.label)}${count}</a>`;
  }).join("");
  const role = state.me.roles.map((r) => ROLE_LABELS[r] || r).join(", ");
  return `
  <header class="top">
    <a class="brand" href="#/"><img src="/static/favicon.svg" alt="">idvault</a>
    <span class="domain">${esc(state.health.source)}</span>
    <div class="who">
      <span>Signed in as <strong>${esc(state.me.name)}</strong> <span class="role">${esc(role)}</span></span>
      <button type="button" data-action="signout">Sign out</button>
    </div>
  </header>
  <div class="shell">
    <nav class="side" aria-label="Sections">${links}</nav>
    <main id="main">
      ${state.flash ? `<div class="notice ${state.flash.kind}" role="status"><p>${state.flash.html}</p></div>` : ""}
      ${body}
    </main>
    <footer class="foot">
      <span>idvault</span>
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
    </footer>
  </div>`;
}

let renderSeq = 0;

async function render() {
  const seq = ++renderSeq;
  if (!state.me) {
    root.innerHTML = viewSignIn();
    return;
  }
  const route = parseRoute();
  const allowed = NAV.filter((n) => can(n.perm));
  let name = route.name;
  if (!allowed.some((n) => n.route === name)) {
    if (!allowed.length) {
      root.innerHTML = frame("", `<div class="panel"><p>Your account has no access to any part of the console.</p></div>`);
      return;
    }
    name = allowed[0].route;
  }

  if (can("restore:approve")) {
    const a = await api("GET", "/v1/approvals");
    if (a.ok) state.pendingApprovals = a.data.filter((x) => x.status === "pending").length;
  }

  let body;
  try {
    body = await VIEWS[name](route);
  } catch (err) {
    body = `<div class="notice bad"><p>Couldn't load this page: ${esc(err.message)}</p></div>`;
  }
  if (seq !== renderSeq) return; // a newer render started while we were loading
  root.innerHTML = frame(name, body);
  const focus = root.querySelector("[data-autofocus]");
  if (focus) focus.focus();
}

/* ---------- snapshots ---------- */

async function viewSnapshots(route) {
  const [list, clean] = await Promise.all([
    api("GET", "/v1/snapshots"),
    api("GET", "/v1/snapshots/last-clean"),
  ]);
  if (!list.ok) throw new Error(errorText(list));
  const snaps = list.data;
  const lastCleanId = clean.ok ? clean.data.id : "";

  const policies = can("policy:read") ? (await api("GET", "/v1/policies")).data || [] : [];
  const takeForm = can("snapshot:create") ? `
    <form class="row" data-form="take-snapshot">
      <label for="policy" class="hint">Policy</label>
      <select id="policy" name="policy">
        ${(policies.length ? policies : [{ name: "gold" }]).map((p) => `<option>${esc(p.name)}</option>`).join("")}
      </select>
      <button class="primary" type="submit">Take snapshot</button>
    </form>` : "";

  const head = `
    <div class="page-head">
      <div>
        <h1>Snapshots</h1>
        <p>Each bar is one snapshot. Taller bars changed more. Red bars were flagged by the detector.</p>
      </div>
      ${takeForm}
    </div>`;

  if (!snaps.length) {
    return head + `<div class="panel"><p class="empty">No snapshots yet. The scheduler takes one as soon as the server starts${can("snapshot:create") ? ", or you can take one now" : ""}.</p></div>`;
  }

  const selectedId = route.arg && snaps.some((s) => s.id === route.arg) ? route.arg : snaps[snaps.length - 1].id;

  const bars = snaps.map((s) => {
    let height;
    if (!s.parent_id) height = 40;
    else if (s.changed === 0) height = 5;
    else height = Math.min(108, 10 + Math.sqrt(s.changed) * 11);
    const cls = ["bar", s.status, s.policy === "pre-restore" ? "pre-restore" : "", s.id === lastCleanId ? "last-clean" : ""].join(" ");
    const label = `${when(s.created_at)}, ${statusLabel(s.status)}, ${s.parent_id ? plural(s.changed, "change") : "first snapshot"}`;
    return `<button type="button" class="${cls}" style="height:${height}px" data-action="select-snap" data-id="${esc(s.id)}"
      aria-pressed="${s.id === selectedId}" title="${esc(label)}" aria-label="${esc(label)}"></button>`;
  }).join("");

  const timeline = `
    <section class="timeline" aria-label="Snapshot timeline">
      <div class="bars">${bars}</div>
      <div class="axis"><span>${when(snaps[0].created_at)}</span><span>${when(snaps[snaps.length - 1].created_at)}</span></div>
      <div class="legend">
        <span style="--sw:var(--pine)">Clean</span>
        <span style="--sw:var(--crimson)">Flagged</span>
        <span style="--sw:var(--grey-bar)">Taken just before a restore</span>
        <span style="--sw:var(--ink)">Dark top edge: last clean snapshot</span>
      </div>
    </section>`;

  const d = await api("GET", "/v1/snapshots/" + encodeURIComponent(selectedId));
  if (!d.ok) throw new Error(errorText(d));
  return head + timeline + snapshotDetail(d.data, lastCleanId);
}

function snapshotDetail(s, lastCleanId) {
  const ch = s.changes || {};
  const rows = [
    ["Users added", ch.users_added], ["Users deleted", ch.users_deleted], ["Users changed", ch.users_modified],
    ["Users disabled", ch.users_disabled], ["Groups added", ch.groups_added], ["Groups deleted", ch.groups_deleted],
    ["Groups changed", ch.groups_modified],
    ["Added to a group", (ch.membership_added || []).map((m) => `${m.user_id} in ${m.group_id}`)],
    ["Removed from a group", (ch.membership_removed || []).map((m) => `${m.user_id} from ${m.group_id}`)],
  ].filter(([, v]) => v && v.length);

  const changes = !s.parent_id
    ? `<p class="hint">First snapshot, nothing to compare against.</p>`
    : rows.length === 0
      ? `<p class="hint">Nothing changed since the previous snapshot.</p>`
      : `<table><tbody>${rows.map(([k, v]) => `
          <tr><td>${esc(k)}</td><td class="num">${v.length}</td>
          <td><details><summary>Show</summary><span class="id">${v.map(esc).join(", ")}</span></details></td></tr>`).join("")}
        </tbody></table>`;

  const findings = (s.findings || []).length ? `
    <h3>What the detector found</h3>
    <ul class="findings">${s.findings.map((f) => `
      <li><span class="sev ${esc(f.severity)}">${esc(f.severity[0].toUpperCase() + f.severity.slice(1))}</span>${esc(f.message)}</li>`).join("")}
    </ul>` : "";

  const triageNote = s.triage ? `
    <div class="notice ${s.triage.status === "clean" ? "good" : "bad"}">
      <p>${esc(s.triage.by)} marked this snapshot ${esc(statusLabel(s.triage.status).toLowerCase())} on ${esc(when(s.triage.at))}: ${esc(s.triage.reason)}
      ${s.triage.status !== s.detected_status ? ` The detector had marked it ${esc(statusLabel(s.detected_status).toLowerCase())}.` : ""}</p>
    </div>` : "";

  const triageForm = can("snapshot:triage") ? `
    <form data-form="triage" data-id="${esc(s.id)}" class="panel">
      <h3>Review this snapshot</h3>
      <p class="hint">Overrule the detector, for example after a planned bulk offboarding. Your name and reason go in the audit log.</p>
      <div class="row" style="align-items:flex-end">
        <label class="field" style="margin:0"><span>Verdict</span>
          <select name="status">
            <option value="clean"${s.status === "clean" ? " selected" : ""}>Clean</option>
            <option value="suspicious"${s.status === "suspicious" ? " selected" : ""}>Flagged</option>
          </select>
        </label>
        <label class="field" style="margin:0;flex:1;min-width:14rem"><span>Reason</span>
          <input type="text" name="reason" required placeholder="Planned offboarding, ticket HR-2214">
        </label>
        <button type="submit">Save verdict</button>
      </div>
    </form>` : "";

  const actions = [
    `<button type="button" data-action="verify" data-id="${esc(s.id)}">Check integrity</button>`,
    can("restore:plan") ? `<a class="button" href="#/restore?snapshot=${encodeURIComponent(s.id)}">Restore from this snapshot</a>` : "",
    can("snapshot:delete") ? `<button type="button" class="danger" data-action="delete-snap" data-id="${esc(s.id)}">Delete snapshot</button>` : "",
  ].join("");

  return `
  <div class="split">
    <section class="panel">
      <h2>${esc(when(s.created_at))}</h2>
      <p class="status ${esc(s.status)}">${statusLabel(s.status)}${s.id === lastCleanId ? ", last clean snapshot" : ""}</p>
      ${triageNote}
      <dl class="facts">
        <dt>Snapshot</dt><dd class="id">${esc(s.id)}</dd>
        <dt>Policy</dt><dd>${esc(s.policy)}</dd>
        <dt>Contents</dt><dd>${plural(s.stats.users, "user")}, ${plural(s.stats.groups, "group")}</dd>
        <dt>Stored</dt><dd>${plural(s.stats.new_objects, "new record")}, ${s.stats.reused_objects} reused from earlier snapshots</dd>
        <dt>Locked until</dt><dd>${esc(when(s.locked_until))}</dd>
        <dt>Expires</dt><dd>${esc(when(s.expires_at))}</dd>
        <dt>Hash</dt><dd class="id" title="${esc(s.hash)}">${esc(shortHash(s.hash))}</dd>
      </dl>
      <div class="row">${actions}</div>
      <div id="snap-msg" style="margin-top:1rem"></div>
    </section>
    <section>
      <div class="panel">
        ${findings}
        <h3>Changes since the previous snapshot</h3>
        ${changes}
      </div>
      ${triageForm}
    </section>
  </div>`;
}

/* ---------- directory ---------- */

async function viewDirectory() {
  const r = await api("GET", "/v1/directory");
  if (!r.ok) throw new Error(errorText(r));
  const st = r.data;
  const groups = Object.values(st.groups).sort((a, b) => a.name.localeCompare(b.name));
  const users = Object.values(st.users).sort((a, b) => a.username.localeCompare(b.username));
  const groupsOf = {};
  for (const g of groups) for (const m of g.members) (groupsOf[m] ||= []).push(g);
  const writable = can("directory:write");

  const groupRows = groups.map((g) => `
    <tr>
      <td>${esc(g.name)} ${g.privileged ? '<span class="tag priv">Privileged</span>' : ""}</td>
      <td class="num">${g.members.length}</td>
      <td>${esc(g.description)}</td>
    </tr>`).join("");

  const userRows = users.map((u) => `
    <tr data-search="${esc((u.username + " " + u.display_name + " " + (u.attributes?.department || "")).toLowerCase())}">
      <td><span class="id">${esc(u.username)}</span></td>
      <td>${esc(u.display_name)}</td>
      <td>${esc(u.attributes?.title || "")}</td>
      <td>${u.enabled ? "Enabled" : '<span class="status suspicious">Disabled</span>'}</td>
      <td>${(groupsOf[u.id] || []).map((g) => `<span class="tag${g.privileged ? " priv" : ""}">${esc(g.name)}</span>`).join(" ")}</td>
      ${writable ? `<td><button type="button" class="danger" data-action="delete-user" data-id="${esc(u.id)}">Delete</button></td>` : ""}
    </tr>`).join("");

  const attack = writable && state.health.dev ? `
    <section class="panel">
      <h2>Simulate an attack</h2>
      <p>Uses this account to delete 25 users and the SG-Finance and SG-HR groups, then creates <span class="id">svc-patchmgr</span> and adds it to Domain Admins. Only available on a <code>-dev</code> server.</p>
      <button type="button" class="danger" data-action="attack">Run the attack</button>
    </section>` : "";

  return `
    <div class="page-head">
      <div>
        <h1>Directory</h1>
        <p>The live state of ${esc(state.health.source)}: ${plural(users.length, "user")} and ${plural(groups.length, "group")}.</p>
      </div>
    </div>
    ${attack}
    <section class="panel">
      <h2>Groups</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th class="num">Members</th><th>Description</th></tr></thead>
        <tbody>${groupRows || '<tr><td colspan="3" class="empty">No groups.</td></tr>'}</tbody>
      </table></div>
    </section>
    <section class="panel">
      <div class="row" style="justify-content:space-between;margin-bottom:0.75rem">
        <h2>Users</h2>
        <input type="text" data-filter="users" placeholder="Filter by name or department" aria-label="Filter users">
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Username</th><th>Name</th><th>Title</th><th>Status</th><th>Groups</th>${writable ? "<th></th>" : ""}</tr></thead>
        <tbody id="user-rows">${userRows || '<tr><td colspan="6" class="empty">No users.</td></tr>'}</tbody>
      </table></div>
    </section>`;
}

/* ---------- restore ---------- */

async function viewRestore(route) {
  const rs = state.restore;
  const [list, clean] = await Promise.all([api("GET", "/v1/snapshots"), api("GET", "/v1/snapshots/last-clean")]);
  if (!list.ok) throw new Error(errorText(list));
  const snaps = list.data.slice().reverse();
  if (!snaps.length) {
    return `<div class="page-head"><div><h1>Restore</h1></div></div><div class="panel"><p class="empty">There are no snapshots to restore from yet.</p></div>`;
  }
  const lastCleanId = clean.ok ? clean.data.id : "";

  const wanted = route.params.get("snapshot");
  if (wanted && wanted !== rs.snapshot && snaps.some((s) => s.id === wanted)) {
    state.restore = freshRestore();
    state.restore.snapshot = wanted;
  }
  const r = state.restore;
  if (!r.snapshot || !snaps.some((s) => s.id === r.snapshot)) r.snapshot = lastCleanId || snaps[0].id;

  const contents = await api("GET", `/v1/snapshots/${encodeURIComponent(r.snapshot)}/contents`);
  if (!contents.ok) throw new Error(errorText(contents));
  const target = contents.data;
  let current = null;
  if (can("directory:read")) {
    const c = await api("GET", "/v1/directory");
    if (c.ok) current = c.data;
  }

  const options = snaps.map((s) => `
    <option value="${esc(s.id)}"${s.id === r.snapshot ? " selected" : ""}>
      ${esc(when(s.created_at))}, ${statusLabel(s.status)}${s.id === lastCleanId ? " (last clean)" : ""}${s.policy === "pre-restore" ? " (before a restore)" : ""}
    </option>`).join("");

  const users = Object.values(target.users).sort((a, b) => a.username.localeCompare(b.username));
  const groups = Object.values(target.groups).sort((a, b) => a.name.localeCompare(b.name));
  const gone = (kind, id) => current && !current[kind][id] ? ' <span class="gone">deleted since</span>' : "";

  const userPicks = users.map((u) => `
    <label data-search="${esc((u.username + " " + u.display_name).toLowerCase())}">
      <input type="checkbox" name="user" value="${esc(u.id)}"${r.users.has(u.id) ? " checked" : ""}>
      <span><span class="id">${esc(u.username)}</span> ${esc(u.display_name)}${gone("users", u.id)}</span>
    </label>`).join("");
  const groupPicks = groups.map((g) => `
    <label>
      <input type="checkbox" name="group" value="${esc(g.id)}"${r.groups.has(g.id) ? " checked" : ""}>
      <span>${esc(g.name)} ${g.privileged ? '<span class="tag priv">Privileged</span>' : ""}${gone("groups", g.id)}</span>
    </label>`).join("");

  const selected = snaps.find((s) => s.id === r.snapshot);
  const flaggedWarning = selected.status === "suspicious"
    ? `<div class="notice warn"><p>This snapshot was flagged. Restoring it could bring back what the attacker changed. The last clean snapshot is usually the right choice.</p></div>` : "";

  return `
    <div class="page-head">
      <div>
        <h1>Restore</h1>
        <p>Preview what a restore will change before you run it.</p>
      </div>
    </div>
    <form class="panel" data-form="plan">
      <label class="field">
        <span>Restore from</span>
        <select name="snapshot" data-action-change="pick-snapshot">${options}</select>
      </label>
      ${flaggedWarning}

      <div class="field"><span>What to restore</span></div>
      <div class="choices">
        <label class="choice"><input type="radio" name="scope" value="all"${r.scope === "all" ? " checked" : ""}>
          <strong>Everything</strong><small>All users, groups and memberships in the snapshot.</small></label>
        <label class="choice"><input type="radio" name="scope" value="some"${r.scope === "some" ? " checked" : ""}>
          <strong>Only what I select</strong><small>Restored users also get their group memberships back.</small></label>
      </div>

      <div id="pickers" class="split" ${r.scope === "some" ? "" : "hidden"} style="margin-bottom:1rem">
        <div>
          <div class="row" style="justify-content:space-between;margin-bottom:0.4rem">
            <strong>Users</strong>
            <input type="text" data-filter="picker" placeholder="Filter" aria-label="Filter users to restore">
          </div>
          <div class="picker" id="user-picker">${userPicks}</div>
        </div>
        <div>
          <strong style="display:block;margin-bottom:0.4rem;line-height:2.1">Groups</strong>
          <div class="picker">${groupPicks}</div>
        </div>
      </div>

      <div class="field"><span>How</span></div>
      <div class="choices">
        <label class="choice"><input type="radio" name="mode" value="merge"${r.mode === "merge" ? " checked" : ""}>
          <strong>Bring back what's missing</strong><small>Recreates deleted items and undoes changes. Never deletes anything.</small></label>
        <label class="choice"><input type="radio" name="mode" value="exact"${r.mode === "exact" ? " checked" : ""}>
          <strong>Match the snapshot exactly</strong><small>Also removes anything added since, such as accounts an attacker created.</small></label>
      </div>

      <button class="primary" type="submit">Preview restore</button>
    </form>
    <div id="plan-out">${planPanel(target, current)}</div>`;
}

function nameOf(st, kind, id) {
  if (!id) return "";
  const x = st && st[kind] && st[kind][id];
  if (!x) return "";
  return kind === "users" ? x.username : x.name;
}

function planPanel(target, current) {
  const r = state.restore;
  if (!r.plan) return "";
  const p = r.plan;
  p.ops = p.ops || [];
  p.counts = p.counts || {};
  const lookup = (kind, id) => nameOf(target, kind, id) || nameOf(current, kind, id) || id;

  let out = "";
  if (r.result) out += r.result;

  if (!p.ops.length) {
    return out + `<div class="panel"><p>Nothing to restore. The directory already matches this snapshot for what you selected.</p></div>`;
  }

  const counts = OP_COUNTS.filter(([k]) => p.counts[k])
    .map(([k, one, many]) => `${p.counts[k]} ${p.counts[k] === 1 ? one : many}`).join(", ");
  const opRow = (o) => `
    <tr class="${o.privileged ? "privileged" : ""}">
      <td>${esc(OP_LABELS[o.kind] || o.kind)}</td>
      <td>${o.user_id ? `<span class="id">${esc(lookup("users", o.user_id))}</span>` : ""}</td>
      <td>${o.group_id ? esc(lookup("groups", o.group_id)) : ""}</td>
      <td>${o.privileged ? '<span class="tag priv">Privileged</span>' : ""}</td>
    </tr>`;
  const table = (ops) => `<div class="table-wrap"><table>
        <thead><tr><th>Change</th><th>User</th><th>Group</th><th></th></tr></thead>
        <tbody>${ops.map(opRow).join("")}</tbody>
      </table></div>`;
  // Long plans: show the privileged changes up front, the rest on request.
  const priv = p.ops.filter((o) => o.privileged);
  const opsHtml = p.ops.length <= 20
    ? table(p.ops)
    : `${priv.length ? `<h3 style="margin:1rem 0 0.4rem">Privileged changes</h3>${table(priv)}` : ""}
       <details style="margin-top:1rem"><summary>Show all ${p.ops.length} changes</summary>${table(p.ops)}</details>`;

  const warnings = (p.warnings || []).map((w) => `<p>${esc(w)}</p>`).join("");

  let runArea = "";
  if (!can("restore:execute")) {
    runArea = `<p class="hint">Your role can preview restores but not run them.</p>`;
  } else if (r.pending) {
    const a = r.pending;
    const votes = a.approvals.length ? ": " + a.approvals.map((v) => esc(v.by)).join(", ") : "";
    runArea = `
      <div class="notice ${a.status === "approved" ? "good" : "warn"}">
        <p>${a.status === "approved"
          ? `Approved by ${a.approvals.map((v) => esc(v.by)).join(" and ")}. You can run the restore now.`
          : `Waiting for approval. ${a.approvals.length} of ${a.required} security officers have approved${votes}.`}
        Request <span class="id">${esc(a.id)}</span>.</p>
      </div>
      <div class="row">
        <button type="button" data-action="check-approval">Check approval</button>
        <button type="button" class="primary" data-action="run-restore"${a.status === "approved" ? "" : " disabled"}>Run restore</button>
      </div>`;
  } else {
    runArea = `<button type="button" class="primary" data-action="run-restore">${p.privileged ? "Request approval" : "Run restore"}</button>`;
  }

  return out + `
    <section class="panel" aria-label="Restore preview">
      <h2>Preview: ${plural(p.ops.length, "change")}</h2>
      <p>${esc(counts)}.</p>
      ${p.privileged ? `<div class="notice warn"><p>This restore changes privileged groups, so two security officers have to approve it before it runs.</p></div>` : ""}
      ${warnings ? `<div class="notice warn">${warnings}</div>` : ""}
      ${opsHtml}
      <div style="margin-top:1rem">${runArea}</div>
    </section>`;
}

function restoreBody() {
  const r = state.restore;
  const body = { snapshot_id: r.snapshot, mode: r.mode, scope: {} };
  if (r.scope === "some") {
    body.scope = { users: [...r.users], groups: [...r.groups] };
  }
  return body;
}

function readPlanForm(form) {
  const r = state.restore;
  const fd = new FormData(form);
  r.snapshot = fd.get("snapshot");
  r.scope = fd.get("scope");
  r.mode = fd.get("mode");
  r.users = new Set(fd.getAll("user"));
  r.groups = new Set(fd.getAll("group"));
}

async function previewRestore() {
  const r = state.restore;
  if (r.scope === "some" && !r.users.size && !r.groups.size) {
    flash("bad", "Select at least one user or group, or choose Everything.");
    r.plan = null;
    return render();
  }
  const res = await api("POST", "/v1/restores/plan", restoreBody());
  state.flash = null;
  r.result = null;
  if (!res.ok) {
    r.plan = null;
    flash("bad", esc(errorText(res)));
  } else {
    r.plan = res.data;
    r.pending = null;
    // Pick up an earlier request for this exact plan, e.g. after signing out and back in.
    if (r.plan.privileged) {
      const a = await api("GET", "/v1/approvals");
      if (a.ok) {
        const live = a.data.filter((x) => x.resource === r.plan.hash && x.requester === state.me.name &&
          (x.status === "pending" || x.status === "approved") && new Date(x.expires_at) > new Date());
        if (live.length) r.pending = live[live.length - 1];
      }
    }
  }
  render();
}

async function runRestore() {
  const r = state.restore;
  const body = restoreBody();
  if (r.pending) body.approval_id = r.pending.id;
  const res = await api("POST", "/v1/restores", body);

  if (res.status === 202) {
    r.pending = res.data.approval;
    r.result = "";
  } else if (res.ok && res.data.status === "noop") {
    r.result = `<div class="notice good"><p>Nothing to do. The directory already matches the snapshot.</p></div>`;
    r.plan = res.data.plan;
    r.pending = null;
  } else if (res.ok) {
    const n = res.data.result.applied;
    const pre = res.data.pre_restore_snapshot;
    const failed = res.data.result.failed;
    r.result = `<div class="notice ${failed ? "bad" : "good"}"><p>Restore finished: ${plural(n, "change")} applied${failed ? `, ${failed} failed. Preview again and rerun to finish` : ""}.
      Before it ran, idvault saved the previous state as <a href="#/snapshots/${encodeURIComponent(pre)}" class="id">${esc(pre)}</a>, so you can undo it.</p></div>`;
    r.pending = null;
    const again = await api("POST", "/v1/restores/plan", restoreBody());
    if (again.ok) r.plan = again.data;
  } else {
    const msg = errorText(res);
    let text = esc(msg);
    if (msg.includes("plan changed")) {
      text = "The directory changed after this restore was approved, so it's no longer the same restore. Preview it again and request a new approval.";
    } else if (msg.includes("already used")) {
      text = "That approval has already been used. Request a new one.";
    }
    r.result = `<div class="notice bad"><p>${text}</p></div>`;
    r.pending = null;
  }
  render();
}

async function checkApproval() {
  const r = state.restore;
  if (!r.pending) return;
  const res = await api("GET", "/v1/approvals");
  if (res.ok) {
    const a = res.data.find((x) => x.id === r.pending.id);
    if (a) r.pending = a;
  }
  render();
}

/* ---------- approvals ---------- */

async function viewApprovals() {
  const r = await api("GET", "/v1/approvals");
  if (!r.ok) throw new Error(errorText(r));
  const list = r.data.slice().reverse();
  const me = state.me.name;

  const rows = list.map((a) => {
    const expired = a.status === "pending" && new Date(a.expires_at) < new Date();
    const status = expired ? "expired" : a.status;
    const voted = a.approvals.some((v) => v.by === me);
    let action = "";
    if (can("restore:approve") && status === "pending") {
      if (a.requester === me) action = '<span class="hint">Your request</span>';
      else if (voted) action = '<span class="hint">You approved</span>';
      else action = `<button type="button" class="primary" data-action="approve" data-id="${esc(a.id)}">Approve</button>`;
    }
    return `
      <tr>
        <td><span class="id">${esc(a.id)}</span></td>
        <td>${esc(a.summary)}</td>
        <td>${esc(a.requester)}<br><span class="hint">${esc(when(a.created_at))}</span></td>
        <td>${a.approvals.length} of ${a.required}${a.approvals.length ? `<br><span class="hint">${a.approvals.map((v) => esc(v.by)).join(", ")}</span>` : ""}</td>
        <td><span class="status ${status === "pending" ? "pending" : status === "approved" || status === "consumed" ? "clean" : "suspicious"}">${esc({ pending: "Waiting", approved: "Approved", consumed: "Used", expired: "Expired" }[status])}</span></td>
        <td>${action}</td>
      </tr>`;
  }).join("");

  return `
    <div class="page-head">
      <div>
        <h1>Approvals</h1>
        <p>Restores that change privileged groups need two security officers. Nobody can approve their own request.</p>
      </div>
    </div>
    <section class="panel">
      ${list.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Request</th><th>Restore</th><th>Requested by</th><th>Approvals</th><th>Status</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
        : `<p class="empty">No approval requests. They appear here when a restore operator asks to run a privileged restore.</p>`}
    </section>`;
}

/* ---------- audit ---------- */

async function viewAudit(route) {
  const r = await api("GET", "/v1/audit");
  if (!r.ok) throw new Error(errorText(r));
  const only = route.params.get("show") || "all";
  const entries = r.data.slice().reverse().filter((e) => only === "all" || e.outcome === only);
  const rows = entries.map((e) => `
    <tr class="${e.outcome === "denied" ? "denied" : ""}">
      <td class="num">${e.seq}</td>
      <td style="white-space:nowrap">${esc(when(e.time))}</td>
      <td>${esc(e.actor)}</td>
      <td><span class="id">${esc(e.action)}</span></td>
      <td><span class="id">${esc(e.target || "")}</span></td>
      <td>${esc({ ok: "OK", denied: "Denied", error: "Error" }[e.outcome] || e.outcome)}</td>
      <td>${esc(e.detail || "")}</td>
    </tr>`).join("");

  return `
    <div class="page-head">
      <div>
        <h1>Audit log</h1>
        <p>Every request, including refused ones. Each entry includes the hash of the one before it, so edits and deletions show up when you check the chain.</p>
      </div>
      <div class="row">
        <select data-action-change="audit-filter" aria-label="Show">
          <option value="all"${only === "all" ? " selected" : ""}>All entries</option>
          <option value="denied"${only === "denied" ? " selected" : ""}>Denied only</option>
          <option value="error"${only === "error" ? " selected" : ""}>Errors only</option>
        </select>
        <button type="button" data-action="verify-audit">Check the chain</button>
      </div>
    </div>
    <div id="audit-msg"></div>
    <section class="panel">
      ${entries.length ? `<div class="table-wrap"><table>
        <thead><tr><th class="num">#</th><th>Time</th><th>Account</th><th>Action</th><th>Target</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>${rows}</tbody></table></div>` : `<p class="empty">No entries match.</p>`}
    </section>`;
}

const VIEWS = {
  snapshots: viewSnapshots,
  directory: viewDirectory,
  restore: viewRestore,
  approvals: viewApprovals,
  audit: viewAudit,
};

/* ---------- events ---------- */

const ACTIONS = {
  "dev-signin": (el) => signIn("dev-" + el.dataset.name),
  signout: () => signOut(),
  "select-snap": (el) => go("#/snapshots/" + encodeURIComponent(el.dataset.id)),

  async verify(el) {
    const out = document.getElementById("snap-msg");
    out.innerHTML = `<p class="hint">Checking every record</p>`;
    const r = await api("GET", `/v1/snapshots/${encodeURIComponent(el.dataset.id)}/verify`);
    if (!r.ok) {
      out.innerHTML = `<div class="notice bad"><p>${esc(errorText(r))}</p></div>`;
    } else if (r.data.ok) {
      out.innerHTML = `<div class="notice good"><p>All ${r.data.objects_checked} records match their hashes and the snapshot hasn't been modified.</p></div>`;
    } else {
      out.innerHTML = `<div class="notice bad"><p>This snapshot has been tampered with or damaged. Don't restore from it.</p>
        <ul>${r.data.problems.map((p) => `<li class="id">${esc(p)}</li>`).join("")}</ul></div>`;
    }
  },

  async "delete-snap"(el) {
    if (el.dataset.armed !== "1") {
      el.dataset.armed = "1";
      el.textContent = "Click again to delete";
      return;
    }
    const r = await api("DELETE", "/v1/snapshots/" + encodeURIComponent(el.dataset.id));
    if (r.status === 204) {
      flash("good", "Snapshot deleted. Its records are removed at the next cleanup.");
      go("#/snapshots");
    } else if (r.status === 409) {
      document.getElementById("snap-msg").innerHTML =
        `<div class="notice bad"><p>This snapshot is locked and can't be deleted by anyone until the lock expires.</p></div>`;
      el.dataset.armed = "";
      el.textContent = "Delete snapshot";
    } else {
      document.getElementById("snap-msg").innerHTML = `<div class="notice bad"><p>${esc(errorText(r))}</p></div>`;
    }
  },

  async "delete-user"(el) {
    if (el.dataset.armed !== "1") {
      el.dataset.armed = "1";
      el.textContent = "Confirm";
      return;
    }
    const r = await api("DELETE", "/v1/directory/users/" + encodeURIComponent(el.dataset.id));
    if (r.ok) flash("good", "User deleted.");
    else flash("bad", esc(errorText(r)));
    render();
  },

  async attack(el) {
    el.disabled = true;
    el.textContent = "Running";
    const calls = [];
    for (let i = 1; i <= 25; i++) calls.push(api("DELETE", `/v1/directory/users/u-${String(i).padStart(3, "0")}`));
    calls.push(api("DELETE", "/v1/directory/groups/g-finance"), api("DELETE", "/v1/directory/groups/g-hr"));
    await Promise.all(calls);
    await api("PUT", "/v1/directory/users/u-900", { username: "svc-patchmgr", display_name: "Patch management", enabled: true });
    await api("PUT", "/v1/directory/groups/g-domain-admins/members/u-900", {});
    flash("bad", "Attack finished. This account has no access to backups, so it can't delete them. Sign in as amehta and take a snapshot to see what the detector finds.");
    render();
  },

  "check-approval": () => checkApproval(),
  "run-restore": () => runRestore(),

  async approve(el) {
    const r = await api("POST", `/v1/approvals/${encodeURIComponent(el.dataset.id)}/approve`, {});
    if (r.ok) {
      flash("good", r.data.status === "approved"
        ? "Approved. The request has enough approvals and the operator can run it."
        : `Approved. ${r.data.required - r.data.approvals.length} more approval needed.`);
    } else {
      flash("bad", esc(errorText(r)));
    }
    render();
  },

  async "verify-audit"() {
    const out = document.getElementById("audit-msg");
    const r = await api("GET", "/v1/audit/verify");
    out.innerHTML = r.ok && r.data.ok
      ? `<div class="notice good"><p>The chain is intact: all ${r.data.entries} entries check out.</p></div>`
      : `<div class="notice bad"><p>The audit log has been altered: ${esc(r.data?.error || errorText(r))}</p></div>`;
  },
};

root.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (!el || !root.contains(el)) return;
  const fn = ACTIONS[el.dataset.action];
  if (fn) {
    e.preventDefault();
    fn(el);
  }
});

root.addEventListener("submit", async (e) => {
  const form = e.target;
  const kind = form.dataset.form;
  if (!kind) return;
  e.preventDefault();

  if (kind === "token") {
    return signIn(new FormData(form).get("token").trim());
  }
  if (kind === "take-snapshot") {
    const btn = form.querySelector("button");
    btn.disabled = true;
    const r = await api("POST", "/v1/snapshots", { policy: new FormData(form).get("policy") });
    if (r.ok) {
      flash(r.data.status === "suspicious" ? "bad" : "good", r.data.status === "suspicious"
        ? "Snapshot taken, and the detector flagged it. See what it found below."
        : "Snapshot taken.");
      go("#/snapshots/" + encodeURIComponent(r.data.id));
    } else {
      flash("bad", esc(errorText(r)));
      render();
    }
    return;
  }
  if (kind === "triage") {
    const fd = new FormData(form);
    const r = await api("POST", `/v1/snapshots/${encodeURIComponent(form.dataset.id)}/triage`,
      { status: fd.get("status"), reason: fd.get("reason").trim() });
    if (r.ok) flash("good", "Verdict saved.");
    else flash("bad", esc(errorText(r)));
    render();
    return;
  }
  if (kind === "plan") {
    readPlanForm(form);
    return previewRestore();
  }
});

root.addEventListener("change", (e) => {
  const el = e.target;
  if (el.dataset.actionChange === "audit-filter") {
    go("#/audit?show=" + el.value);
    return;
  }
  const form = el.closest("form[data-form='plan']");
  if (!form) return;
  if (el.dataset.actionChange === "pick-snapshot") {
    const keep = state.restore;
    state.restore = freshRestore();
    state.restore.snapshot = el.value;
    state.restore.scope = keep.scope;
    state.restore.mode = keep.mode;
    go("#/restore");
    return;
  }
  // Any other edit makes the preview stale.
  readPlanForm(form);
  state.restore.plan = null;
  state.restore.result = null;
  document.getElementById("plan-out").innerHTML = "";
  document.getElementById("pickers").hidden = state.restore.scope !== "some";
});

root.addEventListener("input", (e) => {
  const el = e.target;
  if (!el.dataset.filter) return;
  const q = el.value.trim().toLowerCase();
  const container = el.dataset.filter === "users" ? document.getElementById("user-rows") : document.getElementById("user-picker");
  for (const row of container.querySelectorAll("[data-search]")) {
    row.hidden = q !== "" && !row.dataset.search.includes(q);
  }
});

boot();
