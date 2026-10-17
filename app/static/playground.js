// /playground: build a request, POST it to /playground/send, show the response and the server's trace.
// All text goes in with textContent (never innerHTML): claim values and responses can be attacker-made.
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("pg-data").textContent);
  var USERS = {};
  D.user_cards.forEach(function (u) { USERS[u.key] = u; });
  var $ = function (id) { return document.getElementById(id); };
  var form = $("req");

  // ------------------------------------------------------------ tiny DOM helper
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function add(el, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(el, x); }); return; }
    el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
  function code(t) { return h("code", { text: String(t) }); }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function tag(text, cls) { return h("span", { class: "tag " + cls, text: text }); }
  function store(key, val) {
    try { if (val === undefined) return JSON.parse(sessionStorage.getItem(key) || "null"); sessionStorage.setItem(key, JSON.stringify(val)); }
    catch (e) { return null; }
  }

  // ------------------------------------------------------------ form state
  var bodies = { ask: JSON.stringify(D.default_bodies.ask, null, 2), admin: JSON.stringify(D.default_bodies.admin, null, 2) };
  var headerRows = [{ name: "X-Roles", value: "Tenant.Admin" }];

  var pick = $("collection-pick"), ctext = $("collection-text");
  D.collections.forEach(function (c) { pick.appendChild(h("option", { value: c, text: c })); });
  pick.appendChild(h("option", { value: "__custom", text: "other (type it)…" }));
  var modeSel = $("token-mode"), roleSel = $("forged-role");
  Object.keys(D.token_modes).forEach(function (k) { modeSel.appendChild(h("option", { value: k, text: D.token_modes[k].label })); });
  D.roles.forEach(function (r) { roleSel.appendChild(h("option", { value: r, text: "roles = [" + r + "]" })); });
  roleSel.value = "Tenant.Admin";

  function radio(name) { var el = form.querySelector('input[name="' + name + '"]:checked') || document.querySelector('input[name="' + name + '"]:checked'); return el && el.value; }
  function setRadio(name, value) { var el = document.querySelector('input[name="' + name + '"][value="' + value + '"]'); if (el) el.checked = true; }
  function collection() { return pick.value === "__custom" ? ctext.value.trim() : pick.value; }

  function state() {
    var call = radio("call");
    return {
      user: radio("user"), call: call, collection: collection(),
      body: (call === "ask" || call === "admin") ? $("body").value : "",
      headers: headerRows.filter(function (r) { return r.name.trim(); }).map(function (r) { return { name: r.name.trim(), value: r.value }; }),
      token_mode: modeSel.value, forged_role: roleSel.value
    };
  }

  function applyState(st) {
    setRadio("user", st.user);
    setRadio("call", st.call);
    if (st.call === "ask" || st.call === "admin") bodies[st.call] = st.body;
    if (st.collection) {
      if (D.collections.indexOf(st.collection) >= 0) { pick.value = st.collection; ctext.value = ""; }
      else { pick.value = "__custom"; ctext.value = st.collection; }
    }
    headerRows = (st.headers || []).map(function (r) { return { name: r.name, value: r.value }; });
    modeSel.value = st.token_mode || "real";
    roleSel.value = st.forged_role || "Tenant.Admin";
    sync();
  }

  // ------------------------------------------------------------ presets
  var presetBox = $("presets");
  D.presets.forEach(function (p) {
    presetBox.appendChild(h("button", {
      type: "button", class: "preset", title: "Fills the form. Expected: HTTP " + p.expect,
      onclick: function () {
        applyState({
          user: p.user, call: p.call, collection: p.collection || "kb_public",
          body: p.body ? JSON.stringify(p.body, null, 2) : (D.default_bodies[p.call] ? JSON.stringify(D.default_bodies[p.call], null, 2) : ""),
          headers: p.headers || [], token_mode: p.token_mode || "real", forged_role: p.forged_role || "Tenant.Admin"
        });
        $("send-status").textContent = "Preset loaded: " + p.label + " (expect " + p.expect + "). Press Send.";
        $("send").focus({ preventScroll: true });
      }
    }, h("span", { text: p.label }), h("small", { text: (p.role || "no role") + " · " + p.expect })));
  });

  // ------------------------------------------------------------ headers editor
  function renderHeaders() {
    var box = clear($("headers"));
    headerRows.forEach(function (row, i) {
      box.appendChild(h("div", { class: "pg-hrow" },
        h("input", { type: "text", value: row.name, placeholder: "Header-Name", "aria-label": "Header name", spellcheck: "false",
          oninput: function (e) { row.name = e.target.value; refresh(); } }),
        h("input", { type: "text", value: row.value, placeholder: "value", "aria-label": "Header value", spellcheck: "false",
          oninput: function (e) { row.value = e.target.value; refresh(); } }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Remove header", text: "×",
          onclick: function () { headerRows.splice(i, 1); renderHeaders(); refresh(); } })));
    });
  }
  $("add-header").addEventListener("click", function () {
    if (headerRows.length >= 10) return;
    headerRows.push({ name: "", value: "" }); renderHeaders();
    var inputs = $("headers").querySelectorAll("input"); inputs[inputs.length - 2].focus();
  });

  // ------------------------------------------------------------ Who: claims
  var countdowns = [];
  function fmtTime(sec) { return new Date(sec * 1000).toLocaleString(); }
  function left(sec) {
    var d = Math.round(sec - Date.now() / 1000), neg = d < 0; d = Math.abs(d);
    var m = Math.floor(d / 60), s = d % 60, hh = Math.floor(m / 60); m = m % 60;
    var t = (hh ? hh + "h " : "") + m + "m " + (s < 10 ? "0" : "") + s + "s";
    return neg ? "expired " + t + " ago" : "in " + t;
  }
  function renderClaims() {
    var u = USERS[radio("user")], box = clear($("claims"));
    countdowns = [];
    if (!u.claims) {
      box.appendChild(h("p", { class: "muted", text: (u.problem || "Not signed in") + ": no token to decode." }));
      return;
    }
    var dl = h("dl", { class: "kv" });
    function row(k, v) { dl.appendChild(h("dt", { text: k })); dl.appendChild(h("dd", null, v)); }
    var hd = u.claims.header, pl = u.claims.payload;
    row("header", [code("alg " + hd.alg), " ", code("kid " + hd.kid), hd.typ ? [" ", code("typ " + hd.typ)] : null]);
    ["iss", "aud", "tid", "oid", "preferred_username"].forEach(function (k) { if (k in pl) row(k, code(pl[k])); });
    row("roles", (pl.roles || []).length ? pl.roles.map(function (r) { return [code(r), " "]; }) : h("em", { text: "none" }));
    row("scp", code(pl.scp || ""));
    ["iat", "nbf"].forEach(function (k) { if (k in pl) row(k, fmtTime(pl[k])); });
    if ("exp" in pl) {
      var cd = h("strong", { class: "pg-countdown" });
      countdowns.push([cd, pl.exp]);
      row("exp", [fmtTime(pl.exp), " ", cd]);
    }
    box.appendChild(h("p", { class: "pg-note", text: "Decoded on the server from " + u.label + "'s cached token. The token itself never reaches this page." }));
    box.appendChild(dl);
    tick();
  }
  function tick() { countdowns.forEach(function (c) { c[0].textContent = "(" + left(c[1]) + ")"; c[0].className = "pg-countdown" + (c[1] < Date.now() / 1000 ? " bad" : ""); }); }
  setInterval(tick, 1000);

  // ------------------------------------------------------------ permission table
  function effectiveRoles(st) {
    var u = USERS[st.user];
    if (st.token_mode === "none") return [];
    if (st.token_mode === "forged_roles") return [st.forged_role];
    return u.roles || [u.expected_role];
  }
  function callRows(st) {
    if (st.call === "data") return ["read:" + st.collection];
    if (st.call === "admin") return ["admin:manage_roles"];
    if (st.call === "ask") {
      try { var b = JSON.parse(st.body); if (b && Array.isArray(b.collections)) return b.collections.map(function (c) { return "read:" + c; }); } catch (e) { /* hint shows it */ }
      return [];
    }
    return [];
  }
  function renderPerm() {
    var st = state(), roles = effectiveRoles(st), want = callRows(st), T = D.table;
    var table = h("table", { class: "perm" });
    var short = { "Support.Agent": "Support", "Finance.Analyst": "Finance", "Tenant.Admin": "Admin" };
    table.appendChild(h("thead", null, h("tr", null, h("th", { text: "" }),
      T.roles.map(function (r) { return h("th", { class: roles.indexOf(r) >= 0 ? "on" : null, title: r, text: short[r] || r }); }))));
    var tb = h("tbody");
    T.rows.forEach(function (row) {
      var hit = want.indexOf(row.permission) >= 0;
      tb.appendChild(h("tr", { class: hit ? "on" : null }, h("th", { scope: "row", text: row.label }),
        T.roles.map(function (r) {
          var ok = row.cells[r], cur = hit && roles.indexOf(r) >= 0;
          return h("td", { class: (ok ? "yes" : "no") + (cur ? " cur" : ""), title: r + " → " + row.label + ": " + (ok ? "allowed" : "denied") },
            ok ? "✓" : "✗");
        })));
    });
    table.appendChild(tb);
    add(clear($("perm")), table);

    var why = clear($("perm-why"));
    var mode = st.token_mode;
    var lines = [];
    if (mode === "none") lines.push("No token: the server answers 401 before the table is consulted.");
    else if (mode !== "real") lines.push("Token mode “" + D.token_modes[mode].label + "” fails validation, so the server answers 401 before the table is consulted.");
    if (st.call === "me") lines.push("GET /api/me needs no permission: any valid token can read its own identity.");
    var known = {}; T.rows.forEach(function (r) { known[r.permission] = r; });
    want.forEach(function (perm) {
      var row = known[perm];
      if (!row) { lines.push((perm.slice(5) || "(empty)") + " is not a collection: no table row, so it is denied by default (403)."); return; }
      if (!roles.length) { lines.push("No roles → " + row.label + ": denied (deny by default)."); return; }
      roles.forEach(function (r) {
        var ok = row.cells[r];
        lines.push(r + " → " + row.label + ": " + (ok === undefined ? "unknown role, grants nothing" : ok ? "allowed" : "denied") + " (CONTRACT.md table)");
      });
    });
    if (st.call === "ask" && !want.length) lines.push("Body has no collections list yet.");
    lines.forEach(function (l) { why.appendChild(h("span", { text: l })); });
  }

  // ------------------------------------------------------------ body hint, preview, curl
  function bodyHint() {
    var st = state(), hint = $("body-hint");
    if (!(st.call === "ask" || st.call === "admin")) return;
    try {
      var b = JSON.parse(st.body || "");
      if (st.call === "ask" && !(b && typeof b.question === "string" && Array.isArray(b.collections)))
        { hint.textContent = "Valid JSON, but /api/ask expects {\"question\": str, \"collections\": [str]} → 400"; hint.className = "pg-hint warn"; }
      else { hint.textContent = "Valid JSON"; hint.className = "pg-hint ok"; }
    } catch (e) { hint.textContent = "Not valid JSON (" + e.message + "). You can still send it: the API should answer 400 (or 401 first)."; hint.className = "pg-hint bad"; }
  }
  function requestLines(st, forCurl) {
    var call = D.calls[st.call], path = call.path.replace("{collection}", encodeURIComponent(st.collection));
    var u = USERS[st.user], heads = [];
    var auth = D.token_modes[st.token_mode].auth;
    if (auth) heads.push(["Authorization", forCurl ? "Bearer $TOKEN" : "Bearer <" + auth.replace("{who}", u.label).replace("{role}", st.forged_role) + ", redacted>"]);
    if (call.method === "POST") heads.push(["Content-Type", "application/json"]);
    st.headers.forEach(function (r) { heads.push([r.name, r.value]); });
    return { method: call.method, url: location.origin + path, headers: heads, body: call.method === "POST" ? st.body : null };
  }
  function renderPreview() {
    var r = requestLines(state(), false);
    var text = r.method + " " + r.url + "\n" + r.headers.map(function (x) { return x[0] + ": " + x[1]; }).join("\n");
    if (r.body != null) text += "\n\n" + r.body;
    $("preview").textContent = text;
  }
  function sq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  function curl() {
    var st = state(), r = requestLines(st, true), u = USERS[st.user];
    var out = [];
    if (D.token_modes[st.token_mode].auth) {
      out.push("# $TOKEN: an access token for " + (u.upn || u.label) + " (the playground never shows it).");
      if (st.token_mode !== "real") out.push("# The playground also applies “" + D.token_modes[st.token_mode].label + "” to it server-side.");
    }
    var parts = ["curl -i -X " + r.method + " " + sq(r.url)];
    r.headers.forEach(function (x) { parts.push(x[0] === "Authorization" ? '-H "Authorization: Bearer $TOKEN"' : "-H " + sq(x[0] + ": " + x[1])); });
    if (r.body != null) parts.push("--data-raw " + sq(r.body));
    out.push(parts.join(" \\\n  "));
    return out.join("\n");
  }
  function copy(text, btn) {
    var done = function () { var t = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = t; }, 1200); };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done, function () { fallback(); }); }
    else fallback();
    function fallback() {
      var ta = h("textarea", { class: "sr-only" }); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
      document.body.removeChild(ta);
    }
  }
  $("copy-curl").addEventListener("click", function (e) { copy(curl(), e.currentTarget); });

  // ------------------------------------------------------------ sync visible fields
  // bodies[] is kept current by the textarea's input listener, so switching calls loses nothing.
  function sync() {
    var call = radio("call");
    $("f-collection").hidden = call !== "data";
    $("f-body").hidden = !(call === "ask" || call === "admin");
    if (call === "ask" || call === "admin") $("body").value = bodies[call];
    ctext.hidden = pick.value !== "__custom";
    roleSel.hidden = modeSel.value !== "forged_roles";
    renderHeaders(); renderClaims(); refresh();
  }
  function refresh() { bodyHint(); renderPreview(); renderPerm(); }
  document.querySelectorAll('input[name="user"], input[name="call"]').forEach(function (el) { el.addEventListener("change", sync); });
  [pick, modeSel, roleSel].forEach(function (el) { el.addEventListener("change", function () { if (el === pick && pick.value === "__custom") { ctext.hidden = false; ctext.focus(); } sync(); }); });
  ctext.addEventListener("input", refresh);
  $("body").addEventListener("input", function () { bodies[radio("call")] = $("body").value; refresh(); });

  // ------------------------------------------------------------ trace rendering
  function statusCls(code) { return code >= 200 && code < 300 ? "pass" : code === 403 ? "warn" : "fail"; }
  function by(trace, kind) { return trace.filter(function (s) { return s.kind === kind; }); }
  function kv(pairs) {
    var dl = h("dl", { class: "kv" });
    pairs.forEach(function (p) { if (p && p[1] != null && p[1] !== "") { dl.appendChild(h("dt", { text: p[0] })); dl.appendChild(h("dd", null, p[1])); } });
    return dl;
  }
  function lookup(ref) {
    if (!ref || (!ref.portal.length && !ref.commands.length && !ref.ids)) return null;
    var ids = ref.ids ? Object.keys(ref.ids).filter(function (k) { return ref.ids[k]; }) : [];
    return h("details", { class: "pg-look" }, h("summary", { text: "Look it up yourself" }),
      ref.object ? h("p", { class: "pg-note", text: ref.object }) : null,
      ref.portal.length ? h("ul", { class: "plain" }, ref.portal.map(function (l) {
        return h("li", null, h("a", { href: l.url, target: "_blank", rel: "noopener noreferrer", text: l.label + " ↗" }));
      })) : null,
      ref.commands.map(function (c) {
        return h("div", { class: "pg-cmd" }, h("pre", { class: "pg-pre", text: c }),
          h("button", { type: "button", class: "button small ghost", text: "Copy", onclick: function (e) { copy(c, e.currentTarget); } }));
      }),
      ids.length ? kv(ids.map(function (k) { return [k, code(ref.ids[k])]; })) : null);
  }
  function section(letter, title, state, body, ref) {
    var badge = { pass: tag("ok", "pass"), fail: tag("failed", "fail"), warn: tag("denied", "warn-tag"), skip: tag("not reached", "muted-tag"), info: tag("info", "ai") }[state];
    return h("details", { class: "pg-step " + state, open: state !== "skip" },
      h("summary", null, h("span", { class: "pg-step-l", text: letter + ")" }), " " + title + " ", badge),
      h("div", { class: "pg-step-b" }, body, lookup(ref)));
  }
  function collectionsOf(perms) { return (perms || []).filter(function (p) { return p.indexOf("read:") === 0; }).map(function (p) { return p.slice(5); }); }

  function renderTrace(res) {
    var t = res.trace, refs = res.refs, req = res.request, status = res.response.status, out = [];
    var who = req.user_label;
    // a) token
    var tok = by(t, "token")[0] || {}, forge = by(t, "forge")[0];
    var a = [];
    if (tok.msal_token_source === "cache") a.push(h("p", null, "MSAL cache hit for ", code(tok.account), " (", code(tok.cache_file), "): no network call."));
    else if (tok.msal_token_source === "identity_provider") a.push(h("p", null, "MSAL network refresh: ", code("POST " + tok.token_endpoint)),
      kv([["grant_type", code(tok.grant_type)], ["client_id", code(tok.client_id)], ["scope", code(tok.scope)], ["client auth", tok.client_auth], ["refresh token", "sent, not shown"]]));
    else a.push(h("p", { text: tok.source || "no token step" }));
    if (tok.scope && tok.msal_token_source === "cache") a.push(kv([["client_id", code(tok.client_id)], ["scope", code(tok.scope)]]));
    if (tok.expires_at) a.push(h("p", null, "Access token expires " + new Date(tok.expires_at).toLocaleString() + " (" + left(Date.parse(tok.expires_at) / 1000) + ")."));
    if (tok.error) a.push(h("p", { class: "bad", text: "MSAL error: " + tok.error }));
    if (forge) a.push(h("p", { class: "pg-forge" }, "Then changed on the server: ", h("strong", { text: forge.label }), forge.forged_roles ? [" → roles ", code(JSON.stringify(forge.forged_roles))] : null,
      forge.note ? h("small", { class: "muted", text: " (" + forge.note + ")" }) : null));
    out.push(section("a", "Token from Azure (MSAL)", tok.source === "none" ? "info" : "pass", a, refs.token));

    // b) signing keys
    var jw = by(t, "jwks")[0];
    if (jw) out.push(section("b", "Signing keys (JWKS)", jw.kid_matched ? "pass" : "fail", [
      h("p", null, code("GET " + jw.url)),
      kv([["source", jw.source + " (" + jw.why + ")"], ["fetched at", jw.fetched_at ? new Date(jw.fetched_at).toLocaleString() : null],
          ["kid in token", code(jw.kid)], ["kid matched", jw.kid_matched ? "yes" : "no"], ["keys in set", (jw.keys_in_set || []).map(function (k) { return [code(k), " "]; })],
          jw.error ? ["error", jw.error] : null])], refs.jwks));
    else out.push(section("b", "Signing keys (JWKS)", "skip", h("p", { class: "muted", text: "Not reached: the request failed before the key lookup." }), refs.jwks));

    // c) claim checks
    var ah = by(t, "auth_header")[0], cl = by(t, "claims")[0], c = [];
    if (ah && !ah.ok) c.push(h("p", { class: "cause" }, "Cause of the 401: ", h("strong", { text: ah.error }), " (no Authorization: Bearer header)."));
    if (cl) {
      var list = h("ol", { class: "checks" });
      cl.checks.forEach(function (k) {
        var act = k.actual && typeof k.actual === "object" ? JSON.stringify(k.actual) : k.actual;
        list.appendChild(h("li", { class: "chk " + k.result.replace(" ", "-") },
          h("div", { class: "chk-head" }, h("strong", { text: k.check }), " ",
            k.result === "pass" ? tag("pass", "pass") : k.result === "fail" ? tag("FAIL", "fail") : h("small", { class: "muted", text: "not reached" })),
          k.result === "not reached" ? null : h("div", { class: "chk-row" }, h("span", { class: "muted", text: "expected " }), code(k.expected != null ? k.expected : "—")),
          k.result === "not reached" ? null : h("div", { class: "chk-row" }, h("span", { class: "muted", text: "actual " }), code(act != null ? act : "—"))));
      });
      c.push(list);
      if (cl.outcome === "fail") c.unshift(h("p", { class: "cause" }, "Cause of the 401: ", h("strong", { text: cl.error })));
      c.push(h("p", { class: "pg-note", text: "Order is the code's: our alg/kid/key checks, then PyJWT's jwt.decode (signature, required claims, iat/nbf/exp, iss, aud), then our tid and scp checks." }));
    }
    var cState = (ah && !ah.ok) || (cl && cl.outcome === "fail") ? "fail" : cl ? "pass" : "skip";
    out.push(section("c", "Claim checks", cState, c.length ? c : h("p", { class: "muted", text: "Not reached." }), refs.claims));

    // d) RBAC
    var pr = by(t, "principal")[0], rb = by(t, "rbac"), dec = by(t, "decision")[0], hints = by(t, "role_hints")[0], d = [];
    if (hints) d.push(h("div", { class: "pg-hints" }, h("strong", { text: "Role hints in the request, ignored: " }),
      h("ul", { class: "plain" }, hints.found.map(function (f) { return h("li", null, f.where + " ", code(f.name), ": ", code(f.value)); })),
      h("small", { class: "muted", text: hints.note })));
    if (pr) {
      d.push(h("p", null, "Token ", code("roles"), " claim: ", pr.roles.length ? pr.roles.map(function (r) { return [code(r), " "]; }) : h("em", { text: "none (deny by default)" })));
      if (!rb.length) d.push(h("p", { class: "muted", text: "No permission check for this call." }));
      rb.forEach(function (step) {
        var chain = h("ol", { class: "pg-chain" });
        step.roles.forEach(function (r) {
          var obj = D.role_objects[r.role];
          chain.appendChild(h("li", null, "roles claim value ", code(r.role)));
          chain.appendChild(h("li", null, "Entra app role: ", obj ? [h("strong", { text: obj.displayName }), " ", code(obj.id)] : (r.known ? h("em", { text: "ids unavailable (no entra-objects.json)" }) : h("em", { text: "not an app role of this app" }))));
          chain.appendChild(h("li", null, "permission-table row: ", r.known ? r.grants.map(function (g) { return [code(g), " "]; }) : h("em", { text: "none: unknown role grants nothing" })));
          chain.appendChild(h("li", null, "allowed collections: ", collectionsOf(r.grants).length ? collectionsOf(r.grants).join(", ") : "none"));
        });
        chain.appendChild(h("li", { class: step.allowed ? "ok" : "bad" }, h("strong", { text: (step.allowed ? "allowed: " : "denied: ") + step.permission }), " — " + step.why));
        d.push(chain);
      });
      var rd = by(t, "readable")[0];
      if (rd) d.push(h("p", null, "Readable collections for the retrieval filter: ", rd.collections.join(", ") || "none"));
      if (dec) d.push(h("p", { class: "pg-decision " + statusCls(dec.status) }, h("strong", { text: "Decision: HTTP " + dec.status }), " — " + dec.why));
      var ids = refs.rbac && refs.rbac.ids;
      if (ids && ids.assignmentId && pr.roles.indexOf(USERS[req.user].expected_role) >= 0)
        d.push(h("p", null, "Granted to " + who + " by app role assignment ", code(ids.assignmentId), "."));
    } else d.push(h("p", { class: "muted", text: "Not reached: the token was rejected (401) before any role was read." }));
    var dState = !pr ? "skip" : dec && dec.status === 403 ? "warn" : "pass";
    out.push(section("d", "RBAC decision", dState, d, refs.rbac));

    // e) data filter
    var f = by(t, "filter")[0];
    if (f) {
      out.push(section("e", "Data filter", "pass", [
        h("p", null, "Rows passed on (ids only):"),
        h("ul", { class: "plain" }, Object.keys(f.passed).map(function (k) { return h("li", null, code(k), ": " + f.passed[k].join(", ")); })),
        h("p", null, "Filtered out:"),
        h("ul", { class: "plain" }, Object.keys(f.excluded).map(function (k) { return h("li", null, code(k), " — " + f.excluded[k]); }))], refs.filter));
    } else out.push(section("e", "Data filter", "skip", h("p", { class: "muted", text: req.call === "data" || req.call === "ask" ? "Not reached: no rows were read." : "This call reads no rows." }), refs.filter));

    // f) Claude
    if (req.call === "ask") {
      var ac = by(t, "ai_call")[0], ar = by(t, "ai_result")[0];
      if (ac) out.push(section("f", "Claude call", !ar || ar.error ? "info" : "pass", [
        kv([["model", code(ac.model)], ["effort", code(ac.effort)], ["rows sent", String(ac.rows_sent)], ["collections", ac.collections.join(", ")],
            ar && !ar.error ? ["stop_reason", code(ar.stop_reason)] : null,
            ar && ar.usage ? ["usage", "input " + ar.usage.input_tokens + ", output " + ar.usage.output_tokens + " tokens"] : null,
            ar && ar.error ? ["result", ar.error] : null]),
        res.response.body && typeof res.response.body.answer === "string" ? h("div", { class: "pg-answer-text", text: res.response.body.answer }) : null,
        ar ? null : h("p", { class: "muted", text: "No response details recorded: ai.answer is replaced on this server (fake tenant or tests), so Claude was not called." })], refs.ai));
      else out.push(section("f", "Claude call", "skip", h("p", { class: "muted", text: "Not reached: Claude is called only after the RBAC check passes." }), refs.ai));
    }
    out.push(h("details", { class: "pg-raw" }, h("summary", { text: "Raw trace JSON" }), h("pre", { class: "pg-pre", text: JSON.stringify(t, null, 2) })));
    return out;
  }

  // The model's answer, front and centre for ask calls. Rendered as text, never HTML.
  function askQuestion(q) { try { return JSON.parse(q.body || "{}").question; } catch (e) { return null; } }
  function renderAnswer(res) {
    var q = res.request, r = res.response, b = r.body;
    if (q.call !== "ask") return null;
    var ar = by(res.trace, "ai_result")[0], ac = by(res.trace, "ai_call")[0], question = askQuestion(q);
    var card = h("section", { class: "pg-answer" }, h("h3", { class: "pg-h3", text: "AI answer" }));
    if (question) card.appendChild(h("p", { class: "pg-q" }, h("span", { class: "muted", text: "Asked: " }), question));
    if (b && typeof b === "object" && typeof b.answer === "string") {
      card.appendChild(h("div", { class: "pg-answer-text", text: b.answer }));
      var meta = [];
      if (ac) meta.push(ac.model + " · effort " + ac.effort + " · " + ac.rows_sent + " rows from " + ac.collections.join(", "));
      if (ar && ar.usage) meta.push(ar.usage.input_tokens + " in / " + ar.usage.output_tokens + " out tokens");
      if (ar && ar.stop_reason) meta.push("stop_reason " + ar.stop_reason);
      if (meta.length) card.appendChild(h("p", { class: "pg-note", text: meta.join(" · ") }));
    } else {
      var why = r.status === 401 ? "the token was rejected, so Claude was never called."
        : r.status === 403 ? "this role may not read a requested collection, so Claude was never called."
        : r.status === 503 ? "the AI is not configured or the call failed (see the response body)."
        : "no answer in the response (HTTP " + r.status + ").";
      card.appendChild(h("p", { class: "muted", text: "No answer: " + why }));
    }
    return card;
  }

  function renderResult(entry) {
    var box = clear($("result"));
    if (entry.error) { box.appendChild(h("div", { class: "banner warn" }, h("strong", { text: "Not sent: " }), entry.error)); return; }
    var res = entry.result, r = res.response, q = res.request;
    box.appendChild(h("div", { class: "pg-status" },
      h("span", { class: "pg-code " + statusCls(r.status), text: "HTTP " + r.status }),
      h("span", null, code(q.method + " " + q.path), " as " + q.user_label + " · " + r.elapsed_ms + " ms")));
    if (r.headers["www-authenticate"]) box.appendChild(h("p", { class: "pg-note" }, "WWW-Authenticate: ", code(r.headers["www-authenticate"])));
    box.appendChild(h("details", { class: "pg-sent" }, h("summary", { text: "Request as sent (token redacted)" }),
      h("pre", { class: "pg-pre", text: q.method + " " + q.path + "\n" + q.headers.map(function (x) { return x[0] + ": " + x[1]; }).join("\n") + (q.body != null ? "\n\n" + q.body : "") })));
    var ai = renderAnswer(res);
    if (ai) box.appendChild(ai);
    box.appendChild(h("h3", { class: "pg-h3", text: "Response body" }));
    box.appendChild(h("pre", { class: "pg-pre pg-body", text: typeof r.body === "string" ? r.body : JSON.stringify(r.body, null, 2) }));
    box.appendChild(h("h3", { class: "pg-h3", text: "Trace (from the server's code path)" }));
    add(box, renderTrace(res));
  }

  // ------------------------------------------------------------ history
  var history = store("pg-history") || [];
  function renderHistory(activeIdx) {
    var ol = clear($("history"));
    if (!history.length) { ol.appendChild(h("li", { class: "muted", text: "No sends yet." })); return; }
    history.forEach(function (e, i) {
      var label = e.error ? "not sent" : "HTTP " + e.result.response.status;
      ol.appendChild(h("li", null, h("button", { type: "button", class: "pg-hist" + (i === activeIdx ? " on" : ""), onclick: function () {
        applyState(e.state); renderResult(e); renderHistory(i);
      } }, h("span", { class: "pg-code small " + (e.error ? "fail" : statusCls(e.result.response.status)), text: label }),
        h("span", { text: " " + e.at + " · " + USERS[e.state.user].label + " · " + D.calls[e.state.call].label.replace("{collection}", e.state.collection) +
          (e.state.token_mode !== "real" ? " · " + D.token_modes[e.state.token_mode].label : "") }))));
    });
  }
  function remember(entry) {
    history.unshift(entry); history = history.slice(0, 10); store("pg-history", history); renderHistory(0);
  }

  // ------------------------------------------------------------ send
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var st = state(), btn = $("send"), status = $("send-status");
    btn.disabled = true; status.textContent = st.call === "ask" ? "Sending a real request; waiting for Claude…" : "Sending a real request…";
    var at = new Date().toLocaleTimeString();
    fetch("/playground/send", { method: "POST", headers: { "Content-Type": "application/json", "X-Playground-Send": "1" }, body: JSON.stringify(st) })
      .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }, function () { return { ok: false, body: { detail: "HTTP " + r.status } }; }); })
      .then(function (x) {
        var entry = x.ok ? { at: at, state: st, result: x.body } : { at: at, state: st, error: x.body.detail || "failed" };
        renderResult(entry); remember(entry);
        status.textContent = x.ok ? "Done: HTTP " + x.body.response.status + "." : "Not sent.";
        if (window.matchMedia("(max-width: 1099px)").matches) $("res-h").scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch(function (e) { status.textContent = "Request failed: " + e.message; })
      .then(function () { btn.disabled = !D.configured; });
  });

  sync();
  renderHistory(-1);
})();
