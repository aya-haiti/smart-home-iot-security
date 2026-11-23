// Smart Home IoT Security Lab — in-browser simulation.
// Mirrors the repository: the Python devices (topics, value ranges, intervals), both mosquitto.conf
// files, mosquitto/secure/config/aclfile and the Node-RED anomaly rule (> 30 msg in 60 s on one topic).
// No network connection is ever opened.
(() => {
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // ------------------------------------------------------------------ simulated clock (×5)
  const SPEED = 5;
  let simNow = 0, last = performance.now();
  const timers = [];
  const every = (ms, fn) => timers.push({ ms, fn, next: simNow + ms });
  function tick() {
    const t = performance.now();
    simNow += Math.min(t - last, 2000) * SPEED; last = t;  // cap catch-up after a background pause
    for (const tm of timers) while (simNow >= tm.next) { tm.next += tm.ms; tm.fn(); }
  }
  const sleep = (simMs) => new Promise((r) => setTimeout(r, simMs / SPEED));
  const clock = () => { const s = Math.floor(simNow / 1000); return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; };

  // ------------------------------------------------------------------ ACL (aclfile) and topic matching
  const ACL = {
    sensor_user: [["write", "home/+/temperature/state"], ["write", "home/+/gas/state"], ["write", "home/+/door/state"]],
    actuator_user: [["read", "home/+/light/cmd"], ["write", "home/+/light/state"], ["read", "home/+/ac/cmd"], ["write", "home/+/ac/state"]],
    dashboard_user: [["read", "home/+/+/state"], ["write", "home/+/light/cmd"], ["write", "home/+/ac/cmd"]],
    admin_user: [["readwrite", "home/#"]]
  };
  function match(filter, topic) {
    const f = filter.split("/"), t = topic.split("/");
    for (let i = 0; i < f.length; i++) {
      if (f[i] === "#") return true;
      if (i >= t.length || (f[i] !== "+" && f[i] !== t[i])) return false;
    }
    return f.length === t.length;
  }
  const allowed = (user, access, topic) => (ACL[user] || []).some(([a, f]) => (a === access || a === "readwrite") && match(f, topic));

  // ------------------------------------------------------------------ broker rules (mosquitto.conf)
  const rules = {
    connect(mode, c) {
      if (mode === "vulnerable") return { ok: true, code: "CONNACK 0", why: "accès anonyme accepté (allow_anonymous true, port 1883 en clair)" };
      if (!c.tls) return { ok: false, code: "TLS requis", why: "le port 8883 n'accepte que TLS 1.2 : handshake refusé" };
      if (!c.user) return { ok: false, code: "CONNACK 5", why: "not authorised : allow_anonymous false" };
      return { ok: true, code: "CONNACK 0", why: `authentifié comme ${c.user} (password_file), TLS 1.2` };
    },
    canWrite: (mode, c, topic) => mode === "vulnerable" || allowed(c.user, "write", topic),
    canRead: (mode, c, topic) => mode === "vulnerable" || allowed(c.user, "read", topic)
  };

  // ------------------------------------------------------------------ live broker
  const broker = {
    mode: "vulnerable", subs: [],
    subscribe(c, filter, cb) { this.subs.push({ c, filter, cb }); },
    unsubscribe(c) { this.subs = this.subs.filter((s) => s.c !== c); },
    publish(c, topic, payload) {
      if (this.mode === "secure" && JSON.stringify(payload).length > 8192) return "size";
      if (!rules.canWrite(this.mode, c, topic)) return "denied";
      anomaly.record(topic);
      for (const s of this.subs) if (match(s.filter, topic) && rules.canRead(this.mode, s.c, topic)) s.cb(topic, payload, c);
      return "ok";
    }
  };

  // ------------------------------------------------------------------ anomaly detection (Node-RED flow)
  const anomaly = {
    hist: {}, series: Array(60).fill(0), active: false,
    record(topic) { (this.hist[topic] ||= []).push(simNow); },
    rate() {
      let max = 0, top = "";
      for (const [t, a] of Object.entries(this.hist)) { while (a.length && simNow - a[0] > 60000) a.shift(); if (a.length > max) { max = a.length; top = t; } }
      return { max, top };
    }
  };

  // ------------------------------------------------------------------ timeline
  const events = [], routine = [];   // notable events and raw measurements are kept apart
  function logEvent(kind, title, detail = "") {
    events.unshift({ t: clock(), kind, title, detail, at: simNow });
    if (events.length > 100) events.pop();
    renderTimeline();
  }
  function renderTimeline() {
    const hide = $("#hide-routine").checked;
    const list = (hide ? events : [...events, ...routine].sort((a, b) => b.at - a.at)).slice(0, 60);
    $("#timeline").innerHTML = list.length ? list.map((e) => `<li class="${e.kind}"><time>${e.t}</time><div><div class="k">${esc(e.title)}</div>${e.detail ? `<div class="d">${esc(e.detail)}</div>` : ""}</div></li>`).join("")
      : '<li class="empty">Aucun événement notable. Lancez une attaque depuis l’onglet « Attaques ».</li>';
  }
  $("#hide-routine").addEventListener("change", renderTimeline);

  // ------------------------------------------------------------------ devices (devices/*.py)
  const legit = (user) => ({ user, tls: true, label: user });
  const sensorC = legit("sensor_user"), actuatorC = legit("actuator_user"), dashC = legit("dashboard_user");
  const st = { temp: 22.0, gas: 100, door: "CLOSED", light: { state: "OFF", intensity: 0 }, ac: { state: "OFF", mode: "COOL", target_temp: 22 } };

  every(5000, () => { // temperature_sensor.py : ±0.4 °C, bounded 15..30
    st.temp = Math.max(15, Math.min(30, st.temp + (Math.random() * 0.8 - 0.4)));
    broker.publish(sensorC, "home/salon/temperature/state", { type: "temperature", value: +st.temp.toFixed(1), unit: "C" });
  });
  every(5000, () => { // gas_sensor.py : 5 % chance of +50..350 ppm, else ±15, bounded 50..800, ALERT > 400
    st.gas = Math.random() < 0.05 ? st.gas + 50 + Math.random() * 300 : st.gas + (Math.random() * 30 - 15);
    st.gas = Math.max(50, Math.min(800, st.gas));
    broker.publish(sensorC, "home/cuisine/gas/state", { type: "gas", value: Math.round(st.gas), unit: "ppm", status: st.gas > 400 ? "ALERT" : "OK" });
  });
  every(5000, () => { // door_sensor.py : 15 % chance of toggling
    if (Math.random() < 0.15) st.door = st.door === "OPEN" ? "CLOSED" : "OPEN";
    broker.publish(sensorC, "home/entree/door/state", { type: "door", state: st.door });
  });
  const pubLight = () => broker.publish(actuatorC, "home/salon/light/state", { type: "light", ...st.light });
  const pubAc = () => broker.publish(actuatorC, "home/chambre/ac/state", { type: "ac", ...st.ac });
  every(10000, pubLight); every(10000, pubAc);

  broker.subscribe(actuatorC, "home/salon/light/cmd", (_, p, from) => { // light_device.py
    const a = String(p.action || "").toUpperCase();
    if (a === "ON" || a === "OFF") { st.light.state = a; if (a === "ON" && !st.light.intensity) st.light.intensity = 80; if (a === "OFF") st.light.intensity = 0; }
    if (p.intensity != null) st.light.intensity = Math.max(0, Math.min(100, +p.intensity));
    if (from !== dashC) logEvent("attack", "Lampe pilotée par un tiers", `état : ${st.light.state} ${st.light.intensity}%`);
    pubLight();
  });
  broker.subscribe(actuatorC, "home/chambre/ac/cmd", (_, p, from) => { // ac_device.py
    const a = String(p.action || "").toUpperCase();
    if (a === "ON" || a === "OFF") st.ac.state = a;
    if (p.mode) st.ac.mode = String(p.mode).toUpperCase();
    if (p.target_temp != null) st.ac.target_temp = +p.target_temp;
    if (from !== dashC) logEvent("attack", "Climatisation pilotée par un tiers", `${st.ac.state} · ${st.ac.mode} ${st.ac.target_temp} °C`);
    pubAc();
  });

  // ------------------------------------------------------------------ dashboard (dashboard_user)
  const DEV = [
    ["temp", "🌡️ Salon", "Température"], ["gas", "🔥 Cuisine", "Gaz"], ["door", "🚪 Entrée", "Porte"],
    ["light", "💡 Salon", "Lampe"], ["ac", "❄️ Chambre", "Climatisation"], ["rate", "📈 Broker", "Msg/min max"]
  ];
  $("#devices").innerHTML = DEV.map(([k, room, name]) => `<div class="dev" id="dev-${k}"><div class="t"><span>${room}</span><span>${name}</span></div><b id="v-${k}">—</b><span class="s" id="s-${k}">&nbsp;</span></div>`).join("");
  const set = (k, v, s = " ", alert = false) => { $("#v-" + k).textContent = v; $("#s-" + k).textContent = s; $("#dev-" + k).classList.toggle("alert", alert); };
  const flash = (k) => { const el = $("#dev-" + k); el.classList.add("changed"); setTimeout(() => el.classList.remove("changed"), 1200); };
  let lastGasStatus = "OK";
  broker.subscribe(dashC, "home/+/+/state", (topic, p) => {
    if (topic.endsWith("temperature/state")) set("temp", p.value.toFixed(1) + " °C");
    if (topic.endsWith("gas/state")) {
      set("gas", p.value + " ppm", p.status === "ALERT" ? "ALERTE gaz > 400 ppm" : "normal", p.status === "ALERT");
      if (p.status !== lastGasStatus) logEvent(p.status === "ALERT" ? "alert" : "info", p.status === "ALERT" ? "Alerte gaz affichée" : "Niveau de gaz revenu à la normale", `${p.value} ppm`);
      lastGasStatus = p.status;
    }
    if (topic.endsWith("door/state")) set("door", p.state === "OPEN" ? "Ouverte" : "Fermée");
    if (topic.endsWith("light/state")) { set("light", p.state === "ON" ? `ON · ${p.intensity}%` : "OFF"); flash("light"); }
    if (topic.endsWith("ac/state")) { set("ac", p.state === "ON" ? `${p.mode} · ${p.target_temp}°` : "OFF"); flash("ac"); }
  });

  const spark = $("#spark"), ctx = spark.getContext("2d");
  every(1000, () => {
    const { max, top } = anomaly.rate();
    anomaly.series.push(max); anomaly.series.shift();
    set("rate", String(max), max > 30 ? "anomalie détectée" : "normal", max > 30);
    if (max > 30 && !anomaly.active) logEvent("alert", "ANOMALIE détectée par Node-RED", `${max} msg/min sur ${top} (seuil 30)`);
    if (max <= 30 && anomaly.active) logEvent("info", "Fin de l'anomalie", "débit revenu sous le seuil");
    anomaly.active = max > 30;
    renderStatus(); drawSpark();
  });
  function drawSpark() {
    const dpr = devicePixelRatio || 1, w = spark.width = spark.clientWidth * dpr, h = spark.height = 80 * dpr;
    const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
    const max = Math.max(40, ...anomaly.series), y = (v) => h - (v / max) * (h - 10 * dpr) - 5 * dpr;
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = css("--red"); ctx.globalAlpha = .6; ctx.setLineDash([4 * dpr, 4 * dpr]); ctx.lineWidth = dpr;
    ctx.beginPath(); ctx.moveTo(0, y(30)); ctx.lineTo(w, y(30)); ctx.stroke(); ctx.setLineDash([]); ctx.globalAlpha = 1;
    ctx.strokeStyle = css("--accent"); ctx.lineWidth = 2 * dpr; ctx.beginPath();
    anomaly.series.forEach((v, i) => { const x = (i / 59) * w; i ? ctx.lineTo(x, y(v)) : ctx.moveTo(x, y(v)); }); ctx.stroke();
  }
  function renderStatus() {
    const secure = broker.mode === "secure";
    $("#status").innerHTML = `<span class="pill ${secure ? "ok" : "bad"}">Broker ${secure ? "sécurisé :8883 · TLS · ACL" : "vulnérable :1883 · anonyme"}</span>`
      + `<span class="pill">5 objets connectés</span>`
      + (anomaly.active ? '<span class="pill warn">Anomalie en cours</span>' : "");
  }

  $$("[data-cmd]").forEach((b) => b.addEventListener("click", () => {
    const cmds = { "light-on": ["home/salon/light/cmd", { action: "ON" }], "light-off": ["home/salon/light/cmd", { action: "OFF" }], "ac-cool": ["home/chambre/ac/cmd", { action: "ON", mode: "COOL", target_temp: 22 }], "ac-off": ["home/chambre/ac/cmd", { action: "OFF" }] };
    const [t, p] = cmds[b.dataset.cmd];
    broker.publish(dashC, t, p);
    logEvent("info", "Commande du propriétaire", `${t} ${JSON.stringify(p)}`);
  }));

  // ------------------------------------------------------------------ scenarios
  const SCENARIOS = {
    sniff: { name: "Espionner", desc: "S'abonner à # et lire tout le trafic", map: "STRIDE : Information disclosure · ATT&CK ICS T0830" },
    inject: { name: "Injecter une commande", desc: "Allumer la lampe, chauffer la chambre à 30 °C", map: "STRIDE : Spoofing / Elevation of privilege · T0855" },
    spoof: { name: "Falsifier une mesure", desc: "Publier une fausse fuite de gaz à 999 ppm", map: "STRIDE : Tampering · T0832" },
    flood: { name: "Inonder le broker", desc: "500 messages sur le topic du gaz", map: "STRIDE : Denial of Service · T0814" }
  };
  const IDENTITIES = {
    anon: { name: "Anonyme, sans TLS", desc: "outil MQTT par défaut", client: { user: null, tls: false } },
    "anon-tls": { name: "Anonyme, avec TLS", desc: "chiffre mais sans identifiants", client: { user: null, tls: true } },
    sensor_user: { name: "Identifiants volés", desc: "compte sensor_user d'un capteur compromis", client: { user: "sensor_user", tls: true } }
  };
  const TOPICS = { inject: ["home/salon/light/cmd", "home/chambre/ac/cmd"], spoof: ["home/cuisine/gas/state"], flood: ["home/cuisine/gas/state"] };

  // Pure evaluation of a scenario against a configuration (used by the comparison table and the result panel)
  function evaluate(mode, idKey, scKey) {
    const c = IDENTITIES[idKey].client, steps = [];
    const conn = rules.connect(mode, c);
    steps.push({ s: conn.ok ? (mode === "vulnerable" ? "bad" : "warn") : "ok", text: `Connexion : <code>${conn.code}</code> — ${conn.why}` });
    if (!conn.ok) return { outcome: "blocked", steps, short: "connexion refusée" };
    if (scKey === "sniff") {
      const visible = ["home/salon/temperature/state", "home/cuisine/gas/state", "home/entree/door/state", "home/salon/light/state", "home/chambre/ac/state"].filter((t) => rules.canRead(mode, c, t));
      steps.push({ s: visible.length ? "bad" : "ok", text: visible.length ? `Abonnement à <code>#</code> : ${visible.length} topics lisibles en clair` : `Abonnement à <code>#</code> accepté, mais l'ACL n'accorde aucun droit de lecture à ${c.user} : 0 message reçu` });
      return visible.length ? { outcome: "success", steps, short: "trafic lu" } : { outcome: "blocked", steps, short: "ACL : aucune lecture" };
    }
    const results = TOPICS[scKey].map((t) => [t, rules.canWrite(mode, c, t)]);
    results.forEach(([t, ok]) => steps.push({ s: ok ? "bad" : "ok", text: `Publication sur <code>${t}</code> : ${ok ? "acceptée" : "refusée par l'ACL (message ignoré)"}` }));
    const okAll = results.every(([, ok]) => ok);
    if (!okAll) return { outcome: "blocked", steps, short: "ACL : écriture refusée" };
    if (scKey === "flood") {
      steps.push({ s: "warn", text: "Aucune limite de débit dans mosquitto.conf : les 500 messages passent ; la règle Node-RED (> 30 msg/min) lève une alerte" });
      return { outcome: mode === "vulnerable" ? "success" : "partial", steps, short: mode === "vulnerable" ? "saturation, alerte Node-RED" : "passe, mais détecté" };
    }
    if (scKey === "spoof" && mode === "secure") {
      steps.push({ s: "warn", text: "Le compte capteur a le droit d'écrire sur son propre topic : la fausse mesure est affichée" });
      return { outcome: "partial", steps, short: "possible avec un compte capteur" };
    }
    return { outcome: "success", steps, short: scKey === "inject" ? "actionneurs pilotés" : "fausse alerte affichée" };
  }

  let choice = { sc: "sniff", id: "anon" };
  function radios(container, items, key) {
    $(container).innerHTML = Object.entries(items).map(([k, v]) => `<button role="radio" aria-checked="${choice[key] === k}" data-${key}="${k}"><b>${esc(v.name)}</b><span>${esc(v.desc)}</span></button>`).join("");
    $$(`${container} button`).forEach((b) => b.addEventListener("click", () => { choice[key] = b.dataset[key]; radios(container, items, key); }));
  }
  radios("#scenarios", SCENARIOS, "sc"); radios("#identities", IDENTITIES, "id");

  async function runAttack() {
    const btn = $("#run"); btn.disabled = true;
    const { sc, id } = choice, c = { ...IDENTITIES[id].client, label: "attaquant" };
    const ev = evaluate(broker.mode, id, sc);
    logEvent("attack", `Attaque lancée : ${SCENARIOS[sc].name}`, `${IDENTITIES[id].name} → broker ${broker.mode === "secure" ? "sécurisé" : "vulnérable"}`);
    let live = "";
    if (rules.connect(broker.mode, c).ok) {
      if (sc === "sniff") {
        let n = 0; broker.subscribe(c, "#", () => n++);
        await sleep(30000); broker.unsubscribe(c);
        live = `${n} message(s) intercepté(s) en 30 s simulées.`;
      } else if (sc === "inject") {
        broker.publish(c, "home/salon/light/cmd", { action: "ON", intensity: 100 });
        broker.publish(c, "home/chambre/ac/cmd", { action: "ON", mode: "HEAT", target_temp: 30 });
        live = `État actuel : lampe ${st.light.state} ${st.light.intensity}%, climatisation ${st.ac.state} ${st.ac.mode} ${st.ac.target_temp} °C.`;
      } else if (sc === "spoof") {
        broker.publish(c, "home/cuisine/gas/state", { type: "gas", value: 999, unit: "ppm", status: "ALERT" });
        live = "Regardez la carte « Gaz » du tableau de bord.";
      } else if (sc === "flood") {
        let ok = 0;
        for (let i = 0; i < 500; i++) { if (broker.publish(c, "home/cuisine/gas/state", { type: "gas", value: 999, unit: "ppm", status: "ALERT" }) === "ok") ok++; if (i % 50 === 49) await sleep(400); }
        live = `${ok} / 500 messages acceptés.`;
      }
    }
    logEvent(ev.outcome === "blocked" ? "blocked" : "attack", ev.outcome === "blocked" ? "Attaque bloquée" : ev.outcome === "partial" ? "Attaque partiellement réussie" : "Attaque réussie", ev.short);
    const verdict = { success: ["bad", "Attaque réussie"], partial: ["mid", "Partiellement contenue"], blocked: ["ok", "Bloquée"] }[ev.outcome];
    const icon = { ok: "✓", bad: "!", warn: "~" };
    $("#result").hidden = false;
    $("#result").innerHTML = `<h2>${esc(SCENARIOS[sc].name)} <span class="verdict ${verdict[0]}">${verdict[1]}</span></h2>
      <p class="hint">${esc(IDENTITIES[id].name)} contre le broker ${broker.mode === "secure" ? "sécurisé (:8883)" : "vulnérable (:1883)"}</p>
      <ol class="flow">${ev.steps.map((s) => `<li class="${s.s}"><span class="ic">${icon[s.s]}</span><span>${s.text}</span></li>`).join("")}</ol>
      ${live ? `<p>${esc(live)}</p>` : ""}
      <div class="lesson">${lessonFor(sc, ev.outcome)}<br><span class="map">${SCENARIOS[sc].map}</span></div>`;
    btn.disabled = false;
  }
  function lessonFor(sc, outcome) {
    if (outcome === "blocked") return "<b>Protection efficace.</b> Comparez avec le même scénario sur le broker vulnérable, ou essayez des identifiants volés.";
    return {
      sniff: "<b>Risque :</b> sans authentification, quiconque atteint le port lit toutes les mesures et déduit la présence des habitants.",
      inject: "<b>Risque :</b> un attaquant commande physiquement les objets ; ici lampe et chauffage, ailleurs serrures ou alarmes.",
      spoof: "<b>Risque :</b> une mesure non authentifiée déclenche une fausse alerte ou masque une vraie fuite. Un compte par capteur et la rotation des secrets limitent ce risque.",
      flood: "<b>Risque :</b> le flot de fausses mesures noie une vraie alerte et sature le tableau de bord ; la détection d'anomalies est la dernière ligne de défense."
    }[sc];
  }
  $("#run").addEventListener("click", runAttack);

  // ------------------------------------------------------------------ comparison matrix
  function renderMatrix() {
    const rows = [["sniff", "anon"], ["inject", "anon"], ["spoof", "anon"], ["flood", "anon"], ["inject", "sensor_user"], ["spoof", "sensor_user"]];
    const cell = (ev) => {
      const [cls, txt] = { success: ["bad", "Réussie"], partial: ["mid", "Partielle"], blocked: ["ok", "Bloquée"] }[ev.outcome];
      return `<td><span class="verdict ${cls}">${txt}</span><small>${esc(ev.short)}</small></td>`;
    };
    $("#matrix").innerHTML = `<thead><tr><th>Attaque</th><th>Attaquant</th><th>Broker vulnérable</th><th>Broker sécurisé</th></tr></thead><tbody>${rows.map(([sc, id]) =>
      `<tr><td><b>${SCENARIOS[sc].name}</b></td><td>${IDENTITIES[id].name}</td>${cell(evaluate("vulnerable", id, sc))}${cell(evaluate("secure", id, sc))}</tr>`).join("")}</tbody>`;
  }

  // ------------------------------------------------------------------ broker switch, tabs
  function setMode(mode) {
    broker.mode = mode; anomaly.hist = {};
    $$("[data-mode]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.mode === mode));
    $("#broker-reminder").innerHTML = `Broker actif : <b>${mode === "secure" ? "sécurisé (:8883)" : "vulnérable (:1883)"}</b> — modifiable en haut à droite.`;
    logEvent("info", `Bascule vers le broker ${mode === "secure" ? "sécurisé" : "vulnérable"}`, mode === "secure" ? "TLS 1.2 · authentification · ACL" : "port 1883 · anonyme");
    renderStatus();
  }
  $$("[data-mode]").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));

  const tabs = $$('[role="tab"]');
  function selectTab(t) {
    tabs.forEach((x) => { const on = x === t; x.setAttribute("aria-selected", on); x.tabIndex = on ? 0 : -1; $("#" + x.getAttribute("aria-controls")).hidden = !on; });
    history.replaceState(null, "", "#" + t.getAttribute("aria-controls"));
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => selectTab(t));
    t.addEventListener("keydown", (e) => { if (e.key === "ArrowRight" || e.key === "ArrowLeft") { const n = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length]; n.focus(); selectTab(n); } });
  });
  const init = tabs.find((t) => "#" + t.getAttribute("aria-controls") === location.hash); if (init) selectTab(init);

  // routine measurements in the timeline (hidden by default)
  broker.subscribe(legit("admin_user"), "home/#", (t, p) => {
    if (!t.endsWith("/state")) return;
    routine.unshift({ t: clock(), kind: "routine", title: t, detail: JSON.stringify(p), at: simNow });
    if (routine.length > 40) routine.pop();
  });
  every(2000, () => { if (!$("#hide-routine").checked) renderTimeline(); });

  setMode("vulnerable"); renderMatrix();
  logEvent("info", "Maison démarrée", "5 objets publient leurs mesures");
  last = performance.now();
  setInterval(tick, 100);
})();
