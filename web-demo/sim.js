// Smart Home IoT Security Lab — in-browser simulation.
// Mirrors the repository: the Python devices (topics, ranges, intervals), both mosquitto.conf files,
// mosquitto/secure/config/aclfile and the Node-RED anomaly rule (> 30 msg / 60 s on one topic).
// No network connection is ever opened.
(() => {
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];

  // ---------------------------------------------------------------- clock
  let speed = 5, simNow = 0, last = performance.now();
  const timers = [];
  function every(ms, fn) { timers.push({ ms, fn, next: simNow + ms }); }
  function tick(t) {
    simNow += (t - last) * speed; last = t;
    for (const tm of timers) while (simNow >= tm.next) { tm.next += tm.ms; tm.fn(); }
    requestAnimationFrame(tick);
  }
  const sleep = (simMs) => new Promise((r) => setTimeout(r, simMs / speed));

  // ---------------------------------------------------------------- ACL (aclfile)
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
  const allowed = (user, access, topic) =>
    (ACL[user] || []).some(([a, f]) => (a === access || a === "readwrite") && match(f, topic));

  // ---------------------------------------------------------------- broker
  const broker = {
    mode: "vulnerable",
    subs: [], // {client, filter, cb}
    connect(client) {
      if (this.mode === "vulnerable") return { ok: true, info: "CONNACK 0 — accès anonyme accepté (port 1883, en clair)" };
      if (!client.tls) return { ok: false, info: "Échec : le port 8883 exige TLS 1.2 (handshake refusé)" };
      if (!client.user) return { ok: false, info: "CONNACK 5 — Connection Refused: not authorised (allow_anonymous false)" };
      if (!ACL[client.user]) return { ok: false, info: "CONNACK 4 — bad username or password" };
      return { ok: true, info: `CONNACK 0 — authentifié comme ${client.user} (TLS 1.2)` };
    },
    subscribe(client, filter, cb) { this.subs.push({ client, filter, cb }); },
    unsubscribe(client) { this.subs = this.subs.filter((s) => s.client !== client); },
    publish(client, topic, payload) {
      const body = JSON.stringify(payload);
      if (this.mode === "secure") {
        if (body.length > 8192) return "rejected:size";
        if (!allowed(client.user, "write", topic)) return "denied";
      }
      anomaly.record(topic);
      for (const s of this.subs) {
        if (!match(s.filter, topic)) continue;
        if (this.mode === "secure" && !allowed(s.client.user, "read", topic)) continue;
        s.cb(topic, payload);
      }
      return "ok";
    }
  };

  // ---------------------------------------------------------------- anomaly detection (Node-RED)
  const anomaly = {
    hist: {}, series: Array(60).fill(0), alert: null,
    record(topic) { (this.hist[topic] ||= []).push(simNow); },
    maxRate() {
      let max = 0, top = null;
      for (const [t, arr] of Object.entries(this.hist)) {
        while (arr.length && simNow - arr[0] > 60000) arr.shift();
        if (arr.length > max) { max = arr.length; top = t; }
      }
      return { max, top };
    }
  };

  // ---------------------------------------------------------------- devices (devices/*.py)
  const legit = (user) => ({ user, tls: true });
  const sensorC = legit("sensor_user"), actuatorC = legit("actuator_user"), dashC = legit("dashboard_user");
  const state = { temp: 22.0, gas: 100, door: "CLOSED", light: { state: "OFF", intensity: 0 }, ac: { state: "OFF", mode: "COOL", target_temp: 22 } };

  every(5000, () => { // temperature_sensor.py
    state.temp = Math.max(15, Math.min(30, state.temp + (Math.random() * 0.8 - 0.4)));
    broker.publish(sensorC, "home/salon/temperature/state", { device_id: "temp-salon", room: "salon", type: "temperature", value: +state.temp.toFixed(1), unit: "C" });
  });
  every(5000, () => { // gas_sensor.py
    // Same rule as gas_sensor.py: 5 % chance of a +50..350 ppm spike, otherwise ±15 ppm, bounded 50..800
    state.gas = Math.random() < 0.05 ? state.gas + 50 + Math.random() * 300 : state.gas + (Math.random() * 30 - 15);
    state.gas = Math.max(50, Math.min(800, state.gas));
    broker.publish(sensorC, "home/cuisine/gas/state", { device_id: "gas-cuisine", room: "cuisine", type: "gas", value: Math.round(state.gas), unit: "ppm", status: state.gas > 400 ? "ALERT" : "OK" });
  });
  every(5000, () => { // door_sensor.py
    if (Math.random() < 0.15) state.door = state.door === "OPEN" ? "CLOSED" : "OPEN";
    broker.publish(sensorC, "home/entree/door/state", { device_id: "door-entree", room: "entree", type: "door", state: state.door });
  });
  const pubLight = () => broker.publish(actuatorC, "home/salon/light/state", { device_id: "light-salon", room: "salon", type: "light", ...state.light });
  const pubAc = () => broker.publish(actuatorC, "home/chambre/ac/state", { device_id: "ac-chambre", room: "chambre", type: "ac", ...state.ac });
  every(10000, pubLight); every(10000, pubAc);

  function subscribeActuators() {
    broker.subscribe(actuatorC, "home/salon/light/cmd", (_, p) => { // light_device.py
      const a = String(p.action || "").toUpperCase();
      if (a === "ON" || a === "OFF") { state.light.state = a; if (a === "ON" && !state.light.intensity) state.light.intensity = 80; if (a === "OFF") state.light.intensity = 0; }
      if (p.intensity != null) state.light.intensity = Math.max(0, Math.min(100, +p.intensity));
      pubLight();
    });
    broker.subscribe(actuatorC, "home/chambre/ac/cmd", (_, p) => { // ac_device.py
      const a = String(p.action || "").toUpperCase();
      if (a === "ON" || a === "OFF") state.ac.state = a;
      if (p.mode) state.ac.mode = String(p.mode).toUpperCase();
      if (p.target_temp != null) state.ac.target_temp = +p.target_temp;
      pubAc();
    });
  }

  // ---------------------------------------------------------------- dashboard (Node-RED)
  const ui = { temp: $("#d-temp"), gas: $("#d-gas"), gasSt: $("#d-gas-st"), door: $("#d-door"), light: $("#d-light"), ac: $("#d-ac"), rate: $("#d-rate") };
  function flash(id) { const el = $(id); el.classList.add("flash"); setTimeout(() => el.classList.remove("flash"), 900); }
  function subscribeDashboard() {
    broker.subscribe(dashC, "home/+/+/state", (topic, p) => {
      if (topic.endsWith("temperature/state")) ui.temp.textContent = p.value.toFixed(1) + " °C";
      if (topic.endsWith("gas/state")) {
        ui.gas.textContent = p.value + " ppm"; ui.gasSt.textContent = p.status; ui.gasSt.style.color = p.status === "ALERT" ? "var(--red)" : "var(--green)";
        $("#card-gas").classList.toggle("hot", p.status === "ALERT");
      }
      if (topic.endsWith("door/state")) ui.door.textContent = p.state === "OPEN" ? "Ouverte" : "Fermée";
      if (topic.endsWith("light/state")) { ui.light.textContent = p.state === "ON" ? `ON · ${p.intensity}%` : "OFF"; flash("#card-light"); }
      if (topic.endsWith("ac/state")) { ui.ac.textContent = p.state === "ON" ? `${p.mode} · ${p.target_temp}°` : "OFF"; flash("#card-ac"); }
    });
  }

  const spark = $("#spark"), ctx = spark.getContext("2d");
  every(1000, () => {
    const { max, top } = anomaly.maxRate();
    anomaly.series.push(max); anomaly.series.shift();
    ui.rate.textContent = max;
    const al = $("#anomaly");
    if (max > 30) { al.hidden = false; al.textContent = `🚨 ANOMALIE (règle Node-RED > 30 msg/min) : ${max} msg/min sur ${top}`; }
    else al.hidden = true;
    drawSpark();
  });
  function drawSpark() {
    const w = spark.width = spark.clientWidth * devicePixelRatio, h = spark.height = 70 * devicePixelRatio;
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(40, ...anomaly.series), y = (v) => h - (v / max) * (h - 8) - 4;
    ctx.strokeStyle = "rgba(244,63,94,.6)"; ctx.setLineDash([4 * devicePixelRatio, 4 * devicePixelRatio]); ctx.beginPath(); ctx.moveTo(0, y(30)); ctx.lineTo(w, y(30)); ctx.stroke(); ctx.setLineDash([]);
    ctx.strokeStyle = "#38bdf8"; ctx.lineWidth = 2 * devicePixelRatio; ctx.beginPath();
    anomaly.series.forEach((v, i) => { const x = (i / 59) * w; i ? ctx.lineTo(x, y(v)) : ctx.moveTo(x, y(v)); }); ctx.stroke();
  }

  // ---------------------------------------------------------------- terminal
  const term = $("#term");
  function log(text, cls = "") { const s = document.createElement("span"); if (cls) s.className = cls; s.textContent = text + "\n"; term.appendChild(s); term.scrollTop = term.scrollHeight; }
  const short = (p) => JSON.stringify(p).slice(0, 90);

  function attackerClient() {
    const id = $("#identity").value;
    return { user: id === "sensor_user" ? "sensor_user" : null, tls: id !== "anon", label: id };
  }
  async function attack(kind) {
    const c = attackerClient();
    log(`\n$ python devices/attack_demo.py --scenario ${kind} --port ${broker.mode === "vulnerable" ? 1883 : 8883}${c.user ? " --user " + c.user : ""}`, "b");
    const res = broker.connect(c);
    log((res.ok ? "[+] " : "[-] ") + res.info, res.ok ? (broker.mode === "vulnerable" ? "r" : "y") : "g");
    if (!res.ok) { log("[✓] Attaque bloquée avant même la connexion.", "g"); return; }

    if (kind === "sniff") {
      let n = 0;
      broker.subscribe(c, "#", (t, p) => { n++; if (n <= 14) log(`[INTERCEPTÉ] ${t} -> ${short(p)}`, "r"); });
      log("[+] Abonné à # (TOUS les topics) pendant 30 s…", "m");
      await sleep(30000); broker.unsubscribe(c);
      if (n) log(`[!] ${n} messages interceptés : habitudes des habitants exposées.`, "r");
      else log(`[✓] 0 message reçu : l'ACL n'accorde aucun droit de LECTURE à ${c.user}.`, "g");
    }
    if (kind === "inject") {
      const r1 = broker.publish(c, "home/salon/light/cmd", { action: "ON", intensity: 100 });
      const r2 = broker.publish(c, "home/chambre/ac/cmd", { action: "ON", mode: "HEAT", target_temp: 30 });
      log(`[>] PUBLISH home/salon/light/cmd {"action":"ON","intensity":100}  -> ${verdict(r1)}`, r1 === "ok" ? "r" : "g");
      log(`[>] PUBLISH home/chambre/ac/cmd {"action":"ON","mode":"HEAT","target_temp":30} -> ${verdict(r2)}`, r2 === "ok" ? "r" : "g");
      if (r1 === "ok") log("[!] Les actionneurs ont obéi : regardez le tableau de bord.", "r");
    }
    if (kind === "spoof") {
      const r = broker.publish(c, "home/cuisine/gas/state", { device_id: "gas-cuisine", room: "cuisine", type: "gas", value: 999, unit: "ppm", status: "ALERT" });
      log(`[>] PUBLISH home/cuisine/gas/state {"value":999,"status":"ALERT"} -> ${verdict(r)}`, r === "ok" ? "r" : "g");
      if (r === "ok" && c.user) log("[!] Avec des identifiants de capteur volés, l'ACL autorise encore l'écriture sur gas/state : il faut aussi protéger les secrets des objets (un compte par capteur, rotation, certificats clients).", "y");
      else if (r === "ok") log("[!] Fausse alerte gaz affichée : la mesure n'est pas authentifiée.", "r");
    }
    if (kind === "flood") {
      log("[+] Envoi de 500 messages value=999 sur home/cuisine/gas/state…", "m");
      let ok = 0, denied = 0;
      for (let i = 0; i < 500; i++) {
        const r = broker.publish(c, "home/cuisine/gas/state", { device_id: "gas-cuisine", room: "cuisine", type: "gas", value: 999, unit: "ppm", status: "ALERT" });
        r === "ok" ? ok++ : denied++;
        if (i % 50 === 49) await sleep(400);
      }
      log(`[=] ${ok} acceptés, ${denied} refusés.`, ok ? "r" : "g");
      if (ok && broker.mode === "secure") log("[!] mosquitto.conf limite connexions et taille, pas le débit : c'est la détection Node-RED qui lève l'alerte.", "y");
    }
  }
  const verdict = (r) => (r === "ok" ? "ACCEPTÉ" : r === "denied" ? "REFUSÉ par l'ACL (message ignoré)" : "REFUSÉ (message_size_limit)");

  $$("[data-atk]").forEach((b) => b.addEventListener("click", async () => {
    $$("[data-atk]").forEach((x) => (x.disabled = true));
    try { await attack(b.dataset.atk); } finally { $$("[data-atk]").forEach((x) => (x.disabled = false)); }
  }));
  $$("[data-cmd]").forEach((b) => b.addEventListener("click", () => {
    const cmds = { "light-on": ["home/salon/light/cmd", { action: "ON" }], "light-off": ["home/salon/light/cmd", { action: "OFF" }], "ac-cool": ["home/chambre/ac/cmd", { action: "ON", mode: "COOL", target_temp: 22 }], "ac-off": ["home/chambre/ac/cmd", { action: "OFF" }] };
    const [t, p] = cmds[b.dataset.cmd]; broker.publish(dashC, t, p);
  }));

  // ---------------------------------------------------------------- broker switch
  $$(".bk").forEach((b) => b.addEventListener("click", () => {
    $$(".bk").forEach((x) => x.classList.toggle("active", x === b));
    broker.mode = b.dataset.mode;
    const tag = $("#broker-tag"); tag.textContent = broker.mode === "secure" ? "sécurisé" : "vulnérable"; tag.classList.toggle("ok", broker.mode === "secure");
    anomaly.hist = {};
    log(`\n=== Bascule vers le broker ${broker.mode === "secure" ? "SÉCURISÉ :8883 (TLS + auth + ACL)" : "VULNÉRABLE :1883 (anonyme)"} ===`, broker.mode === "secure" ? "g" : "r");
  }));
  $("#fast").addEventListener("change", (e) => { speed = e.target.checked ? 5 : 1; });

  // ---------------------------------------------------------------- lessons
  const L = [
    ["Tout est exposé", "Un broker anonyme laisse quiconque atteint le port 1883 se connecter sans identifiant.", "Configuration par défaut dangereuse"],
    ["Espionnage", "S'abonner à # suffit à lire toutes les mesures et à déduire la présence des habitants.", "STRIDE : Information disclosure · ATT&CK ICS T0830"],
    ["Injection de commandes", "Sans authentification ni ACL, un attaquant pilote lampes et chauffage.", "STRIDE : Spoofing / Elevation of privilege · T0855"],
    ["Falsification & flood", "De fausses mesures déclenchent ou noient les alertes ; 500 messages saturent le tableau de bord.", "STRIDE : Tampering / DoS · T0814"],
    ["Contre-mesures", "TLS 1.2, allow_anonymous false, mots de passe, ACL par rôle et limites bloquent 3 des 4 attaques. Le flood avec un compte légitime volé reste détecté par Node-RED.", "Défense en profondeur"]
  ];
  $("#lessons").innerHTML = L.map(([h, p, m]) => `<div class="lesson"><h3>${h}</h3><p>${p}</p><div class="map">${m}</div></div>`).join("");

  // ---------------------------------------------------------------- start
  subscribeActuators(); subscribeDashboard();
  log("Simulation démarrée : 5 objets publient sur le broker vulnérable.", "m");
  log("Choisissez une attaque, puis recommencez sur le broker sécurisé.", "m");
  requestAnimationFrame((t) => { last = t; tick(t); });
})();
