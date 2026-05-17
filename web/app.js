const WEEKDAYS = ["domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"];

function $(id) {
  return document.getElementById(id);
}

function parseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

function daysSince(value) {
  const d = parseDate(value);
  if (!d) return null;
  return Math.max(0, (Date.now() - d.getTime()) / 86400000);
}

function fmtDate(value) {
  const d = parseDate(value);
  if (!d) return "fecha desconocida";

  return d.toLocaleString("es-ES", {
    weekday: "short",
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function nextWindow(minDays, maxDays) {
  const today = new Date();
  const dates = [];

  for (let i = minDays; i <= maxDays; i++) {
    const d = new Date(today);
    d.setDate(today.getDate() + i);
    dates.push(d);
  }

  let preferred = dates.filter(d => [1, 2, 3].includes(d.getDay()));

  if (!preferred.length) {
    preferred = dates.filter(d => d.getDay() === 4);
  }

  if (!preferred.length) {
    preferred = dates;
  }

  const first = preferred[0];
  const last = preferred[preferred.length - 1];

  const f = `${WEEKDAYS[first.getDay()]} ${String(first.getDate()).padStart(2, "0")}/${String(first.getMonth() + 1).padStart(2, "0")}`;
  const l = `${WEEKDAYS[last.getDay()]} ${String(last.getDate()).padStart(2, "0")}/${String(last.getMonth() + 1).padStart(2, "0")}`;

  if (f === l) return `${f}, sobre las 19:00 España`;
  return `entre ${f} y ${l}, sobre las 19:00 España`;
}

function latestByKind(events, kind) {
  return events.find(e => e.kind === kind) || null;
}

function describeEvent(event) {
  if (!event) return "no detectada";

  const d = daysSince(event.datetime);
  const suffix = d === null ? "" : ` — hace ${d.toFixed(1)} días`;
  return `${event.title}${suffix}`;
}

function scoreFromState(data) {
  const events = [...(data.event_history || [])]
    .filter(e => e.datetime)
    .sort((a, b) => String(b.datetime).localeCompare(String(a.datetime)));

  const latestRc = latestByKind(events, "rc");
  const latestBeta = latestByKind(events, "beta");

  const ipsw = data.latest_ipsw_fingerprint || "no detectado";
  const security = data.latest_security_version || "no detectada";

  if (latestRc) {
    const rcDays = daysSince(latestRc.datetime);

    if (rcDays !== null && rcDays <= 7) {
      const max = Math.max(1, Math.round(10 - rcDays));
      return {
        level: "MUY ALTA",
        css: "status-high",
        score: 88,
        estimate: `Update probable en 0-${max} días`,
        window: nextWindow(0, Math.min(max, 5)),
        latestRc,
        latestBeta,
        ipsw,
        security
      };
    }

    if (rcDays !== null && rcDays <= 12) {
      return {
        level: "ALTA, pero con cautela",
        css: "status-high",
        score: 72,
        estimate: "Podría caer en cualquier momento, pero la RC empieza a ser vieja",
        window: nextWindow(0, 4),
        latestRc,
        latestBeta,
        ipsw,
        security
      };
    }

    return {
      level: "MEDIA",
      css: "status-mid",
      score: 45,
      estimate: "Hay RC, pero no parece inminente por antigüedad",
      window: "esperaría nueva RC o señal pública",
      latestRc,
      latestBeta,
      ipsw,
      security
    };
  }

  if (latestBeta) {
    const betaDays = daysSince(latestBeta.datetime);
    const betaNumber = latestBeta.beta_number || null;

    if (betaNumber && betaNumber >= 4) {
      return {
        level: "MEDIA-ALTA",
        css: "status-mid",
        score: 55,
        estimate: "Ciclo beta avanzado; posible RC en próximos días",
        window: nextWindow(0, 7),
        latestRc,
        latestBeta,
        ipsw,
        security
      };
    }

    if (betaDays !== null && betaDays >= 5) {
      return {
        level: "MEDIA",
        css: "status-mid",
        score: 42,
        estimate: "Podría tocar nueva beta pronto; final aún no clara",
        window: nextWindow(0, 7),
        latestRc,
        latestBeta,
        ipsw,
        security
      };
    }

    return {
      level: "MEDIA-BAJA",
      css: "status-mid",
      score: 30,
      estimate: "Hay ciclo beta activo, pero no avisaría de update final todavía",
      window: nextWindow(3, 9),
      latestRc,
      latestBeta,
      ipsw,
      security
    };
  }

  return {
    level: "BAJA",
    css: "status-low",
    score: 10,
    estimate: "Sin señales fuertes de update cercano",
    window: "sin ventana probable",
    latestRc,
    latestBeta,
    ipsw,
    security
  };
}

function renderHistory(data) {
  const now = Date.now();
  const events = [...(data.event_history || [])]
    .filter(e => e.datetime)
    .sort((a, b) => String(b.datetime).localeCompare(String(a.datetime)));

  let recent = events.filter(e => {
    const d = parseDate(e.datetime);
    return d && now - d.getTime() <= 3600000;
  });

  if (!recent.length) {
    recent = events.slice(0, 10);
  }

  if (!recent.length) {
    $("history").textContent = "Sin historial todavía.";
    return;
  }

  $("history").innerHTML = recent.map(e => `
    <div class="event">
      <strong>${escapeHtml(e.title || "Sin título")}</strong>
      <small>${escapeHtml(e.kind || "evento")} · ${escapeHtml(e.source || "fuente")} · ${fmtDate(e.datetime)}</small>
    </div>
  `).join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function load() {
  try {
    const res = await fetch(`state.json?ts=${Date.now()}`);

    if (!res.ok) {
      throw new Error("No se pudo leer state.json");
    }

    const data = await res.json();
    const state = scoreFromState(data);

    $("status").textContent = state.level;
    $("status").className = state.css;
    $("estimate").textContent = state.estimate;
    $("window").textContent = state.window;
    $("score").textContent = `${state.score}/100`;
    $("lastRun").textContent = fmtDate(data.last_run);

    $("lastRc").textContent = describeEvent(state.latestRc);
    $("lastBeta").textContent = describeEvent(state.latestBeta);
    $("security").textContent = state.security;
    $("ipsw").textContent = state.ipsw;

    renderHistory(data);
  } catch (err) {
    $("status").textContent = "Sin datos";
    $("status").className = "status-low";
    $("estimate").textContent = err.message;
  }
}

load();
setInterval(load, 60000);
