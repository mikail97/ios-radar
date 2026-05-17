#!/usr/bin/env python3
import os
import re
import json
import time
import argparse
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

import requests
import feedparser
from bs4 import BeautifulSoup
from dotenv import load_dotenv


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "state.json"
WEB_DIR = BASE_DIR / "web"
WEB_STATE_FILE = WEB_DIR / "state.json"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
IPSW_DEVICE = os.getenv("IPSW_DEVICE", "iPhone16,2")
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "900"))

APPLE_DEV_RELEASES_RSS = "https://developer.apple.com/news/releases/rss/releases.rss"
APPLE_DEV_NEWS_RSS = "https://developer.apple.com/news/rss/news.rss"
APPLE_SECURITY_PAGE = "https://support.apple.com/es-es/100100"

WEEKDAYS_ES = [
    "lunes", "martes", "miércoles", "jueves",
    "viernes", "sábado", "domingo"
]


# -------------------------
# Helpers base
# -------------------------

def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().isoformat(timespec="seconds")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def http_get(url, timeout=25):
    headers = {"User-Agent": "Mozilla/5.0 iOS-Radar/4.0"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text


def default_state():
    return {
        "initialized": False,
        "seen_keys": [],
        "latest_security_version": None,
        "latest_ipsw_fingerprint": None,
        "last_summary_fingerprint": None,
        "last_stage_key": None,
        "last_run": None,
        "last_meaningful_run": None,
        "event_history": [],
        "last_estimation": {},
    }


def load_state():
    state = default_state()

    if STATE_FILE.exists():
        try:
            old = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            state.update(old)
        except Exception as e:
            print(f"[WARN] No se pudo leer state.json: {e}")

    # Migraciones desde versiones anteriores
    if "seen_events" in state and not state.get("seen_keys"):
        state["seen_keys"] = state.get("seen_events", [])

    for key, value in default_state().items():
        state.setdefault(key, value)

    return state


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def save_state(state):
    save_json(STATE_FILE, state)


def save_web_state(state):
    """
    Estado público para el dashboard.

    No incluye token, chat_id ni nada sensible.
    """
    public_state = {
        "initialized": state.get("initialized"),
        "latest_security_version": state.get("latest_security_version"),
        "latest_ipsw_fingerprint": state.get("latest_ipsw_fingerprint"),
        "last_run": state.get("last_run"),
        "last_meaningful_run": state.get("last_meaningful_run"),
        "last_stage_key": state.get("last_stage_key"),
        "last_estimation": state.get("last_estimation", {}),
        "event_history": state.get("event_history", [])[:80],
    }

    save_json(WEB_STATE_FILE, public_state)


def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "pendiente":
        print("[TELEGRAM OFF]")
        print(message)
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    r = requests.post(url, json=payload, timeout=25)
    r.raise_for_status()


# -------------------------
# Parsing
# -------------------------

def clean_title(title):
    return re.sub(r"\s+", " ", title or "").strip()


def make_key(source, title, extra=""):
    return sha256(f"{source}|{title}|{extra}")


def parse_feed_datetime(entry):
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return None

    try:
        return datetime(*parsed[:6], tzinfo=timezone.utc)
    except Exception:
        return None


def parse_iso_dt(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def days_since(dt):
    if not dt:
        return None

    delta = now_utc() - dt
    return max(0, delta.total_seconds() / 86400)


def format_date(dt):
    if not dt:
        return "fecha desconocida"

    weekday = WEEKDAYS_ES[dt.weekday()]
    return f"{weekday} {dt.day:02d}/{dt.month:02d}"


def extract_ios_version(text):
    patterns = [
        r"\biOS\s+([0-9]+(?:\.[0-9]+){0,2})",
        r"\biPadOS\s+([0-9]+(?:\.[0-9]+){0,2})",
        r"\biOS/iPadOS\s+([0-9]+(?:\.[0-9]+){0,2})",
    ]

    for pattern in patterns:
        match = re.search(pattern, text or "", re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def extract_beta_number(text):
    match = re.search(r"\bbeta\s*([0-9]+)", text or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def extract_rc_number(text):
    text = text or ""

    patterns = [
        r"\brelease candidate\s*([0-9]+)",
        r"\brc\s*([0-9]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return int(match.group(1))

    if re.search(r"\brelease candidate\b|\brc\b", text, re.IGNORECASE):
        return 1

    return None


def classify_title(title):
    t = title.lower()

    if "release candidate" in t or re.search(r"\brc\b", t):
        return "rc"

    if "beta" in t:
        return "beta"

    if re.search(r"\bios\s+\d|\bipados\s+\d", t):
        return "public_possible"

    return "other"


# -------------------------
# Fuentes
# -------------------------

def fetch_rss_items(source_name, url):
    items = []
    feed = feedparser.parse(url)

    for entry in feed.entries[:60]:
        title = clean_title(entry.get("title", ""))
        link = entry.get("link", "")
        published = entry.get("published", "") or entry.get("updated", "")
        dt = parse_feed_datetime(entry)

        if not re.search(r"\biOS\b|\biPadOS\b", title, re.IGNORECASE):
            continue

        item = {
            "source": source_name,
            "title": title,
            "link": link,
            "published": published,
            "datetime": dt.isoformat(timespec="seconds") if dt else None,
            "kind": classify_title(title),
            "version": extract_ios_version(title),
            "beta_number": extract_beta_number(title),
            "rc_number": extract_rc_number(title),
            "key": make_key(source_name, title, link),
        }

        items.append(item)

    items.sort(key=lambda x: x.get("datetime") or "", reverse=True)
    return items


def fetch_security_version():
    html = http_get(APPLE_SECURITY_PAGE)
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)

    patterns = [
        r"versi[oó]n m[aá]s reciente de iOS y iPadOS es\s+([0-9]+(?:\.[0-9]+){0,2})",
        r"latest version of iOS and iPadOS is\s+([0-9]+(?:\.[0-9]+){0,2})",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def fetch_ipsw_latest():
    url = f"https://api.ipsw.me/v4/device/{IPSW_DEVICE}?type=ipsw"
    r = requests.get(url, timeout=25)
    r.raise_for_status()

    data = r.json()
    firmwares = data.get("firmwares", [])
    signed = [fw for fw in firmwares if fw.get("signed")]

    if not signed:
        return None

    latest = signed[0]

    version = latest.get("version")
    buildid = latest.get("buildid", "")
    releasedate = latest.get("releasedate", "")
    fingerprint = f"{version}-{buildid}"

    return {
        "version": version,
        "buildid": buildid,
        "releasedate": releasedate,
        "fingerprint": fingerprint,
    }


def build_snapshot():
    errors = []
    rss_items = []
    security_version = None
    ipsw_latest = None

    try:
        rss_items.extend(fetch_rss_items("Apple Developer Releases", APPLE_DEV_RELEASES_RSS))
    except Exception as e:
        errors.append(f"RSS releases: {e}")

    try:
        rss_items.extend(fetch_rss_items("Apple Developer News", APPLE_DEV_NEWS_RSS))
    except Exception as e:
        errors.append(f"RSS news: {e}")

    try:
        security_version = fetch_security_version()
    except Exception as e:
        errors.append(f"Apple Security: {e}")

    try:
        ipsw_latest = fetch_ipsw_latest()
    except Exception as e:
        errors.append(f"IPSW: {e}")

    rss_items.sort(key=lambda x: x.get("datetime") or "", reverse=True)

    return {
        "rss_items": rss_items,
        "security_version": security_version,
        "ipsw_latest": ipsw_latest,
        "errors": errors,
        "checked_at": now_iso(),
    }


# -------------------------
# Detección y estado
# -------------------------

def detect_changes(snapshot, state):
    changes = []
    seen_keys = set(state.get("seen_keys", []))

    for item in snapshot["rss_items"][:40]:
        if item["key"] not in seen_keys:
            if item["kind"] in ("beta", "rc", "public_possible"):
                changes.append({
                    "type": "rss",
                    "kind": item["kind"],
                    "title": item["title"],
                    "version": item.get("version"),
                    "source": item["source"],
                    "key": item["key"],
                })

    security_version = snapshot.get("security_version")
    if security_version and state.get("latest_security_version") != security_version:
        changes.append({
            "type": "security",
            "kind": "public",
            "title": f"Apple Security marca iOS/iPadOS {security_version}",
            "version": security_version,
            "source": "Apple Security",
            "key": make_key("security", security_version),
        })

    ipsw = snapshot.get("ipsw_latest")
    if ipsw and state.get("latest_ipsw_fingerprint") != ipsw["fingerprint"]:
        changes.append({
            "type": "ipsw",
            "kind": "public",
            "title": f"IPSW firmado iOS {ipsw['version']} build {ipsw['buildid']}",
            "version": ipsw["version"],
            "source": "IPSW",
            "key": make_key("ipsw", ipsw["fingerprint"]),
        })

    return changes


def update_state_from_snapshot(snapshot, state, changes=None, meaningful=False, update_scan_time=True):
    changes = changes or []

    for change in changes:
        if change.get("key"):
            state["seen_keys"].append(change["key"])

    # Marcar entradas RSS como vistas para evitar spam histórico.
    for item in snapshot["rss_items"][:60]:
        state["seen_keys"].append(item["key"])

    state["seen_keys"] = list(dict.fromkeys(state["seen_keys"]))[-1000:]

    if snapshot.get("security_version"):
        state["latest_security_version"] = snapshot["security_version"]

    ipsw = snapshot.get("ipsw_latest")
    if ipsw:
        state["latest_ipsw_fingerprint"] = ipsw["fingerprint"]

    history = state.get("event_history", [])

    for item in snapshot["rss_items"][:60]:
        if item.get("kind") in ("beta", "rc", "public_possible"):
            history.append({
                "key": item["key"],
                "source": item["source"],
                "title": item["title"],
                "kind": item["kind"],
                "version": item.get("version"),
                "beta_number": item.get("beta_number"),
                "rc_number": item.get("rc_number"),
                "datetime": item.get("datetime"),
            })

    dedup = {}
    for item in history:
        if item.get("key"):
            dedup[item["key"]] = item

    history = list(dedup.values())
    history.sort(key=lambda x: x.get("datetime") or "", reverse=True)

    state["event_history"] = history[:500]

    if update_scan_time:
        state["last_run"] = snapshot["checked_at"]

    if meaningful:
        state["last_meaningful_run"] = snapshot["checked_at"]

    state["initialized"] = True


def combined_events(snapshot, state):
    items = []

    for item in snapshot.get("rss_items", []):
        items.append(item)

    for item in state.get("event_history", []):
        items.append(item)

    dedup = {}
    for item in items:
        key = item.get("key") or make_key(item.get("source", ""), item.get("title", ""))
        dedup[key] = item

    result = list(dedup.values())
    result.sort(key=lambda x: x.get("datetime") or "", reverse=True)
    return result


def latest_event(events, kinds):
    for item in events:
        if item.get("kind") in kinds:
            return item
    return None


def average_beta_cadence(events, version):
    if not version:
        return None

    betas = [
        e for e in events
        if e.get("kind") == "beta"
        and e.get("version") == version
        and e.get("datetime")
    ]

    betas.sort(key=lambda x: x["datetime"])

    if len(betas) < 2:
        return None

    deltas = []

    for a, b in zip(betas, betas[1:]):
        da = parse_iso_dt(a["datetime"])
        db = parse_iso_dt(b["datetime"])

        if da and db:
            deltas.append((db - da).total_seconds() / 86400)

    if not deltas:
        return None

    return sum(deltas) / len(deltas)


# -------------------------
# Estimación
# -------------------------

def probable_window(min_days, max_days):
    today = now_utc().date()
    dates = [today + timedelta(days=i) for i in range(min_days, max_days + 1)]

    # Apple suele publicar mucho lunes/martes/miércoles.
    preferred = [d for d in dates if d.weekday() in (0, 1, 2)]

    if not preferred:
        preferred = [d for d in dates if d.weekday() == 3]

    if not preferred:
        preferred = dates

    first = preferred[0]
    last = preferred[-1]

    if first == last:
        return f"{WEEKDAYS_ES[first.weekday()]} {first.day:02d}/{first.month:02d}, sobre las 19:00 España"

    return (
        f"entre {WEEKDAYS_ES[first.weekday()]} {first.day:02d}/{first.month:02d} "
        f"y {WEEKDAYS_ES[last.weekday()]} {last.day:02d}/{last.month:02d}, "
        f"sobre las 19:00 España"
    )


def compact_changes(changes):
    if not changes:
        return "sin señales nuevas"

    public_count = sum(1 for c in changes if c["kind"] == "public")
    rc_count = sum(1 for c in changes if c["kind"] == "rc")
    beta_count = sum(1 for c in changes if c["kind"] == "beta")
    possible_public_count = sum(1 for c in changes if c["kind"] == "public_possible")

    parts = []

    if public_count:
        parts.append(f"{public_count} señal pública/final")

    if rc_count:
        parts.append(f"{rc_count} RC")

    if beta_count:
        parts.append(f"{beta_count} beta")

    if possible_public_count:
        parts.append(f"{possible_public_count} entrada pública posible")

    return ", ".join(parts)


def calculate_estimation(snapshot, state, changes):
    events = combined_events(snapshot, state)

    latest_rc = latest_event(events, ["rc"])
    latest_beta = latest_event(events, ["beta"])

    public_change = any(c.get("kind") == "public" for c in changes)
    ipsw = snapshot.get("ipsw_latest")
    security_version = snapshot.get("security_version")

    reasons = []
    score = 0
    eta = "sin estimación clara"
    window = "sin ventana probable"
    recommendation = "No avisaría todavía."
    level = "BAJA"
    stage_key = "low"

    if public_change:
        score = 100
        level = "YA DISPONIBLE"
        eta = "0 días"
        window = "ya está saliendo o ya está publicado"
        recommendation = "Avisaría ya: el update parece disponible o en despliegue."
        reasons.append("ha cambiado Apple Security o ha aparecido un IPSW firmado")
        stage_key = f"public:{security_version}:{ipsw['fingerprint'] if ipsw else ''}"

    elif latest_rc:
        rc_dt = parse_iso_dt(latest_rc.get("datetime"))
        rc_days = days_since(rc_dt)
        rc_num = latest_rc.get("rc_number") or 1
        version = latest_rc.get("version") or "desconocida"

        if rc_days is None:
            score = 70
            level = "ALTA"
            eta = "aprox. 1-7 días"
            window = probable_window(1, 7)
            recommendation = "Preavisaría: hay RC detectada."
            reasons.append("hay una Release Candidate reciente")
            stage_key = f"rc:{version}:unknown"

        elif rc_days <= 1:
            score = 78 if rc_num == 1 else 88
            level = "ALTA"
            eta = "aprox. 2-7 días" if rc_num == 1 else "aprox. 1-4 días"
            window = probable_window(1, 7 if rc_num == 1 else 4)
            recommendation = "Preavisaría: puede caer esta semana."
            reasons.append(f"la RC salió hace {rc_days:.1f} días")
            stage_key = f"rc:{version}:fresh"

        elif rc_days <= 7:
            score = 88 if rc_num == 1 else 94
            level = "MUY ALTA"
            remaining_max = max(1, int(10 - rc_days))
            eta = f"aprox. 0-{remaining_max} días"
            window = probable_window(0, min(remaining_max, 5))
            recommendation = "Avisaría como probable esta semana."
            reasons.append(f"hay RC desde hace {rc_days:.1f} días")
            reasons.append("la final suele caer pocos días después de una RC")
            stage_key = f"rc:{version}:window"

        elif rc_days <= 12:
            score = 72
            level = "ALTA PERO RARA"
            eta = "podría caer en cualquier momento, pero la RC ya empieza a ser vieja"
            window = probable_window(0, 4)
            recommendation = "Avisaría con cautela: probable, pero puede haberse retrasado."
            reasons.append(f"la RC tiene {rc_days:.1f} días")
            stage_key = f"rc:{version}:old"

        else:
            score = 40
            level = "MEDIA"
            eta = "incierta"
            window = "la RC es antigua; esperaría nueva RC o señal pública"
            recommendation = "No daría aviso fuerte todavía."
            reasons.append(f"la RC tiene {rc_days:.1f} días")
            stage_key = f"rc:{version}:stale"

    elif latest_beta:
        beta_dt = parse_iso_dt(latest_beta.get("datetime"))
        beta_days = days_since(beta_dt)
        beta_num = latest_beta.get("beta_number")
        version = latest_beta.get("version")
        cadence = average_beta_cadence(events, version)

        cadence_text = (
            f"ritmo medio de betas: {cadence:.1f} días"
            if cadence else
            "ritmo medio de betas: todavía sin datos suficientes"
        )

        if beta_days is None:
            score = 30
            level = "MEDIA"
            eta = "sin fecha clara"
            window = "esperaría más señales"
            recommendation = "Solo seguimiento, sin preaviso fuerte."
            reasons.append("hay beta, pero sin fecha clara")
            stage_key = f"beta:{version}:unknown"

        else:
            next_beta_min = max(0, int(5 - beta_days))
            next_beta_max = max(1, int(9 - beta_days))

            if beta_num and beta_num >= 4:
                score = 55
                level = "MEDIA-ALTA"
                eta = "posible nueva beta/RC en 0-7 días; final aún no confirmada"
                window = probable_window(0, 7)
                recommendation = "Daría solo preaviso suave: ciclo avanzado, pero falta RC."
                reasons.append(f"beta {beta_num} detectada hace {beta_days:.1f} días")
                reasons.append(cadence_text)
                stage_key = f"beta:{version}:{beta_num}:advanced"

            elif beta_days >= 5:
                score = 42
                level = "MEDIA"
                eta = f"posible nueva beta en {next_beta_min}-{next_beta_max} días"
                window = probable_window(next_beta_min, min(next_beta_max, 7))
                recommendation = "Seguimiento. Todavía no avisaría como update final cercano."
                reasons.append(f"última beta hace {beta_days:.1f} días")
                reasons.append(cadence_text)
                stage_key = f"beta:{version}:{beta_num}:next-soon"

            else:
                score = 30
                level = "MEDIA-BAJA"
                eta = f"posible nueva beta en {next_beta_min}-{next_beta_max} días"
                window = probable_window(next_beta_min, min(next_beta_max, 9))
                recommendation = "No avisaría todavía; solo hay ciclo beta activo."
                reasons.append(f"última beta hace {beta_days:.1f} días")
                reasons.append(cadence_text)
                stage_key = f"beta:{version}:{beta_num}:fresh"

    return {
        "score": score,
        "level": level,
        "eta": eta,
        "window": window,
        "recommendation": recommendation,
        "reasons": reasons,
        "stage_key": stage_key,
        "latest_rc": latest_rc,
        "latest_beta": latest_beta,
    }


def item_line(item):
    if not item:
        return "no detectada"

    title = item.get("title") or "sin título"
    dt = parse_iso_dt(item.get("datetime"))

    if dt:
        d = days_since(dt)
        return f"{title} — {format_date(dt)} / hace {d:.1f} días"

    return title


def format_summary(snapshot, changes, state, manual=False):
    estimation = calculate_estimation(snapshot, state, changes)

    ipsw = snapshot.get("ipsw_latest")
    ipsw_line = "no detectado"

    if ipsw:
        ipsw_line = f"iOS {ipsw['version']} build {ipsw['buildid']}"

    security_version = snapshot.get("security_version") or "no detectada"
    mode = "Resumen manual" if manual else "Alerta resumen"

    msg = (
        f"📱 <b>iOS Radar — {mode}</b>\n\n"
        f"<b>Estado:</b> {estimation['level']}\n"
        f"<b>Puntuación:</b> {estimation['score']}/100\n"
        f"<b>Estimación:</b> {estimation['eta']}\n"
        f"<b>Ventana probable:</b> {estimation['window']}\n\n"
        f"<b>Qué haría:</b>\n"
        f"{estimation['recommendation']}\n\n"
        f"<b>Señales nuevas:</b> {compact_changes(changes)}\n\n"
        f"<b>Última RC:</b>\n"
        f"{item_line(estimation['latest_rc'])}\n\n"
        f"<b>Última beta:</b>\n"
        f"{item_line(estimation['latest_beta'])}\n\n"
        f"<b>Versión pública Apple Security:</b> {security_version}\n"
        f"<b>Último IPSW firmado:</b> {ipsw_line}\n"
    )

    if estimation["reasons"]:
        msg += "\n<b>Motivos:</b>\n"
        for reason in estimation["reasons"][:4]:
            msg += f"• {reason}\n"

    if snapshot["errors"]:
        msg += "\n<b>Errores parciales:</b>\n"
        for error in snapshot["errors"][:3]:
            msg += f"• {error}\n"

    msg += f"\nComprobado: <code>{snapshot['checked_at']}</code>"

    return msg


def should_send_alert(snapshot, changes, state, manual=False):
    if manual:
        return True

    meaningful_changes = [
        c for c in changes
        if c.get("kind") in ("beta", "rc", "public", "public_possible")
    ]

    estimation = calculate_estimation(snapshot, state, meaningful_changes)
    stage_key = estimation["stage_key"]
    old_stage = state.get("last_stage_key")

    has_meaningful_changes = bool(meaningful_changes)
    stage_changed = stage_key != old_stage
    strong_stage = estimation["score"] >= 70

    return has_meaningful_changes or (stage_changed and strong_stage)


# -------------------------
# Ejecución
# -------------------------

def run_once(manual_summary=False, github_mode=False):
    state = load_state()
    snapshot = build_snapshot()
    changes = detect_changes(snapshot, state)

    meaningful_changes = [
        c for c in changes
        if c.get("kind") in ("beta", "rc", "public", "public_possible")
    ]

    first_run = not state.get("initialized", False)

    if first_run:
        update_state_from_snapshot(
            snapshot,
            state,
            changes=changes,
            meaningful=False,
            update_scan_time=True,
        )

        estimation = calculate_estimation(snapshot, state, [])
        state["last_stage_key"] = estimation["stage_key"]
        state["last_estimation"] = estimation

        save_state(state)
        save_web_state(state)

        print(f"[{now_iso()}] Primer arranque: baseline guardada sin spam.")
        print(f"[{now_iso()}] Señales iniciales ignoradas: {len(changes)}")

        if manual_summary:
            send_telegram(format_summary(snapshot, [], state, manual=True))

        return True

    estimation = calculate_estimation(snapshot, state, meaningful_changes)
    state["last_estimation"] = estimation

    sent = False

    if should_send_alert(snapshot, meaningful_changes, state, manual=manual_summary):
        summary = format_summary(snapshot, meaningful_changes, state, manual=manual_summary)
        fingerprint = sha256(summary)

        if manual_summary or fingerprint != state.get("last_summary_fingerprint"):
            send_telegram(summary)
            state["last_summary_fingerprint"] = fingerprint
            sent = True
            print(f"[{now_iso()}] Resumen enviado. Cambios: {len(meaningful_changes)}")
        else:
            print(f"[{now_iso()}] Resumen duplicado no enviado.")
    else:
        print(f"[{now_iso()}] Sin cambios relevantes.")

    # Modo normal LXC:
    # Guarda siempre para que dashboard local muestre último scan.
    #
    # Modo GitHub:
    # No guarda cada 15 minutos para evitar 96 commits/día.
    # Solo guarda si hay cambios reales, alerta enviada o resumen manual.
    should_save = (
        not github_mode
        or bool(meaningful_changes)
        or manual_summary
        or sent
    )

    if should_save:
        update_state_from_snapshot(
            snapshot,
            state,
            changes=changes,
            meaningful=bool(meaningful_changes) or sent,
            update_scan_time=True,
        )
        state["last_stage_key"] = estimation["stage_key"]
        state["last_estimation"] = estimation

        save_state(state)
        save_web_state(state)
        return True

    return False


def test_telegram():
    send_telegram("📱 iOS Radar conectado correctamente. Telegram funciona.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Comprueba una vez y sale")
    parser.add_argument("--summary", action="store_true", help="Envía resumen manual y sale")
    parser.add_argument("--github", action="store_true", help="Modo GitHub Actions")
    parser.add_argument("--test-telegram", action="store_true", help="Envía mensaje de prueba")
    args = parser.parse_args()

    if args.test_telegram:
        test_telegram()
        return

    if args.github:
        changed = run_once(manual_summary=False, github_mode=True)
        print(f"[{now_iso()}] GitHub mode. Files changed: {changed}")
        return

    if args.once or args.summary:
        run_once(manual_summary=args.summary, github_mode=False)
        return

    print("iOS Radar iniciado.")

    while True:
        run_once(manual_summary=False, github_mode=False)
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
