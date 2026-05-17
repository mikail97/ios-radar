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

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
IPSW_DEVICE = os.getenv("IPSW_DEVICE", "iPhone16,2")
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "900"))

APPLE_DEV_RELEASES_RSS = "https://developer.apple.com/news/releases/rss/releases.rss"
APPLE_DEV_NEWS_RSS = "https://developer.apple.com/news/rss/news.rss"
APPLE_SECURITY_PAGE = "https://support.apple.com/es-es/100100"
APPLE_DEV_RELEASES_PAGE = "https://developer.apple.com/news/releases/"

WEEKDAYS_ES = [
    "lunes", "martes", "miércoles", "jueves",
    "viernes", "sábado", "domingo"
]


def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().isoformat(timespec="seconds")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def http_get(url, timeout=25):
    headers = {"User-Agent": "Mozilla/5.0 iOS-Radar/3.0"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text


def default_state():
    return {
        "initialized": False,
        "seen_keys": [],
        "hashes": {},
        "latest_security_version": None,
        "latest_ipsw_fingerprint": None,
        "last_summary_fingerprint": None,
        "last_stage_key": None,
        "last_run": None,
        "event_history": []
    }


def load_state():
    state = default_state()

    if STATE_FILE.exists():
        try:
            old = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            state.update(old)
        except Exception:
            pass

    # Migración desde script viejo
    if "seen_events" in state and "seen_keys" not in state:
        state["seen_keys"] = state.get("seen_events", [])

    for key, value in default_state().items():
        state.setdefault(key, value)

    return state


def save_state(state):
    STATE_FILE.write_text(
        json.dumps(state, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


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


def format_date(dt):
    if not dt:
        return "fecha desconocida"

    weekday = WEEKDAYS_ES[dt.weekday()]
    return f"{weekday} {dt.day:02d}/{dt.month:02d}"


def days_since(dt):
    if not dt:
        return None

    delta = now_utc() - dt
    return max(0, delta.total_seconds() / 86400)


def extract_ios_version(text):
    if not text:
        return None

    patterns = [
        r"\biOS\s+([0-9]+(?:\.[0-9]+){0,2})",
        r"\biPadOS\s+([0-9]+(?:\.[0-9]+){0,2})",
        r"\biOS/iPadOS\s+([0-9]+(?:\.[0-9]+){0,2})",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def extract_beta_number(text):
    match = re.search(r"\bbeta\s*([0-9]+)", text or "", re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


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

        kind = classify_title(title)

        item = {
            "source": source_name,
            "title": title,
            "link": link,
            "published": published,
            "datetime": dt.isoformat(timespec="seconds") if dt else None,
            "kind": kind,
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


def fetch_page_hash():
    html = http_get(APPLE_DEV_RELEASES_PAGE)
    return sha256(html)


def build_snapshot():
    errors = []
    rss_items = []
    security_version = None
    ipsw_latest = None
    releases_page_hash = None

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

    try:
        releases_page_hash = fetch_page_hash()
    except Exception as e:
        errors.append(f"Página releases: {e}")

    rss_items.sort(key=lambda x: x.get("datetime") or "", reverse=True)

    return {
        "rss_items": rss_items,
        "security_version": security_version,
        "ipsw_latest": ipsw_latest,
        "releases_page_hash": releases_page_hash,
        "errors": errors,
        "checked_at": now_iso(),
    }


def parse_iso_dt(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def detect_changes(snapshot, state):
    changes = []
    seen_keys = set(state.get("seen_keys", []))

    for item in snapshot["rss_items"][:40]:
        if item["key"] not in seen_keys:
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

    page_hash = snapshot.get("releases_page_hash")
    old_hash = state.get("hashes", {}).get("apple_dev_releases_page")

    if page_hash and old_hash and page_hash != old_hash:
        changes.append({
            "type": "page_hash",
            "kind": "page_change",
            "title": "Cambio en Apple Developer Releases",
            "version": None,
            "source": "Apple Developer",
            "key": make_key("apple_dev_releases_page", page_hash),
        })

    return changes


def update_state_from_snapshot(snapshot, state, changes=None):
    changes = changes or []

    for change in changes:
        if change.get("key"):
            state["seen_keys"].append(change["key"])

    for item in snapshot["rss_items"][:60]:
        state["seen_keys"].append(item["key"])

    state["seen_keys"] = list(dict.fromkeys(state["seen_keys"]))[-1000:]

    if snapshot.get("security_version"):
        state["latest_security_version"] = snapshot["security_version"]

    ipsw = snapshot.get("ipsw_latest")
    if ipsw:
        state["latest_ipsw_fingerprint"] = ipsw["fingerprint"]

    page_hash = snapshot.get("releases_page_hash")
    if page_hash:
        state.setdefault("hashes", {})
        state["hashes"]["apple_dev_releases_page"] = page_hash

    history = state.get("event_history", [])

    for item in snapshot["rss_items"][:60]:
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
    state["last_run"] = now_iso()
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


def probable_window(min_days, max_days):
    today = now_utc().date()
    dates = [today + timedelta(days=i) for i in range(min_days, max_days + 1)]

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
    page_count = sum(1 for c in changes if c["kind"] == "page_change")
    other_count = len(changes) - public_count - rc_count - beta_count - page_count

    parts = []

    if public_count:
        parts.append(f"{public_count} señal pública/final")

    if rc_count:
        parts.append(f"{rc_count} RC")

    if beta_count:
        parts.append(f"{beta_count} beta")

    if page_count:
        parts.append(f"{page_count} cambio en página oficial")

    if other_count:
        parts.append(f"{other_count} señal adicional")

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
            "beta_cadence": None,
        }

    if latest_rc:
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
            recommendation = "Preavisaría: es razonable decir que puede caer esta semana."
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
            recommendation = "Avisaría con cautela: probable, pero algo se puede haber retrasado."
            reasons.append(f"la RC tiene {rc_days:.1f} días")
            stage_key = f"rc:{version}:old"

        else:
            score = 40
            level = "MEDIA"
            eta = "incierta"
            window = "la RC es antigua; esperaría nueva RC o señal pública"
            recommendation = "No daría aviso fuerte todavía."
            reasons.append(f"la RC tiene {rc_days:.1f} días, demasiado para considerarla inminente")
            stage_key = f"rc:{version}:stale"

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
            "beta_cadence": None,
        }

    if latest_beta:
        beta_dt = parse_iso_dt(latest_beta.get("datetime"))
        beta_days = days_since(beta_dt)
        beta_num = latest_beta.get("beta_number")
        version = latest_beta.get("version")
        cadence = average_beta_cadence(events, version)

        if cadence:
            cadence_text = f"ritmo medio de betas: {cadence:.1f} días"
        else:
            cadence_text = "ritmo medio de betas: todavía sin datos suficientes"

        if beta_days is None:
            score = 30
            level = "MEDIA"
            eta = "sin fecha clara"
            window = "esperaría más señales"
            recommendation = "Solo seguimiento, sin preaviso fuerte."
            reasons.append("hay beta, pero sin fecha clara")

        else:
            next_beta_min = max(0, int(5 - beta_days))
            next_beta_max = max(1, int(9 - beta_days))

            if beta_num and beta_num >= 4:
                score = 55
                level = "MEDIA-ALTA"
                eta = "posible nueva beta/RC en 0-7 días; final aún no confirmada"
                window = probable_window(0, 7)
                recommendation = "Yo daría solo preaviso suave: el ciclo está avanzado, pero falta RC."
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
            "beta_cadence": cadence,
        }

    page_change = any(c.get("kind") == "page_change" for c in changes)

    if page_change:
        score = 25
        level = "BAJA-MEDIA"
        eta = "sin días claros"
        window = "requiere más señales"
        recommendation = "No avisaría todavía; solo vigilaría."
        reasons.append("ha cambiado una página oficial, pero no necesariamente por iOS")
        stage_key = "page-change"

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
        "beta_cadence": None,
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

    # Evita spam: los cambios de hash de páginas HTML pueden ser ruido.
    # Solo avisamos por señales reales: beta, RC, IPSW o Apple Security.
    meaningful_changes = [
        c for c in changes
        if c.get("kind") != "page_change"
    ]

    estimation = calculate_estimation(snapshot, state, meaningful_changes)
    stage_key = estimation["stage_key"]
    old_stage = state.get("last_stage_key")

    has_meaningful_changes = bool(meaningful_changes)
    stage_changed = stage_key != old_stage
    strong_stage = estimation["score"] >= 70

    return has_meaningful_changes or (stage_changed and strong_stage)


def run_once(manual_summary=False):
    state = load_state()
    snapshot = build_snapshot()
    changes = detect_changes(snapshot, state)
    first_run = not state.get("initialized", False)

    if first_run:
        update_state_from_snapshot(snapshot, state, changes=changes)
        estimation = calculate_estimation(snapshot, state, [])

        state["last_stage_key"] = estimation["stage_key"]
        save_state(state)

        print(f"[{now_iso()}] Primer arranque: baseline guardada sin spam.")
        print(f"[{now_iso()}] Señales iniciales ignoradas: {len(changes)}")

        if manual_summary:
            send_telegram(format_summary(snapshot, [], state, manual=True))

        return

    if should_send_alert(snapshot, changes, state, manual=manual_summary):
        summary = format_summary(snapshot, changes, state, manual=manual_summary)
        fingerprint = sha256(summary)

        if manual_summary or fingerprint != state.get("last_summary_fingerprint"):
            send_telegram(summary)
            state["last_summary_fingerprint"] = fingerprint
            print(f"[{now_iso()}] Resumen enviado. Cambios: {len(changes)}")
        else:
            print(f"[{now_iso()}] Resumen duplicado no enviado.")
    else:
        print(f"[{now_iso()}] Sin cambios relevantes.")

    estimation = calculate_estimation(snapshot, state, changes)
    state["last_stage_key"] = estimation["stage_key"]

    update_state_from_snapshot(snapshot, state, changes=changes)
    save_state(state)


def test_telegram():
    send_telegram("📱 iOS Radar conectado correctamente. Telegram funciona.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Comprueba una vez y sale")
    parser.add_argument("--summary", action="store_true", help="Envía resumen manual y sale")
    parser.add_argument("--test-telegram", action="store_true", help="Envía mensaje de prueba")
    args = parser.parse_args()

    if args.test_telegram:
        test_telegram()
        return

    if args.once or args.summary:
        run_once(manual_summary=args.summary)
        return

    print("iOS Radar iniciado.")

    while True:
        run_once(manual_summary=False)
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
