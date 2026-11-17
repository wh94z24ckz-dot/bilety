"""
TicketFlow — panel sprzedaży i kontroli biletów
Uruchomienie:
  pip install streamlit qrcode[pil]
  streamlit run app.py

Pierwsze uruchomienie:
  Domyślne konto administratora: admin
  Hasło: zmien-me-przed-uruchomieniem

Przed wdrożeniem publicznym ustaw zmienne środowiskowe:
  TICKETFLOW_ADMIN_USER
  TICKETFLOW_ADMIN_PASSWORD
  TICKETFLOW_QR_SECRET (stały, losowy sekret do podpisywania QR; wymagany na hostingu)

To wersja MVP. Przed użyciem komercyjnym dodaj HTTPS, kopie zapasowe,
limity prób logowania i skonfiguruj hosting/bazę danych.
"""

import os
import io
import json
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path

import qrcode
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("TICKETFLOW_DB_PATH", str(APP_DIR / "ticketflow.sqlite3")))

st.set_page_config(
    page_title="TicketFlow | Bilety i promotorzy",
    page_icon="🎟️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Wygląd ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');

/* Dark theme with strong text contrast */
:root {
  color-scheme: dark;
  --tf-bg: #080b12;
  --tf-panel: #111827;
  --tf-panel-2: #172033;
  --tf-border: #293449;
  --tf-text: #f8fafc;
  --tf-muted: #cbd5e1;
  --tf-accent: #8b5cf6;
}
html, body, [class*="css"], [data-testid="stAppViewContainer"] {
  font-family: 'DM Sans', sans-serif !important;
  color: var(--tf-text) !important;
}
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
  background: var(--tf-bg) !important;
  color: var(--tf-text) !important;
}
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1450px; }
h1, h2, h3, h4, h5, h6, p, label, span, li, small, strong, em,
[data-testid="stMarkdownContainer"], [data-testid="stWidgetLabel"] {
  color: var(--tf-text);
}
h1, h2, h3 { font-family: 'Manrope', sans-serif !important; letter-spacing: -0.035em; }
.hero {
  background: linear-gradient(120deg, #111827 0%, #312e81 55%, #5b21b6 100%);
  border: 1px solid #433878;
  border-radius: 22px; padding: 28px 32px; color: #ffffff !important; margin-bottom: 22px;
}
.hero h1 { color: #ffffff !important; font-size: 2.05rem; margin: 0 0 7px 0; }
.hero p { color: #f1f5f9 !important; margin: 0; font-size: 1rem; }
div[data-testid="stMetric"] {
  background: var(--tf-panel) !important; border: 1px solid var(--tf-border);
  padding: 18px 20px; border-radius: 16px; box-shadow: 0 4px 16px rgba(0, 0, 0, .18);
}
div[data-testid="stMetricLabel"], div[data-testid="stMetricLabel"] * { color: #cbd5e1 !important; }
div[data-testid="stMetricValue"], div[data-testid="stMetricValue"] * { color: #ffffff !important; font-weight: 800; }
.stButton > button, .stDownloadButton > button, button[kind="secondary"], button[kind="primary"] {
  border-radius: 10px; min-height: 42px; font-weight: 700;
}
.stButton > button[kind="primary"], button[kind="primary"], .stDownloadButton > button {
  background: #7c3aed !important; color: #ffffff !important; border: 1px solid #8b5cf6 !important;
}
.stButton > button[kind="secondary"], button[kind="secondary"] {
  background: #1f2937 !important; color: #ffffff !important; border: 1px solid #475569 !important;
}
div[data-testid="stSidebar"] { background: #05070c !important; border-right: 1px solid #293449; }
div[data-testid="stSidebar"] * { color: #f8fafc !important; }
.stTextInput input, .stNumberInput input, .stDateInput input, .stTimeInput input,
.stTextArea textarea, [data-baseweb="select"] > div, [data-baseweb="input"] > div {
  background: #111827 !important; color: #ffffff !important; border-color: #475569 !important;
}
.stTextInput input::placeholder, .stTextArea textarea::placeholder { color: #94a3b8 !important; }
[data-baseweb="select"] *, [data-baseweb="popover"] *, [role="listbox"] * {
  color: #f8fafc !important;
}
[data-baseweb="popover"], [role="listbox"] { background: #111827 !important; }
div[data-testid="stExpander"], div[data-testid="stForm"], div[data-testid="stAlert"],
div[data-testid="stVerticalBlockBorderWrapper"] > div {
  border-color: var(--tf-border) !important;
}
div[data-testid="stVerticalBlockBorderWrapper"] > div,
div[data-testid="stForm"] {
  background: var(--tf-panel) !important;
}
[data-testid="stDataFrame"], [data-testid="stTable"] {
  background: var(--tf-panel) !important;
}
[data-testid="stCaptionContainer"], .small-muted, .stCaption {
  color: var(--tf-muted) !important;
}
hr { border-color: var(--tf-border) !important; }
a { color: #c4b5fd !important; }
</style>
""", unsafe_allow_html=True)


# ---------- Baza danych ----------
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 250_000).hex()
    return salt, digest


def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','promoter')),
            commission REAL NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            venue TEXT DEFAULT '',
            event_date TEXT NOT NULL,
            ticket_price REAL NOT NULL DEFAULT 0,
            capacity INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            event_id INTEGER NOT NULL REFERENCES events(id),
            buyer_name TEXT NOT NULL,
            buyer_email TEXT DEFAULT '',
            price REAL NOT NULL,
            promoter_id INTEGER REFERENCES users(id),
            status TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','used','cancelled')),
            created_at TEXT NOT NULL,
            checked_at TEXT,
            checked_by INTEGER REFERENCES users(id)
        );
        """)
        admin_user = os.getenv("TICKETFLOW_ADMIN_USER", "admin")
        admin_password = os.getenv("TICKETFLOW_ADMIN_PASSWORD", "zmien-me-przed-uruchomieniem")
        existing = con.execute("SELECT id FROM users WHERE username=?", (admin_user,)).fetchone()
        if not existing:
            salt, digest = password_hash(admin_password)
            con.execute(
                "INSERT INTO users(username,full_name,salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
                (admin_user, "Administrator", salt, digest, "admin", datetime.now().isoformat(timespec="seconds"))
            )


init_db()


def verify_login(username, password):
    with connect() as con:
        user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username.strip(),)).fetchone()
    if not user:
        return None
    _, digest = password_hash(password, user["salt"])
    if hmac.compare_digest(digest, user["password_hash"]):
        return dict(user)
    return None


def money(value):
    return f"{float(value or 0):,.2f} zł".replace(",", " ").replace(".", ",")


def get_events(active_only=False):
    with connect() as con:
        sql = "SELECT * FROM events"
        if active_only:
            sql += " WHERE active=1"
        return con.execute(sql + " ORDER BY event_date DESC, id DESC").fetchall()


def qr_secret():
    """Stały sekret do podpisywania QR. Na hostingu ustaw TICKETFLOW_QR_SECRET w ustawieniach sekretów."""
    env_secret = os.getenv("TICKETFLOW_QR_SECRET", "").strip()
    if env_secret:
        return env_secret.encode("utf-8")

    secret_path = Path(os.getenv("TICKETFLOW_QR_SECRET_FILE", str(APP_DIR / "ticketflow_qr_secret.key")))
    try:
        if secret_path.exists():
            return secret_path.read_bytes()
        secret = secrets.token_bytes(32)
        # Tryb tworzenia wyłączny ogranicza ryzyko nadpisania sekretu przy równoczesnym starcie.
        try:
            with open(secret_path, "xb") as f:
                f.write(secret)
            return secret
        except FileExistsError:
            return secret_path.read_bytes()
    except OSError:
        # Awaryjnie dla środowisk tylko do odczytu; na wdrożeniu należy ustawić TICKETFLOW_QR_SECRET.
        return os.getenv("TICKETFLOW_ADMIN_PASSWORD", "ticketflow-dev-secret-change-me").encode("utf-8")


def make_qr_payload(ticket):
    """QR zawiera dane biletu/uczestnika, a nie sam losowy kod."""
    payload = {
        "type": "ticketflow_ticket",
        "ticket_id": int(ticket["id"]),
        "event": str(ticket["event_name"]),
        "event_date": str(ticket["event_date"]),
        "buyer_name": str(ticket["buyer_name"]),
        "buyer_email": str(ticket["buyer_email"] or ""),
        "price": round(float(ticket["price"]), 2),
        "created_at": str(ticket["created_at"]),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    signature = hmac.new(qr_secret(), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return json.dumps({"ticket": payload, "signature": signature}, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def qr_png(payload_text):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=10,
        border=4,
    )
    qr.add_data(payload_text)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    buffer.seek(0)
    return buffer.getvalue()


def parse_ticket_qr(scanned_text):
    """Zwraca zweryfikowany bilet z QR albo None + komunikat błędu."""
    scanned_text = (scanned_text or "").strip()
    if not scanned_text:
        return None, "Wpisz lub zeskanuj zawartość kodu QR."

    try:
        envelope = json.loads(scanned_text)
    except (json.JSONDecodeError, TypeError):
        # Wsteczna kompatybilność ze starymi QR zawierającymi wewnętrzny kod biletu.
        with connect() as con:
            ticket = con.execute("""
                SELECT t.*, e.name AS event_name, e.event_date, u.full_name AS promoter_name
                FROM tickets t JOIN events e ON e.id=t.event_id
                LEFT JOIN users u ON u.id=t.promoter_id
                WHERE t.code=?
            """, (scanned_text,)).fetchone()
        return (dict(ticket), None) if ticket else (None, "Nie rozpoznano QR. Zeskanuj pełną zawartość kodu z nowej wersji biletu.")

    payload = envelope.get("ticket") if isinstance(envelope, dict) else None
    signature = envelope.get("signature") if isinstance(envelope, dict) else None
    if not isinstance(payload, dict) or not isinstance(signature, str) or payload.get("type") != "ticketflow_ticket":
        return None, "Ten kod QR nie jest biletem TicketFlow."

    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    expected = hmac.new(qr_secret(), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None, "Podpis QR jest nieprawidłowy. Kod mógł zostać zmieniony lub pochodzić z innej instalacji."

    try:
        ticket_id = int(payload["ticket_id"])
    except (KeyError, TypeError, ValueError):
        return None, "QR nie zawiera prawidłowego identyfikatora biletu."

    with connect() as con:
        row = con.execute("""
            SELECT t.*, e.name AS event_name, e.event_date, u.full_name AS promoter_name
            FROM tickets t JOIN events e ON e.id=t.event_id
            LEFT JOIN users u ON u.id=t.promoter_id
            WHERE t.id=?
        """, (ticket_id,)).fetchone()

    if not row:
        return None, "Nie znaleziono biletu w bazie danych."
    ticket = dict(row)
    # Sprawdź, czy dane zapisane w QR nadal odpowiadają rekordowi w bazie.
    expected_fields = {
        "event": ticket["event_name"],
        "event_date": ticket["event_date"],
        "buyer_name": ticket["buyer_name"],
        "buyer_email": ticket["buyer_email"] or "",
        "price": round(float(ticket["price"]), 2),
        "created_at": ticket["created_at"],
    }
    for key, value in expected_fields.items():
        if payload.get(key) != value:
            return None, "Dane w QR nie zgadzają się z biletem w bazie."
    return ticket, None


def get_stats(event_id=None, promoter_id=None):
    clauses, params = [], []
    if event_id:
        clauses.append("event_id=?")
        params.append(int(event_id))
    if promoter_id:
        clauses.append("promoter_id=?")
        params.append(int(promoter_id))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with connect() as con:
        row = con.execute(f"""
            SELECT COUNT(*) AS sold,
                   COALESCE(SUM(price),0) AS revenue,
                   SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) AS used,
                   SUM(CASE WHEN status='valid' THEN 1 ELSE 0 END) AS valid,
                   SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) AS cancelled
            FROM tickets {where}
        """, params).fetchone()
    return dict(row)


def ticket_rows(event_id=None, promoter_id=None):
    clauses, params = [], []
    if event_id:
        clauses.append("t.event_id=?")
        params.append(int(event_id))
    if promoter_id:
        clauses.append("t.promoter_id=?")
        params.append(int(promoter_id))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with connect() as con:
        return con.execute(f"""
          SELECT t.id, t.code, e.name AS event, t.buyer_name, t.buyer_email,
                 t.price, t.status, t.created_at, t.checked_at,
                 COALESCE(u.full_name, 'Sprzedaż administratora') AS promoter
          FROM tickets t JOIN events e ON e.id=t.event_id
          LEFT JOIN users u ON u.id=t.promoter_id
          {where}
          ORDER BY t.id DESC
        """, params).fetchall()


# ---------- Logowanie ----------
if "user" not in st.session_state:
    st.session_state.user = None

if not st.session_state.user:
    st.markdown("""
    <div class="hero">
      <h1>🎟️ TicketFlow</h1>
      <p>Jedno miejsce do sprzedaży, dystrybucji i kontroli biletów.</p>
    </div>
    """, unsafe_allow_html=True)
    left, center, right = st.columns([1, 1.15, 1])
    with center:
        with st.container(border=True):
            st.subheader("Zaloguj się")
            st.caption("Panel administratora i promotorów")
            with st.form("login_form"):
                username = st.text_input("Login", placeholder="np. admin")
                password = st.text_input("Hasło", type="password")
                submitted = st.form_submit_button("Zaloguj", use_container_width=True, type="primary")
            if submitted:
                user = verify_login(username, password)
                if user:
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Nieprawidłowy login lub hasło.")
        st.info("Pierwsze logowanie: admin / zmien-me-przed-uruchomieniem. Zmień hasło przez ustawienie TICKETFLOW_ADMIN_PASSWORD przed pierwszym uruchomieniem.")
    st.stop()


user = st.session_state.user
is_admin = user["role"] == "admin"

with st.sidebar:
    st.markdown("# 🎟️ TicketFlow")
    st.caption("SYSTEM ZARZĄDZANIA BILETAMI")
    st.divider()
    st.write(f"**{user['full_name']}**")
    st.caption("Administrator" if is_admin else "Panel promotora")
    page_options = ["Przegląd", "Bilety i sprzedaż", "Kontrola wejścia"]
    if is_admin:
        page_options += ["Wydarzenia", "Promotorzy", "Raporty"]
    page = st.radio("NAWIGACJA", page_options, label_visibility="visible")
    st.divider()
    if st.button("Wyloguj", use_container_width=True):
        st.session_state.user = None
        st.rerun()
    st.caption("TicketFlow • MVP")


st.markdown(f"""
<div class="hero">
  <h1>{'Panel administratora' if is_admin else 'Panel promotora'}</h1>
  <p>{'Zarządzaj wydarzeniami, sprzedażą, zespołem i kontrolą wejścia.' if is_admin else 'Sprzedawaj bilety, kontroluj swoje wyniki i sprawdzaj wejściówki.'}</p>
</div>
""", unsafe_allow_html=True)


# ---------- Przegląd ----------
if page == "Przegląd":
    stats = get_stats(None if is_admin else None, None if is_admin else user["id"])
    events = get_events(active_only=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sprzedane bilety", stats["sold"] or 0)
    c2.metric("Przychód ze sprzedaży", money(stats["revenue"]))
    c3.metric("Wykorzystane bilety", stats["used"] or 0)
    c4.metric("Do wykorzystania", stats["valid"] or 0)
    st.subheader("Aktywne wydarzenia")
    if events:
        for event in events:
            sold = get_stats(event["id"])["sold"]
            capacity = event["capacity"] or 0
            ratio = min(sold / capacity, 1.0) if capacity else 0
            with st.container(border=True):
                a, b, c = st.columns([3, 1.2, 1.5])
                a.markdown(f"**{event['name']}**")
                a.caption(f"{event['venue'] or 'Miejsce nieustalone'} • {event['event_date']}")
                b.metric("Cena biletu", money(event["ticket_price"]))
                c.metric("Sprzedane / limit", f"{sold} / {capacity}" if capacity else str(sold))
                if capacity:
                    st.progress(ratio, text=f"Wykorzystanie puli: {ratio:.0%}")
    else:
        st.info("Brak aktywnych wydarzeń. Administrator może dodać je w zakładce „Wydarzenia”.")
    if not is_admin:
        st.subheader("Twoje wyniki")
        st.caption(f"Ustawiona prowizja: {user['commission']:.2f}%")

# ---------- Wydarzenia ----------
elif page == "Wydarzenia" and is_admin:
    st.subheader("Dodaj wydarzenie")
    with st.form("event_form", clear_on_submit=True):
        name = st.text_input("Nazwa wydarzenia *", placeholder="np. Summer Night")
        venue = st.text_input("Miejsce", placeholder="np. Klub / adres")
        date = st.date_input("Data wydarzenia")
        price = st.number_input("Cena biletu (zł)", min_value=0.0, value=50.0, step=5.0)
        capacity = st.number_input("Limit biletów (0 = bez limitu)", min_value=0, value=300, step=25)
        submitted = st.form_submit_button("Utwórz wydarzenie", type="primary")
    if submitted:
        if not name.strip():
            st.error("Podaj nazwę wydarzenia.")
        else:
            with connect() as con:
                con.execute("INSERT INTO events(name,venue,event_date,ticket_price,capacity,created_at) VALUES(?,?,?,?,?,?)",
                            (name.strip(), venue.strip(), date.isoformat(), price, int(capacity), datetime.now().isoformat(timespec="seconds")))
            st.success("Wydarzenie zostało utworzone.")
            st.rerun()
    st.subheader("Lista wydarzeń")
    events = get_events()
    for ev in events:
        with st.container(border=True):
            a, b, c, d = st.columns([3, 1.3, 1.2, 1.2])
            a.markdown(f"**{ev['name']}**")
            a.caption(f"{ev['venue']} • {ev['event_date']}")
            b.write(money(ev["ticket_price"]))
            b.caption(f"Limit: {ev['capacity'] or 'bez limitu'}")
            c.write("Aktywne" if ev["active"] else "Nieaktywne")
            if ev["active"]:
                if d.button("Dezaktywuj", key=f"deactivate_{ev['id']}"):
                    with connect() as con:
                        con.execute("UPDATE events SET active=0 WHERE id=?", (ev["id"],))
                    st.rerun()
            else:
                if d.button("Aktywuj", key=f"activate_{ev['id']}"):
                    with connect() as con:
                        con.execute("UPDATE events SET active=1 WHERE id=?", (ev["id"],))
                    st.rerun()

# ---------- Bilety i sprzedaż ----------
elif page == "Bilety i sprzedaż":
    st.subheader("Wystaw bilet")
    events = get_events(active_only=True)
    if not events:
        st.warning("Brak aktywnych wydarzeń. Poproś administratora o dodanie wydarzenia.")
    else:
        event_map = {f"{e['name']} — {e['event_date']} ({money(e['ticket_price'])})": e for e in events}
        with st.form("ticket_form", clear_on_submit=True):
            chosen = st.selectbox("Wydarzenie", list(event_map.keys()))
            buyer = st.text_input("Imię i nazwisko kupującego *")
            email = st.text_input("E-mail kupującego (opcjonalnie)")
            custom_price = st.checkbox("Ustaw inną cenę")
            price_override = st.number_input("Cena indywidualna (zł)", min_value=0.0, value=0.0, step=5.0, disabled=not custom_price)
            create = st.form_submit_button("Utwórz bilet i kod QR", type="primary")
        if create:
            ev = event_map[chosen]
            with connect() as con:
                sold = con.execute("SELECT COUNT(*) FROM tickets WHERE event_id=? AND status!='cancelled'", (ev["id"],)).fetchone()[0]
                if ev["capacity"] and sold >= ev["capacity"]:
                    st.error("Wyczerpano pulę biletów na to wydarzenie.")
                elif not buyer.strip():
                    st.error("Podaj imię i nazwisko kupującego.")
                else:
                    code = secrets.token_urlsafe(24)
                    ticket_price = float(price_override) if custom_price else float(ev["ticket_price"])
                    created_at = datetime.now().isoformat(timespec="seconds")
                    with connect() as con:
                        cur = con.execute("""INSERT INTO tickets(code,event_id,buyer_name,buyer_email,price,promoter_id,created_at)
                                             VALUES(?,?,?,?,?,?,?)""",
                                          (code, ev["id"], buyer.strip(), email.strip(), ticket_price,
                                           None if is_admin else user["id"], created_at))
                        ticket_id = cur.lastrowid
                        qr_row = con.execute("""
                            SELECT t.*, e.name AS event_name, e.event_date
                            FROM tickets t JOIN events e ON e.id=t.event_id WHERE t.id=?
                        """, (ticket_id,)).fetchone()
                    qr_payload = make_qr_payload(dict(qr_row))
                    st.session_state["last_ticket"] = {
                        "code": code, "qr_payload": qr_payload, "buyer": buyer.strip(),
                        "email": email.strip(), "event": ev["name"], "event_date": ev["event_date"],
                        "price": ticket_price, "ticket_id": ticket_id
                    }
                    st.rerun()
    if st.session_state.get("last_ticket"):
        ticket = st.session_state["last_ticket"]
        st.success("Bilet utworzony. Zapisz kod QR i przekaż go kupującemu.")
        a, b = st.columns([1, 2])
        with a:
            qr_image = qr_png(ticket["qr_payload"])
            st.image(qr_image, width=260, caption="Kod QR z danymi uczestnika i biletu")
            st.download_button("Pobierz kod QR (PNG)", data=qr_image,
                               file_name=f"bilet_{ticket['ticket_id']}.png", mime="image/png")
        with b:
            st.markdown(f"### {ticket['event']}")
            st.write(f"**Kupujący:** {ticket['buyer']}")
            st.write(f"**Cena:** {money(ticket['price'])}")
            st.write("**Dane zapisane w QR:**")
            st.code(ticket["qr_payload"], language="json")
            st.caption("QR zawiera dane uczestnika i wydarzenia oraz podpis bezpieczeństwa. Przy kontroli wklej pełną treść QR do pola w zakładce „Kontrola wejścia”.")
    st.divider()
    st.subheader("Lista biletów")
    all_rows = ticket_rows(promoter_id=None if is_admin else user["id"])
    if all_rows:
        st.dataframe([dict(r) for r in all_rows], use_container_width=True, hide_index=True)
        csv_data = __import__("pandas").DataFrame([dict(r) for r in all_rows]).to_csv(index=False).encode("utf-8-sig")
        st.download_button("Eksportuj bilety do CSV", csv_data, "bilety.csv", "text/csv")
    else:
        st.info("Nie ma jeszcze wystawionych biletów.")

# ---------- Kontrola wejścia ----------
elif page == "Kontrola wejścia":
    st.subheader("Sprawdź ważność biletu")
    st.write("Zeskanuj QR telefonem/skanerem i wklej odczytaną pełną treść do pola. Nowy QR zawiera dane biletu w formacie JSON.")
    with st.form("check_ticket_form"):
        scanned_text = st.text_area("Treść kodu QR", placeholder='Wklej pełny tekst QR, zaczynający się od {"signature"... lub {"ticket"...}', height=120)
        check = st.form_submit_button("Sprawdź bilet", type="primary")
    if check:
        ticket, error = parse_ticket_qr(scanned_text)
        if error:
            st.error("❌ " + error)
        elif ticket is None:
            st.error("❌ Nie znaleziono biletu.")
        elif not is_admin and ticket["promoter_id"] != user["id"]:
            st.error("Ten bilet nie należy do Twojej sprzedaży. Poproś administratora o weryfikację.")
        elif ticket["status"] == "cancelled":
            st.error("🚫 Bilet anulowany.")
        elif ticket["status"] == "used":
            st.warning(f"⚠️ Bilet został już wykorzystany: {ticket['checked_at'] or 'brak daty'}")
            st.write(f"Wydarzenie: **{ticket['event_name']}** • Kupujący: **{ticket['buyer_name']}**")
        else:
            st.success("✅ Bilet ważny — można wpuścić uczestnika.")
            st.write(f"**Wydarzenie:** {ticket['event_name']}")
            st.write(f"**Data wydarzenia:** {ticket['event_date']}")
            st.write(f"**Kupujący:** {ticket['buyer_name']}")
            if ticket.get("buyer_email"):
                st.write(f"**E-mail:** {ticket['buyer_email']}")
            st.write(f"**Cena:** {money(ticket['price'])}")
            if st.button("Oznacz jako wykorzystany", type="primary"):
                with connect() as con:
                    cur = con.execute("""UPDATE tickets SET status='used', checked_at=?, checked_by=?
                                         WHERE id=? AND status='valid'""",
                                      (datetime.now().isoformat(timespec="seconds"), user["id"], ticket["id"]))
                    if cur.rowcount:
                        st.success("Bilet oznaczono jako wykorzystany.")
                    else:
                        st.error("Bilet został właśnie wykorzystany w innym stanowisku. Sprawdź ponownie.")
                st.rerun()
    st.divider()
    stats = get_stats(promoter_id=None if is_admin else user["id"])
    a, b, c = st.columns(3)
    a.metric("Wszystkie sprzedane", stats["sold"] or 0)
    b.metric("Wykorzystane", stats["used"] or 0)
    c.metric("Pozostałe ważne", stats["valid"] or 0)

# ---------- Promotorzy ----------
elif page == "Promotorzy" and is_admin:
    st.subheader("Dodaj konto promotora")
    with st.form("promoter_form", clear_on_submit=True):
        full_name = st.text_input("Imię i nazwisko")
        username = st.text_input("Login")
        password = st.text_input("Hasło początkowe", type="password")
        commission = st.number_input("Prowizja (%)", min_value=0.0, max_value=100.0, value=10.0, step=0.5)
        add = st.form_submit_button("Utwórz konto promotora", type="primary")
    if add:
        if not full_name.strip() or not username.strip() or len(password) < 8:
            st.error("Uzupełnij imię, login i hasło (minimum 8 znaków).")
        else:
            salt, digest = password_hash(password)
            try:
                with connect() as con:
                    con.execute("""INSERT INTO users(username,full_name,salt,password_hash,role,commission,created_at)
                                   VALUES(?,?,?,?,?,?,?)""",
                                (username.strip(), full_name.strip(), salt, digest, "promoter", commission,
                                 datetime.now().isoformat(timespec="seconds")))
                st.success("Konto promotora zostało utworzone.")
                st.rerun()
            except sqlite3.IntegrityError:
                st.error("Taki login już istnieje.")
    st.subheader("Zespół promotorów")
    with connect() as con:
        promoters = con.execute("SELECT * FROM users WHERE role='promoter' ORDER BY full_name").fetchall()
    if promoters:
        for p in promoters:
            stats = get_stats(promoter_id=p["id"])
            with st.container(border=True):
                a, b, c, d = st.columns([2.2, 1, 1.2, 1.2])
                a.markdown(f"**{p['full_name']}**")
                a.caption(f"Login: {p['username']} • {'Aktywny' if p['active'] else 'Nieaktywny'}")
                b.metric("Bilety", stats["sold"] or 0)
                c.metric("Sprzedaż", money(stats["revenue"]))
                d.metric("Prowizja", money((stats["revenue"] or 0) * p["commission"] / 100))
                if p["active"]:
                    if st.button("Dezaktywuj konto", key=f"disable_{p['id']}"):
                        with connect() as con:
                            con.execute("UPDATE users SET active=0 WHERE id=?", (p["id"],))
                        st.rerun()
                else:
                    if st.button("Aktywuj konto", key=f"enable_{p['id']}"):
                        with connect() as con:
                            con.execute("UPDATE users SET active=1 WHERE id=?", (p["id"],))
                        st.rerun()
    else:
        st.info("Nie dodano jeszcze promotorów.")

# ---------- Raporty ----------
elif page == "Raporty" and is_admin:
    st.subheader("Raport sprzedaży")
    events = get_events()
    event_options = {"Wszystkie wydarzenia": None}
    event_options.update({f"{e['name']} — {e['event_date']}": e["id"] for e in events})
    chosen = st.selectbox("Filtr wydarzenia", list(event_options.keys()))
    stats = get_stats(event_options[chosen])
    a, b, c, d = st.columns(4)
    a.metric("Bilety", stats["sold"] or 0)
    b.metric("Przychód", money(stats["revenue"]))
    c.metric("Wykorzystane", stats["used"] or 0)
    d.metric("Anulowane", stats["cancelled"] or 0)
    rows = ticket_rows(event_options[chosen])
    if rows:
        import pandas as pd
        df = pd.DataFrame([dict(r) for r in rows])
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Pobierz raport CSV", df.to_csv(index=False).encode("utf-8-sig"),
                           "raport_sprzedazy.csv", "text/csv")
    st.subheader("Wyniki promotorów")
    with connect() as con:
        promoters = con.execute("SELECT id, full_name, commission FROM users WHERE role='promoter' ORDER BY full_name").fetchall()
    report = []
    for p in promoters:
        s = get_stats(event_options[chosen], p["id"])
        report.append({
            "Promotor": p["full_name"],
            "Bilety": s["sold"] or 0,
            "Przychód": round(s["revenue"] or 0, 2),
            "Prowizja (%)": p["commission"],
            "Prowizja do rozliczenia": round((s["revenue"] or 0) * p["commission"] / 100, 2),
        })
    if report:
        st.dataframe(report, use_container_width=True, hide_index=True)
    else:
        st.info("Brak danych promotorów.")

st.markdown("---")
st.markdown('<p class="small-muted">TicketFlow MVP • Dane przechowywane lokalnie w pliku SQLite. Przed wdrożeniem produkcyjnym skonfiguruj bezpieczeństwo i kopie zapasowe.</p>', unsafe_allow_html=True)
