#!/usr/bin/env python3
"""
Secure Online Event Booking & E-Ticketing System
=================================================
Streamlit Web Frontend (Polished & Modern)
Information Security – Complex Computing Problem (CCP)
Faculty of Computing, Riphah International University

Authors: Hamza Rahim (56776), Rashid Islam (54384)
Instructor: Dr. Jawaid Iqbal
"""

import streamlit as st
import sys
import os
import io
import base64
import importlib
from datetime import datetime
from typing import Optional, Dict, List, Any
import pandas as pd
import qrcode

# Make the existing secure backend importable
sys.path.insert(0, os.path.dirname(__file__))
import secure_eticket
importlib.reload(secure_eticket)
from secure_eticket import (
    SecureETicketApp,
    ROLE_ATTENDEE,
    ROLE_GATE,
    ROLE_ADMIN,
    VALID_ROLES
)

# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Secure E-Ticketing System | InfoSec CCP",
    page_icon="🎟️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------------------------
# Session State Helpers
# ---------------------------------------------------------------------------
def get_app() -> SecureETicketApp:
    if "app" not in st.session_state:
        st.session_state.app = SecureETicketApp()
    return st.session_state.app

def is_logged_in() -> bool:
    return st.session_state.get("logged_in", False)

def current_user() -> Optional[Dict[str, Any]]:
    return st.session_state.get("user")

def do_login(username: str, password: str) -> bool:
    app = get_app()
    if app.login(username, password) and app.current_user:
        st.session_state.logged_in = True
        st.session_state.user = dict(app.current_user)
        return True
    return False

def do_logout():
    app = get_app()
    app.logout()
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.pop("last_ticket", None)
    st.session_state.pop("viewing_ticket", None)

def generate_qr_base64(token_str: str) -> str:
    """Generate a high-contrast QR code image as a base64 data URI."""
    try:
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(token_str)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0F172A", back_color="#FFFFFF")
        buffer = io.BytesIO()
        img.save(buffer, "PNG")  # type: ignore
        b64_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{b64_str}"
    except Exception:
        return ""

# Initialize gate scan history in session state
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# ---------------------------------------------------------------------------
# Custom CSS Styling
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Global Typography & Palette */
    :root {
        --primary-brand: #1E3A8A;
        --secondary-brand: #0284C7;
        --success-accent: #059669;
        --danger-accent: #DC2626;
        --warning-accent: #D97706;
        --card-bg: rgba(255, 255, 255, 0.05);
        --border-subtle: rgba(148, 163, 184, 0.25);
    }

    /* Hero Banner */
    .hero-container {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #1E3A8A 100%);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 14px;
        padding: 2rem 2.2rem;
        margin-bottom: 1.8rem;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        color: #F8FAFC;
    }
    .hero-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        margin-bottom: 0.3rem;
        background: linear-gradient(90deg, #FFFFFF 0%, #93C5FD 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .hero-subtitle {
        font-size: 1.05rem;
        color: #94A3B8;
        margin-bottom: 1.2rem;
    }

    /* Badges & Chips */
    .sec-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        padding: 0.35rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 0.5rem;
        margin-bottom: 0.4rem;
    }
    .badge-primary {
        background: rgba(14, 165, 233, 0.15);
        color: #38BDF8;
        border: 1px solid rgba(14, 165, 233, 0.35);
    }
    .badge-success {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .badge-warning {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.35);
    }
    .badge-danger {
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
    }

    /* Feature Pillars on Login */
    .pillar-card {
        background: var(--card-bg);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 1.2rem;
        height: 100%;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .pillar-card:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.5);
    }
    .pillar-title {
        font-size: 1rem;
        font-weight: 700;
        color: #38BDF8;
        margin-bottom: 0.4rem;
    }
    .pillar-desc {
        font-size: 0.85rem;
        color: #94A3B8;
        line-height: 1.45;
    }

    /* Ticket Boarding Pass Card */
    .ticket-container {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        border: 1.5px solid rgba(56, 189, 248, 0.4);
        border-radius: 16px;
        padding: 1.8rem;
        box-shadow: 0 15px 30px -5px rgba(0, 0, 0, 0.4);
        margin: 1.5rem 0;
        position: relative;
        overflow: hidden;
    }
    .ticket-header {
        border-bottom: 2px dashed rgba(148, 163, 184, 0.3);
        padding-bottom: 1.2rem;
        margin-bottom: 1.2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .ticket-event-title {
        font-size: 1.5rem;
        font-weight: 800;
        color: #FFFFFF;
        margin-bottom: 0.3rem;
    }
    .ticket-token-box {
        background: #020617;
        border: 1px solid rgba(148, 163, 184, 0.3);
        border-radius: 8px;
        padding: 0.8rem 1rem;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.9rem;
        color: #38BDF8;
        word-break: break-all;
        margin-top: 0.6rem;
    }

    /* User Profile Chip in Sidebar */
    .user-profile-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    .user-avatar {
        width: 44px;
        height: 44px;
        border-radius: 50%;
        background: linear-gradient(135deg, #0284C7, #1E3A8A);
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 1.1rem;
        margin-bottom: 0.5rem;
    }

    /* Status Notifications */
    .result-granted {
        background: rgba(16, 185, 129, 0.12);
        border: 1.5px solid #10B981;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        margin: 1rem 0;
        color: #A7F3D0;
    }
    .result-denied {
        background: rgba(239, 68, 68, 0.12);
        border: 1.5px solid #EF4444;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        margin: 1rem 0;
        color: #FECACA;
    }

    /* Stat Box */
    .stat-card {
        background: var(--card-bg);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 1rem 1.2rem;
        text-align: center;
    }
    .stat-value {
        font-size: 1.8rem;
        font-weight: 800;
        color: #38BDF8;
    }
    .stat-label {
        font-size: 0.85rem;
        color: #94A3B8;
        margin-top: 0.2rem;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Component: Modern Header / Hero
# ---------------------------------------------------------------------------
def render_header(title: str, subtitle: str, role_badge: Optional[str] = None):
    badge_html = f'<span class="sec-badge badge-primary">{role_badge}</span>' if role_badge else ""
    st.markdown(f"""
    <div class="hero-container">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap;">
            <div>
                <div class="hero-title">{title}</div>
                <div class="hero-subtitle">{subtitle}</div>
            </div>
            <div>{badge_html}</div>
        </div>
        <div>
            <span class="sec-badge badge-success">🛡️ PBKDF2 Password Hashing</span>
            <span class="sec-badge badge-primary">🔐 HMAC-SHA256 Ticket Signing</span>
            <span class="sec-badge badge-warning">⚡ Atomic Single-Use Redemption</span>
            <span class="sec-badge badge-primary">🛑 SQLite ACID Transactions</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# View: Login Page
# ---------------------------------------------------------------------------
def page_login():
    render_header(
        title="🎟️ Secure Online Event Booking & E-Ticketing",
        subtitle="Complex Computing Problem (CCP) • Faculty of Computing, Riphah International University"
    )

    # 4 Security Pillars
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("""
        <div class="pillar-card">
            <div class="pillar-title">🛡️ Authentication</div>
            <div class="pillar-desc">PBKDF2-HMAC-SHA256 with 260k iterations & unique cryptographic salts prevents offline cracking.</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="pillar-card">
            <div class="pillar-title">🔏 Ticket Integrity</div>
            <div class="pillar-desc">HMAC-SHA256 signatures over token, booking ID & event prevent counterfeit ticket generation.</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="pillar-card">
            <div class="pillar-title">⚡ Anti-Replay Gate</div>
            <div class="pillar-desc">Atomic database state change (BEGIN IMMEDIATE) ensures single-use validation and prevents replay fraud.</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown("""
        <div class="pillar-card">
            <div class="pillar-title">🛑 Concurrency Guard</div>
            <div class="pillar-desc">Transactional seat inventory updates ensure zero overbooking even under high concurrent load.</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    st.write("")

    login_col, quick_col = st.columns([1.1, 1.3], gap="large")

    with login_col:
        st.markdown("### 🔐 Account Sign In")
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="e.g. alice, gate1, admin")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)

            if submitted:
                if not username.strip() or not password:
                    st.error("Please provide both username and password.")
                elif do_login(username.strip(), password):
                    st.success(f"Welcome back, {st.session_state.user['full_name']}!")
                    st.rerun()
                else:
                    st.error("Invalid credentials. Login attempt logged in audit trail.")

    with quick_col:
        st.markdown("### ⚡ One-Click Demo Access")
        st.caption("Click any demo role below to test the application instantly with pre-seeded test accounts:")

        q1, q2 = st.columns(2)
        with q1:
            if st.button("👑 Admin\n\n(`admin` / `Admin@123`)", use_container_width=True):
                if do_login("admin", "Admin@123"):
                    st.rerun()
            st.write("")
            if st.button("🚪 Gate Staff\n\n(`gate1` / `Gate@123`)", use_container_width=True):
                if do_login("gate1", "Gate@123"):
                    st.rerun()

        with q2:
            if st.button("👤 Attendee (Alice)\n\n(`alice` / `Pass@123`)", use_container_width=True):
                if do_login("alice", "Pass@123"):
                    st.rerun()
            st.write("")
            if st.button("👤 Attendee (Bob)\n\n(`bob` / `Pass@123`)", use_container_width=True):
                if do_login("bob", "Pass@123"):
                    st.rerun()

        with st.expander("ℹ️ Roles & Privilege Boundaries Guide"):
            st.markdown("""
            | Role | Target Identity | Granted Capabilities | Security Enforcements |
            | :--- | :--- | :--- | :--- |
            | **`admin`** | System Administrator | Event creation, user provisioning, full booking audits, forensic logs | Multi-role mediation |
            | **`gate_staff`** | Gate Check-in Officer | Ticket validation & single-use redemption, event occupancy statistics | No access to booking edits or audit logs |
            | **`attendee`** | Event Goer | Browse events, purchase seats, generate signed tickets for owned bookings | Strict ownership checks (IDOR prevention) |
            """)


# ---------------------------------------------------------------------------
# View: Attendee Dashboard
# ---------------------------------------------------------------------------
def page_attendee():
    app = get_app()
    user = current_user()
    if not user:
        st.error("Please sign in.")
        return

    render_header(
        title=f"Welcome, {user['full_name']} 👋",
        subtitle="Browse events, reserve seats, and manage your cryptographically signed e-tickets.",
        role_badge="ROLE: ATTENDEE"
    )

    tab1, tab2, tab3 = st.tabs([
        "📅 Available Events & Booking",
        "🎫 My Bookings & E-Tickets",
        "🛡️ Security Explainer"
    ])

    # ---- Tab 1: Available Events & Booking ----
    with tab1:
        st.subheader("Upcoming Events")
        events = app.list_events()

        if not events:
            st.info("No active events currently available for booking.")
        else:
            for e in events:
                capacity = e["capacity"]
                left = e["seats_left"]
                booked = capacity - left
                pct = int((booked / capacity) * 100) if capacity > 0 else 0

                status_badge = '<span class="sec-badge badge-success">Available</span>' if left > 10 else (
                    '<span class="sec-badge badge-warning">Filling Fast</span>' if left > 0 else
                    '<span class="sec-badge badge-danger">Sold Out</span>'
                )

                with st.container(border=True):
                    col_info, col_book = st.columns([2.5, 1.2], gap="medium")

                    with col_info:
                        st.markdown(f"### {e['title']} {status_badge}", unsafe_allow_html=True)
                        st.write(e.get("description") or "No description provided.")
                        st.caption(f"📅 **Date:** {e.get('event_date') or 'TBA'}  •  🎟️ **Capacity:** {capacity} total seats")

                        # Visual Capacity Progress Bar
                        st.progress(pct / 100)
                        st.caption(f"**{left}** seats remaining ({booked}/{capacity} booked)")

                    with col_book:
                        st.markdown("#### Reserve Seats")
                        if left > 0:
                            seats = st.number_input(
                                "Number of Seats",
                                min_value=1,
                                max_value=max(1, left),
                                value=1,
                                key=f"seats_in_{e['id']}"
                            )
                            if st.button("Confirm Booking", key=f"book_btn_{e['id']}", type="primary", use_container_width=True):
                                ok, msg, bid = app.book_seats(e["id"], seats)
                                if ok:
                                    st.success(f"🎉 {msg}")
                                    st.rerun()
                                else:
                                    st.error(f"❌ {msg}")
                        else:
                            st.warning("Event is completely sold out.")

    # ---- Tab 2: My Bookings & E-Tickets ----
    with tab2:
        st.subheader("My Reservations & Digital Tickets")
        bookings = app.my_bookings()

        if not bookings:
            st.info("You haven't made any bookings yet. Head over to the 'Available Events' tab to book seats!")
        else:
            b_col, ticket_col = st.columns([1.2, 1.5], gap="large")

            with b_col:
                st.markdown("#### Booking History")
                for b in bookings:
                    with st.container(border=True):
                        st.markdown(f"**Booking #{b['id']}** — {b['title']}")
                        st.caption(f"📅 Booked on {b['created_at']}  •  Seats: **{b['seats']}**")
                        st.markdown(f"Status: `<span class='sec-badge badge-success'>{b['status'].upper()}</span>`", unsafe_allow_html=True)

                        c_gen, c_view = st.columns(2)
                        with c_gen:
                            if st.button("Generate Ticket", key=f"gen_{b['id']}", use_container_width=True):
                                ok, msg, ticket = app.generate_ticket(b["id"])
                                if ok and ticket:
                                    st.session_state.viewing_ticket = {
                                        **ticket,
                                        "booking_id": b["id"],
                                        "event_title": b["title"],
                                        "seats": b["seats"],
                                        "attendee_name": user["full_name"],
                                    }
                                    st.success("Ticket ready!")
                                    st.rerun()
                                else:
                                    st.warning(msg)
                        with c_view:
                            if st.button("View E-Ticket", key=f"view_{b['id']}", use_container_width=True):
                                ok, msg, ticket = app.generate_ticket(b["id"])
                                if ticket:
                                    st.session_state.viewing_ticket = {
                                        **ticket,
                                        "booking_id": b["id"],
                                        "event_title": b["title"],
                                        "seats": b["seats"],
                                        "attendee_name": user["full_name"],
                                    }
                                    st.rerun()

            with ticket_col:
                st.markdown("#### Active E-Ticket Boarding Pass")
                t = st.session_state.get("viewing_ticket")

                if not t:
                    st.info("Select or generate a ticket from your bookings on the left to preview your digital pass.")
                else:
                    token = t.get("token", "")
                    sig = t.get("signature", "")
                    qr_b64 = generate_qr_base64(token) if token else ""

                    # Render Boarding Pass
                    st.markdown(f"""
                    <div class="ticket-container">
                        <div class="ticket-header">
                            <div>
                                <span class="sec-badge badge-primary">🎟️ OFFICIAL ADMISSION PASS</span>
                                <div class="ticket-event-title">{t.get('event_title', 'Conference Admission')}</div>
                                <div style="color: #94A3B8; font-size: 0.9rem;">Booking Ref: <b>#{t.get('booking_id')}</b></div>
                            </div>
                            <div style="text-align: right;">
                                <span class="sec-badge badge-success">✓ HMAC-SHA256 SIGNED</span>
                            </div>
                        </div>
                        <div style="display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap;">
                            <div style="flex: 1; min-width: 220px;">
                                <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Attendee</div>
                                <div style="color: #FFFFFF; font-weight: 700; font-size: 1.15rem; margin-bottom: 0.8rem;">{t.get('attendee_name', user['full_name'])}</div>
                                <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Seats Reserved</div>
                                <div style="color: #38BDF8; font-weight: 800; font-size: 1.2rem; margin-bottom: 0.8rem;">{t.get('seats', 1)} Seat(s)</div>
                                <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Cryptographic Signature</div>
                                <div style="font-family: monospace; font-size: 0.75rem; color: #94A3B8; word-break: break-all;">{sig[:32]}...</div>
                            </div>
                            <div style="text-align: center; background: white; padding: 0.6rem; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.3);">
                                <img src="{qr_b64}" width="150" height="150" alt="Ticket QR Code" style="display: block;" />
                                <div style="color: #0F172A; font-weight: 800; font-size: 0.7rem; margin-top: 0.2rem;">SCAN AT GATE</div>
                            </div>
                        </div>
                        <div style="margin-top: 1.2rem;">
                            <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase; margin-bottom: 0.2rem;">Single-Use Gate Token</div>
                            <div class="ticket-token-box">{token}</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    st.caption("🔒 **Security Assurance:** This token is signed with the organizer's secret key. Any alteration will be rejected by gate scanners.")

    # ---- Tab 3: Security Explainer ----
    with tab3:
        st.markdown("### How Your E-Ticket Is Protected")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""
            #### 1. Inherent Tamper Resistance
            When your ticket is generated, the server creates a unique, 256-bit cryptographically random token:
            ```text
            Message = Token | Booking_ID | Event_ID
            Signature = HMAC_SHA256(Secret_Key, Message)
            ```
            Because attackers do not possess the `Secret_Key`, forging or altering a ticket token is mathematically infeasible.
            """)
        with c2:
            st.markdown("""
            #### 2. Replay & Double-Entry Protection
            Even if a legitimate ticket token is intercepted or copied:
            - Gate staff redemption is **strictly atomic**.
            - Once checked in, the database flags the ticket as `redeemed = 1`.
            - Any subsequent entry attempt using the same token is immediately denied and logged.
            """)


# ---------------------------------------------------------------------------
# View: Gate Staff Dashboard
# ---------------------------------------------------------------------------
def page_gate():
    app = get_app()
    user = current_user()
    if not user:
        st.error("Please sign in.")
        return

    render_header(
        title="Gate Check-In & Validation Console 🚪",
        subtitle="Validate attendee tokens, enforce single-use entry, and monitor venue occupancy.",
        role_badge="ROLE: GATE STAFF"
    )

    tab_scan, tab_stats = st.tabs(["🔍 Token Scanner & Validation", "📊 Venue & Event Statistics"])

    with tab_scan:
        st.subheader("Scan / Enter Ticket Token")

        # Quick Test Helper for Demonstration
        with st.expander("🧪 Evaluator Quick-Test Sandbox (Click to auto-populate tokens)"):
            st.caption("Quickly test valid, forged, and replayed tokens without manual copying:")
            
            # Fetch sample tokens from DB
            sample_unredeemed = None
            sample_redeemed = None
            try:
                cur = app.db.conn.execute("SELECT token FROM tickets WHERE redeemed = 0 LIMIT 1")
                row = cur.fetchone()
                if row:
                    sample_unredeemed = row["token"]
                cur = app.db.conn.execute("SELECT token FROM tickets WHERE redeemed = 1 LIMIT 1")
                row = cur.fetchone()
                if row:
                    sample_redeemed = row["token"]
            except Exception:
                pass

            col_t1, col_t2, col_t3 = st.columns(3)
            with col_t1:
                if sample_unredeemed:
                    if st.button("📋 Load Valid Token", use_container_width=True):
                        st.session_state.gate_token_input = sample_unredeemed
                        st.rerun()
                else:
                    st.caption("No unredeemed ticket available in DB yet.")

            with col_t2:
                if sample_unredeemed:
                    if st.button("⚠️ Load Forged Token", use_container_width=True):
                        # Alter the token string to break HMAC
                        st.session_state.gate_token_input = sample_unredeemed[:-4] + "HACK"
                        st.rerun()
                else:
                    if st.button("⚠️ Load Fake Token", use_container_width=True):
                        st.session_state.gate_token_input = "invalid_token_tampered_12345"
                        st.rerun()

            with col_t3:
                if sample_redeemed:
                    if st.button("🔁 Load Replayed Token", use_container_width=True):
                        st.session_state.gate_token_input = sample_redeemed
                        st.rerun()
                else:
                    st.caption("No redeemed ticket available to replay yet.")

        # Input & Validate
        token_input = st.text_input(
            "Ticket Token",
            value=st.session_state.get("gate_token_input", ""),
            placeholder="Paste token or scan barcode/QR code here...",
            key="gate_token_box"
        )

        v_col1, v_col2 = st.columns([1, 4])
        with v_col1:
            validate_clicked = st.button("Validate & Check-In", type="primary", use_container_width=True)

        if validate_clicked:
            clean_token = (token_input or "").strip()
            if not clean_token:
                st.error("Please enter a ticket token to validate.")
            else:
                ok, msg = app.validate_and_redeem(clean_token)
                info = app.get_ticket_info(clean_token)

                # Record in scan history
                st.session_state.scan_history.insert(0, {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "token": clean_token[:16] + "...",
                    "result": "GRANTED" if ok else "DENIED",
                    "details": msg,
                    "event": info["event_title"] if info else "Unknown",
                    "attendee": info["attendee_name"] if info else "Unknown",
                    "seats": info["seats"] if info else "-"
                })

                if ok:
                    st.markdown(f"""
                    <div class="result-granted">
                        <div style="font-size: 1.35rem; font-weight: 800; color: #10B981; margin-bottom: 0.4rem;">
                            ✓ ENTRY GRANTED – TICKET REDEEMED
                        </div>
                        <div style="font-size: 1rem; color: #E2E8F0;">
                            <b>Attendee:</b> {info['attendee_name'] if info else 'Verified Attendee'} &nbsp;•&nbsp; 
                            <b>Event:</b> {info['event_title'] if info else 'General Admission'} &nbsp;•&nbsp; 
                            <b>Seats:</b> {info['seats'] if info else '1'}
                        </div>
                        <div style="font-size: 0.85rem; color: #94A3B8; margin-top: 0.4rem;">
                            {msg} | Single-use flag updated in database atomically.
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="result-denied">
                        <div style="font-size: 1.35rem; font-weight: 800; color: #EF4444; margin-bottom: 0.4rem;">
                            ✗ ENTRY DENIED – SECURITY ALERT
                        </div>
                        <div style="font-size: 1rem; color: #E2E8F0;">
                            <b>Reason:</b> {msg}
                        </div>
                        <div style="font-size: 0.85rem; color: #94A3B8; margin-top: 0.4rem;">
                            Security incident logged to system audit trail.
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

        # Recent Scans Table
        st.write("")
        st.markdown("#### Session Scan Log")
        if st.session_state.scan_history:
            df_scans = pd.DataFrame(st.session_state.scan_history)
            st.dataframe(
                df_scans,
                column_config={
                    "timestamp": "Time",
                    "token": "Token Snippet",
                    "result": st.column_config.TextColumn("Verdict"),
                    "details": "System Message",
                    "event": "Event Title",
                    "attendee": "Attendee",
                    "seats": "Seats"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No tokens scanned in this gate session yet.")

    with tab_stats:
        st.subheader("Event Capacity & Live Check-in Statistics")
        events = app.list_events()
        if not events:
            st.info("No active events found.")
        else:
            selected_eid = st.selectbox(
                "Select Event to Inspect",
                options=[e["id"] for e in events],
                format_func=lambda x: next(e["title"] for e in events if e["id"] == x)
            )

            stats = app.get_event_stats(int(selected_eid)) if selected_eid is not None else None
            if stats:
                cap = stats["capacity"]
                left = stats["seats_left"]
                sold = cap - left
                redeemed = stats["redeemed_tickets"]
                checkin_pct = int((redeemed / sold * 100)) if sold > 0 else 0

                s1, s2, s3, s4 = st.columns(4)
                with s1:
                    st.metric("Total Venue Capacity", cap)
                with s2:
                    st.metric("Seats Reserved", sold)
                with s3:
                    st.metric("Available Seats Left", left)
                with s4:
                    st.metric("Redeemed at Gates", redeemed, delta=f"{checkin_pct}% of attendees")

                st.write("")
                st.write("**Live Gate Check-In Progress:**")
                st.progress(checkin_pct / 100 if sold > 0 else 0)
                st.caption(f"{redeemed} of {sold} booked attendees checked in ({checkin_pct}%)")


# ---------------------------------------------------------------------------
# View: Admin Dashboard
# ---------------------------------------------------------------------------
def page_admin():
    app = get_app()
    user = current_user()
    if not user:
        st.error("Please sign in.")
        return

    render_header(
        title="System Administration & Security Telemetry 🛠️",
        subtitle="Manage event inventory, provision accounts, monitor bookings, and inspect audit forensics.",
        role_badge="ROLE: SYSTEM ADMIN"
    )

    # Top KPI Metrics Cards
    metrics = getattr(app, "get_system_metrics", lambda: None)()
    if metrics:
        k1, k2, k3, k4, k5, k6 = st.columns(6)
        with k1:
            st.metric("Active Events", metrics["total_events"])
        with k2:
            st.metric("Total Users", metrics["total_users"])
        with k3:
            st.metric("Bookings", metrics["total_bookings"])
        with k4:
            st.metric("Tickets Issued", metrics["total_tickets"])
        with k5:
            st.metric("Gate Check-Ins", metrics["redeemed_tickets"])
        with k6:
            st.metric("Audit Records", metrics["total_logs"])

    st.write("")

    tabs = st.tabs([
        "📅 Event Management",
        "👥 Users & Access Control",
        "📋 Bookings & Tickets",
        "🚪 Gate Validation Scanner",
        "📜 Security Audit Trail"
    ])

    # ---- 1. Event Management ----
    with tabs[0]:
        e_col1, e_col2 = st.columns([1.5, 1], gap="large")

        with e_col1:
            st.subheader("Current Events")
            events = app.list_events()
            if events:
                df_events = pd.DataFrame(events)
                st.dataframe(
                    df_events[["id", "title", "capacity", "seats_left", "event_date", "description"]],
                    column_config={
                        "id": "ID",
                        "title": "Event Title",
                        "capacity": "Capacity",
                        "seats_left": "Seats Remaining",
                        "event_date": "Date",
                        "description": "Details"
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No events configured yet.")

        with e_col2:
            st.subheader("Create New Event")
            with st.form("create_event_form"):
                title = st.text_input("Event Title", placeholder="e.g. AI & Security Summit 2026")
                desc = st.text_area("Event Description", placeholder="Brief description of the event...")
                cap = st.number_input("Total Seating Capacity", min_value=1, max_value=10000, value=100)
                date_val = st.date_input("Event Date", value=datetime(2026, 12, 20))

                submitted = st.form_submit_button("Create Event", type="primary", use_container_width=True)
                if submitted:
                    if not title.strip():
                        st.error("Event title is required.")
                    else:
                        ok, msg = app.create_event(title.strip(), desc.strip(), cap, str(date_val))
                        if ok:
                            st.success(f"✓ {msg}")
                            st.rerun()
                        else:
                            st.error(f"✗ {msg}")

    # ---- 2. Users & Access Control ----
    with tabs[1]:
        u_col1, u_col2 = st.columns([1.5, 1], gap="large")

        with u_col1:
            st.subheader("Registered User Directory")
            users = app.list_users()
            if users:
                df_users = pd.DataFrame(users)
                st.dataframe(
                    df_users[["id", "username", "role", "full_name", "email", "created_at"]],
                    column_config={
                        "id": "ID",
                        "username": "Username",
                        "role": "Assigned Role",
                        "full_name": "Full Name",
                        "email": "Email Address",
                        "created_at": "Joined"
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No users registered.")

        with u_col2:
            st.subheader("Provision New Account")
            with st.form("register_user_form"):
                u_name = st.text_input("Username")
                u_pass = st.text_input("Password (min 8 chars)", type="password")
                u_role = st.selectbox("Role", list(VALID_ROLES), format_func=lambda r: f"{r.upper()} ({r})")
                u_full = st.text_input("Full Name")
                u_email = st.text_input("Email Address")

                submitted = st.form_submit_button("Create User Account", type="primary", use_container_width=True)
                if submitted:
                    if not u_name.strip() or not u_pass:
                        st.error("Username and password are required.")
                    else:
                        ok, msg = app.register_user(u_name.strip(), u_pass, u_role, u_full.strip(), u_email.strip())
                        if ok:
                            st.success(f"✓ {msg}")
                            st.rerun()
                        else:
                            st.error(f"✗ {msg}")

    # ---- 3. Bookings & Tickets ----
    with tabs[2]:
        st.subheader("Master Bookings & Ticket Generation")
        bookings = app.my_bookings()

        if bookings:
            df_b = pd.DataFrame(bookings)
            st.dataframe(
                df_b,
                column_config={
                    "id": "Booking ID",
                    "username": "Reserved By",
                    "title": "Event",
                    "seats": "Seats",
                    "status": "Status",
                    "created_at": "Date"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No bookings recorded in database.")

        st.markdown("---")
        st.subheader("Generate Ticket for Booking")
        g_c1, g_c2 = st.columns([1, 2])
        with g_c1:
            bid = st.number_input("Target Booking ID", min_value=1, step=1, value=1)
            gen_btn = st.button("Generate HMAC Ticket", type="primary", use_container_width=True)

        with g_c2:
            if gen_btn:
                ok, msg, ticket = app.generate_ticket(int(bid))
                if ok and ticket and "token" in ticket:
                    st.success(f"✓ {msg}")
                    st.markdown(f'<div class="ticket-token-box">{ticket["token"]}</div>', unsafe_allow_html=True)
                    st.caption(f"HMAC Signature: `{ticket.get('signature', '')}`")
                else:
                    st.warning(msg)

    # ---- 4. Gate Validation Simulator ----
    with tabs[3]:
        st.subheader("Gate Scanner Simulator")
        st.caption("Administrators have dual privilege to validate and check-in tickets:")

        sim_token = st.text_input("Ticket Token to Validate", placeholder="Paste token here...", key="admin_sim_token")
        if st.button("Validate & Check-In Ticket", type="primary"):
            if not sim_token.strip():
                st.error("Please enter a token.")
            else:
                ok, msg = app.validate_and_redeem(sim_token.strip())
                if ok:
                    st.success(f"✓ {msg}")
                else:
                    st.error(f"✗ {msg}")

    # ---- 5. Security Audit Trail & Forensics ----
    with tabs[4]:
        st.subheader("Restricted Audit Trail & Forensic Telemetry")
        st.caption("Logs actor actions, timestamps, and security events without exposing sensitive credentials or complete keys.")

        f_col1, f_col2, f_col3 = st.columns([1.5, 1, 1])
        with f_col1:
            limit = st.slider("Number of Recent Records", min_value=10, max_value=100, value=30, step=10)
        with f_col2:
            action_filter = st.selectbox(
                "Filter Action",
                ["ALL", "LOGIN_SUCCESS", "LOGIN_FAILED", "BOOKING_SUCCESS", "BOOKING_FAILED", "TICKET_GENERATED", "REDEEM_SUCCESS", "REDEEM_FAIL"]
            )
        with f_col3:
            outcome_filter = st.selectbox("Filter Outcome", ["ALL", "Successes Only", "Failures/Alerts Only"])

        logs = app.view_audit_log(limit=limit)

        if logs:
            # Apply Filters
            filtered_logs = logs
            if action_filter != "ALL":
                filtered_logs = [l for l in filtered_logs if l["action"] == action_filter]
            if outcome_filter == "Successes Only":
                filtered_logs = [l for l in filtered_logs if l["success"] == 1]
            elif outcome_filter == "Failures/Alerts Only":
                filtered_logs = [l for l in filtered_logs if l["success"] == 0]

            # Security Telemetry Counters
            fail_logins = sum(1 for l in logs if l["action"] == "LOGIN_FAILED")
            fail_redeems = sum(1 for l in logs if l["action"] == "REDEEM_FAIL")
            fail_bookings = sum(1 for l in logs if l["action"] == "BOOKING_FAILED")

            a1, a2, a3 = st.columns(3)
            with a1:
                st.metric("Failed Login Attempts (Brute Force Alerts)", fail_logins)
            with a2:
                st.metric("Ticket Verification Failures (Forgery/Replay)", fail_redeems)
            with a3:
                st.metric("Booking Overcapacity Blocks", fail_bookings)

            st.write("")
            df_logs = pd.DataFrame(filtered_logs)
            df_logs["verdict"] = df_logs["success"].apply(lambda s: "✅ SUCCESS" if s == 1 else "❌ FAILED")
            st.dataframe(
                df_logs[["id", "created_at", "verdict", "action", "actor_id", "details"]],
                column_config={
                    "id": "Log ID",
                    "created_at": "Timestamp",
                    "verdict": "Status",
                    "action": "Event Type",
                    "actor_id": "Actor User ID",
                    "details": "Safe Forensic Details"
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Audit log is currently empty.")


# ---------------------------------------------------------------------------
# Main Application Router
# ---------------------------------------------------------------------------
def main():
    # Sidebar Navigation & Status
    with st.sidebar:
        st.markdown("### 🎟️ Secure E-Ticketing")
        st.caption("Faculty of Computing • Riphah Int. Univ.")
        st.markdown("---")

        user = current_user()
        if is_logged_in() and user:
            name = user.get("full_name") or "User"
            uname = user.get("username") or ""
            role_str = str(user.get("role") or "").upper()
            initials = "".join([part[0].upper() for part in name.split()[:2]]) if name else "U"

            st.markdown(f"""
            <div class="user-profile-card">
                <div class="user-avatar">{initials}</div>
                <div style="font-weight: 700; color: #FFFFFF; font-size: 1.05rem;">{name}</div>
                <div style="color: #94A3B8; font-size: 0.85rem;">@{uname}</div>
                <div style="margin-top: 0.5rem;">
                    <span class="sec-badge badge-primary">{role_str}</span>
                </div>
                <div style="color: #10B981; font-size: 0.8rem; margin-top: 0.4rem;">● Session Active</div>
            </div>
            """, unsafe_allow_html=True)

            if st.button("Sign Out", type="secondary", use_container_width=True):
                do_logout()
                st.rerun()
        else:
            st.info("👋 Welcome! Please sign in using your credentials or click a one-click demo role.")

        st.markdown("---")
        st.markdown("#### 🔒 Security Architecture")
        st.markdown("""
        - 🟢 **Storage:** SQLite (WAL Mode)
        - 🟢 **Hashing:** PBKDF2-HMAC-SHA256
        - 🟢 **Signing:** HMAC-SHA256
        - 🟢 **Redemption:** Atomic `BEGIN IMMEDIATE`
        - 🟢 **Forensics:** Parameterized Audit Trail
        """)

        st.markdown("---")
        st.caption("""
        **Project Team:**  
        • Hamza Rahim (56776)  
        • Rashid Islam (54384)  
        **Instructor:** Dr. Jawaid Iqbal  
        **Course:** Information Security (CCP)
        """)

    # Main Content Router
    user = current_user()
    if not is_logged_in() or not user:
        page_login()
    else:
        role = user.get("role")
        if role == ROLE_ATTENDEE:
            page_attendee()
        elif role == ROLE_GATE:
            page_gate()
        elif role == ROLE_ADMIN:
            page_admin()
        else:
            st.error(f"Unknown user role '{role}'. Please logout and try again.")


if __name__ == "__main__":
    main()
