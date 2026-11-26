#!/usr/bin/env python3
"""
Secure Online Event Booking & E-Ticketing Prototype
Implements:
- Role-based access control (attendee, gate_staff, admin)
- Ownership checks for bookings
- Salted PBKDF2-HMAC-SHA256 password hashing
- HMAC-SHA256 signed single-use tickets
- Atomic single-use ticket redemption
- SQLite transactions for seat inventory integrity
- Parameterized queries (SQL injection prevention)
- Restricted audit logging
- Data minimization principles
"""

import sqlite3
import hashlib
import hmac
import secrets
import os
import tempfile
import time
from datetime import datetime
from getpass import getpass
from typing import Optional, Tuple, List, Dict

# ---------------------------------------------------------------------------
# Configuration (secure defaults)
# ---------------------------------------------------------------------------
# Use cross-platform temp directory for SQLite database and keys
_DATA_DIR = os.environ.get("ETICKET_DATA_DIR") or os.path.join(tempfile.gettempdir(), "eticket_secure_data")
os.makedirs(_DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(_DATA_DIR, "eticket.db")
SECRET_KEY_PATH = os.path.join(_DATA_DIR, "ticket_signing.key")
PBKDF2_ITERATIONS = 260000          # NIST recommended minimum range
TOKEN_BYTES = 32
HMAC_ALG = hashlib.sha256

# Roles
ROLE_ATTENDEE = "attendee"
ROLE_GATE = "gate_staff"
ROLE_ADMIN = "admin"
VALID_ROLES = {ROLE_ATTENDEE, ROLE_GATE, ROLE_ADMIN}

# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------
def generate_salt(length: int = 16) -> bytes:
    return secrets.token_bytes(length)

def hash_password(password: str, salt: bytes) -> str:
    """Salted PBKDF2-HMAC-SHA256 password hashing."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()

def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    return hmac.compare_digest(hash_password(password, salt), stored_hash)

def load_or_create_signing_key() -> bytes:
    os.makedirs(os.path.dirname(SECRET_KEY_PATH), exist_ok=True)
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) >= 32:
            return key
    key = secrets.token_bytes(32)
    with open(SECRET_KEY_PATH, "wb") as f:
        f.write(key)
    try:
        os.chmod(SECRET_KEY_PATH, 0o600)
    except (OSError, AttributeError):
        pass
    return key

def create_ticket_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)

def sign_ticket(token: str, booking_id: int, event_id: int, key: bytes) -> str:
    """HMAC-SHA256 over token|booking_id|event_id."""
    message = f"{token}|{booking_id}|{event_id}".encode("utf-8")
    return hmac.new(key, message, HMAC_ALG).hexdigest()

def verify_ticket_signature(token: str, booking_id: int, event_id: int, signature: str, key: bytes) -> bool:
    expected = sign_ticket(token, booking_id, event_id, key)
    return hmac.compare_digest(expected, signature)

# ---------------------------------------------------------------------------
# Database layer (parameterized queries + transactions)
# ---------------------------------------------------------------------------
class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            salt        TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL CHECK(role IN ('attendee','gate_staff','admin')),
            full_name   TEXT,
            email       TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            capacity    INTEGER NOT NULL CHECK(capacity > 0),
            seats_left  INTEGER NOT NULL,
            event_date  TEXT,
            created_by  INTEGER REFERENCES users(id),
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS bookings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            event_id    INTEGER NOT NULL REFERENCES events(id),
            seats       INTEGER NOT NULL CHECK(seats > 0),
            status      TEXT NOT NULL DEFAULT 'confirmed'
                        CHECK(status IN ('confirmed','cancelled')),
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id  INTEGER NOT NULL REFERENCES bookings(id),
            event_id    INTEGER NOT NULL REFERENCES events(id),
            token       TEXT UNIQUE NOT NULL,
            signature   TEXT NOT NULL,
            redeemed    INTEGER NOT NULL DEFAULT 0,
            redeemed_at TEXT,
            redeemed_by INTEGER REFERENCES users(id),
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id    INTEGER,
            action      TEXT NOT NULL,
            details     TEXT,
            success     INTEGER NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_tickets_token ON tickets(token);
        CREATE INDEX IF NOT EXISTS idx_bookings_user ON bookings(user_id);
        CREATE INDEX IF NOT EXISTS idx_bookings_event ON bookings(event_id);
        """)
        self.conn.commit()

    def log(self, actor_id: Optional[int], action: str, details: str, success: bool):
        """Restricted audit logging – no sensitive data (passwords, full tokens)."""
        safe_details = details[:200] if details else ""
        self.conn.execute(
            "INSERT INTO audit_log (actor_id, action, details, success) VALUES (?,?,?,?)",
            (actor_id, action, safe_details, 1 if success else 0)
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

# ---------------------------------------------------------------------------
# Core application logic
# ---------------------------------------------------------------------------
class SecureETicketApp:
    def __init__(self):
        self.db = Database()
        self.signing_key = load_or_create_signing_key()
        self.current_user: Optional[Dict] = None
        self._seed_demo_data()

    def _seed_demo_data(self):
        """Create synthetic demo accounts and one event if empty."""
        cur = self.db.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] > 0:
            return

        # Admin
        salt = generate_salt()
        self.db.conn.execute(
            "INSERT INTO users (username, salt, password_hash, role, full_name, email) VALUES (?,?,?,?,?,?)",
            ("admin", salt.hex(), hash_password("Admin@123", salt), ROLE_ADMIN, "System Admin", "admin@demo.local")
        )
        # Gate staff
        salt = generate_salt()
        self.db.conn.execute(
            "INSERT INTO users (username, salt, password_hash, role, full_name, email) VALUES (?,?,?,?,?,?)",
            ("gate1", salt.hex(), hash_password("Gate@123", salt), ROLE_GATE, "Gate Staff 1", "gate1@demo.local")
        )
        # Attendees
        for u, n in [("alice", "Alice Khan"), ("bob", "Bob Ahmed")]:
            salt = generate_salt()
            self.db.conn.execute(
                "INSERT INTO users (username, salt, password_hash, role, full_name, email) VALUES (?,?,?,?,?,?)",
                (u, salt.hex(), hash_password("Pass@123", salt), ROLE_ATTENDEE, n, f"{u}@demo.local")
            )
        # Sample event
        self.db.conn.execute(
            "INSERT INTO events (title, description, capacity, seats_left, event_date, created_by) VALUES (?,?,?,?,?,?)",
            ("Cybersecurity Summit 2026", "Annual InfoSec conference", 50, 50, "2026-12-15", 1)
        )
        self.db.conn.commit()
        print("[*] Demo data seeded. Default passwords: Admin@123 / Gate@123 / Pass@123")

    # ----- Authentication & Authorization -----
    def login(self, username: str, password: str) -> bool:
        cur = self.db.conn.execute(
            "SELECT id, username, salt, password_hash, role, full_name FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        if not row or not verify_password(password, row["salt"], row["password_hash"]):
            self.db.log(None, "LOGIN_FAILED", f"username={username}", False)
            return False
        self.current_user = dict(row)
        self.db.log(row["id"], "LOGIN_SUCCESS", f"role={row['role']}", True)
        return True

    def logout(self):
        if self.current_user:
            self.db.log(self.current_user["id"], "LOGOUT", "", True)
        self.current_user = None

    def require_login(self) -> bool:
        return self.current_user is not None

    def require_role(self, *roles: str) -> bool:
        if not self.current_user:
            return False
        return self.current_user["role"] in roles

    def require_ownership_or_admin(self, booking_user_id: int) -> bool:
        if not self.current_user:
            return False
        if self.current_user["role"] == ROLE_ADMIN:
            return True
        return self.current_user["id"] == booking_user_id

    # ----- User management (admin only) -----
    def register_user(self, username: str, password: str, role: str, full_name: str, email: str) -> Tuple[bool, str]:
        if not self.require_role(ROLE_ADMIN):
            return False, "Only admin can register new users."
        if role not in VALID_ROLES:
            return False, "Invalid role."
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        salt = generate_salt()
        try:
            self.db.conn.execute(
                "INSERT INTO users (username, salt, password_hash, role, full_name, email) VALUES (?,?,?,?,?,?)",
                (username, salt.hex(), hash_password(password, salt), role, full_name, email)
            )
            self.db.conn.commit()
            self.db.log(self.current_user["id"], "USER_REGISTER", f"new_user={username} role={role}", True)
            return True, f"User '{username}' created with role '{role}'."
        except sqlite3.IntegrityError:
            return False, "Username already exists."

    def list_users(self) -> List[Dict]:
        """Admin-only: list all registered users (excluding sensitive password/salt fields)."""
        if not self.require_role(ROLE_ADMIN):
            return []
        cur = self.db.conn.execute(
            "SELECT id, username, role, full_name, email, created_at FROM users ORDER BY id"
        )
        return [dict(r) for r in cur.fetchall()]

    def get_system_metrics(self) -> Optional[Dict]:
        """Admin-only: summary metrics for the system dashboard."""
        if not self.require_role(ROLE_ADMIN):
            return None
        total_users = self.db.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_events = self.db.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_bookings = self.db.conn.execute("SELECT COUNT(*) FROM bookings").fetchone()[0]
        total_tickets = self.db.conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
        redeemed_tickets = self.db.conn.execute("SELECT COUNT(*) FROM tickets WHERE redeemed = 1").fetchone()[0]
        total_logs = self.db.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {
            "total_users": total_users,
            "total_events": total_events,
            "total_bookings": total_bookings,
            "total_tickets": total_tickets,
            "redeemed_tickets": redeemed_tickets,
            "total_logs": total_logs,
        }

    def get_ticket_info(self, token: str) -> Optional[Dict]:
        """Retrieve ticket and booking metadata for display (Gate Staff & Admin)."""
        if not self.require_role(ROLE_GATE, ROLE_ADMIN):
            return None
        cur = self.db.conn.execute("""
            SELECT t.id, t.booking_id, t.event_id, t.token, t.signature, t.redeemed, t.redeemed_at,
                   e.title AS event_title, e.event_date,
                   b.seats, u.full_name AS attendee_name, u.username AS attendee_username
            FROM tickets t
            JOIN events e ON e.id = t.event_id
            JOIN bookings b ON b.id = t.booking_id
            JOIN users u ON u.id = b.user_id
            WHERE t.token = ?
        """, (token,))
        row = cur.fetchone()
        return dict(row) if row else None

    # ----- Events -----
    def list_events(self) -> List[Dict]:
        cur = self.db.conn.execute(
            "SELECT id, title, description, capacity, seats_left, event_date FROM events ORDER BY id"
        )
        return [dict(r) for r in cur.fetchall()]

    def create_event(self, title: str, description: str, capacity: int, event_date: str) -> Tuple[bool, str]:
        if not self.require_role(ROLE_ADMIN):
            return False, "Only admin can create events."
        if capacity <= 0:
            return False, "Capacity must be positive."
        self.db.conn.execute(
            "INSERT INTO events (title, description, capacity, seats_left, event_date, created_by) VALUES (?,?,?,?,?,?)",
            (title, description, capacity, capacity, event_date, self.current_user["id"])
        )
        self.db.conn.commit()
        self.db.log(self.current_user["id"], "EVENT_CREATE", f"title={title} capacity={capacity}", True)
        return True, "Event created."

    # ----- Booking (with transaction for seat integrity) -----
    def book_seats(self, event_id: int, seats: int) -> Tuple[bool, str, Optional[int]]:
        if not self.require_login():
            return False, "Login required.", None
        if not self.require_role(ROLE_ATTENDEE, ROLE_ADMIN):
            return False, "Only attendees (or admin) can book.", None
        if seats <= 0:
            return False, "Seats must be positive.", None

        try:
            # Explicit transaction for atomic seat update
            self.db.conn.execute("BEGIN IMMEDIATE")
            cur = self.db.conn.execute(
                "SELECT seats_left FROM events WHERE id = ?", (event_id,)
            )
            row = cur.fetchone()
            if not row:
                self.db.conn.rollback()
                return False, "Event not found.", None
            if row["seats_left"] < seats:
                self.db.conn.rollback()
                self.db.log(self.current_user["id"], "BOOKING_FAILED", f"event={event_id} seats={seats} reason=overcapacity", False)
                return False, f"Only {row['seats_left']} seats left.", None

            # Decrease seats
            self.db.conn.execute(
                "UPDATE events SET seats_left = seats_left - ? WHERE id = ?",
                (seats, event_id)
            )
            # Create booking
            cur = self.db.conn.execute(
                "INSERT INTO bookings (user_id, event_id, seats) VALUES (?,?,?)",
                (self.current_user["id"], event_id, seats)
            )
            booking_id = cur.lastrowid
            self.db.conn.commit()
            self.db.log(self.current_user["id"], "BOOKING_SUCCESS", f"booking={booking_id} event={event_id} seats={seats}", True)
            return True, f"Booked {seats} seat(s). Booking ID: {booking_id}", booking_id
        except Exception as e:
            self.db.conn.rollback()
            self.db.log(self.current_user["id"], "BOOKING_ERROR", str(e)[:100], False)
            return False, f"Booking failed: {e}", None

    def my_bookings(self) -> List[Dict]:
        if not self.require_login():
            return []
        if self.current_user["role"] == ROLE_ADMIN:
            cur = self.db.conn.execute("""
                SELECT b.id, b.event_id, e.title, b.seats, b.status, b.created_at, u.username
                FROM bookings b
                JOIN events e ON e.id = b.event_id
                JOIN users u ON u.id = b.user_id
                ORDER BY b.id DESC
            """)
        else:
            cur = self.db.conn.execute("""
                SELECT b.id, b.event_id, e.title, b.seats, b.status, b.created_at
                FROM bookings b
                JOIN events e ON e.id = b.event_id
                WHERE b.user_id = ?
                ORDER BY b.id DESC
            """, (self.current_user["id"],))
        return [dict(r) for r in cur.fetchall()]

    # ----- Ticket generation (HMAC integrity) -----
    def generate_ticket(self, booking_id: int) -> Tuple[bool, str, Optional[Dict]]:
        if not self.require_login():
            return False, "Login required.", None

        cur = self.db.conn.execute(
            "SELECT id, user_id, event_id, seats, status FROM bookings WHERE id = ?",
            (booking_id,)
        )
        booking = cur.fetchone()
        if not booking:
            return False, "Booking not found.", None
        if booking["status"] != "confirmed":
            return False, "Booking is not confirmed.", None
        if not self.require_ownership_or_admin(booking["user_id"]):
            self.db.log(self.current_user["id"], "TICKET_GEN_DENIED", f"booking={booking_id}", False)
            return False, "Access denied: not your booking.", None

        # Check if ticket already exists
        cur = self.db.conn.execute(
            "SELECT id, token, signature FROM tickets WHERE booking_id = ?", (booking_id,)
        )
        existing = cur.fetchone()
        if existing:
            return True, "Ticket already generated.", dict(existing)

        token = create_ticket_token()
        signature = sign_ticket(token, booking_id, booking["event_id"], self.signing_key)
        self.db.conn.execute(
            "INSERT INTO tickets (booking_id, event_id, token, signature) VALUES (?,?,?,?)",
            (booking_id, booking["event_id"], token, signature)
        )
        self.db.conn.commit()
        self.db.log(self.current_user["id"], "TICKET_GENERATED", f"booking={booking_id}", True)
        return True, "Ticket generated successfully.", {
            "token": token,
            "signature": signature,
            "booking_id": booking_id,
            "event_id": booking["event_id"]
        }

    # ----- Gate validation (single-use, atomic, signature check) -----
    def validate_and_redeem(self, token: str) -> Tuple[bool, str]:
        """
        Critical security control:
        1. Look up ticket by token
        2. Verify HMAC signature
        3. Check not already redeemed
        4. Atomically mark as redeemed (BEGIN IMMEDIATE)
        A valid signature alone is NEVER accepted as proof the ticket is unused.
        """
        if not self.require_role(ROLE_GATE, ROLE_ADMIN):
            return False, "Only gate staff or admin can validate tickets."

        try:
            self.db.conn.execute("BEGIN IMMEDIATE")
            cur = self.db.conn.execute(
                "SELECT id, booking_id, event_id, token, signature, redeemed FROM tickets WHERE token = ?",
                (token,)
            )
            ticket = cur.fetchone()
            if not ticket:
                self.db.conn.rollback()
                self.db.log(self.current_user["id"], "REDEEM_FAIL", "token_not_found", False)
                return False, "Invalid ticket: not found."

            # Signature verification
            if not verify_ticket_signature(
                ticket["token"], ticket["booking_id"], ticket["event_id"],
                ticket["signature"], self.signing_key
            ):
                self.db.conn.rollback()
                self.db.log(self.current_user["id"], "REDEEM_FAIL", f"ticket={ticket['id']} bad_signature", False)
                return False, "Invalid ticket: signature verification failed (possible forgery)."

            if ticket["redeemed"]:
                self.db.conn.rollback()
                self.db.log(self.current_user["id"], "REDEEM_FAIL", f"ticket={ticket['id']} already_redeemed", False)
                return False, "Ticket already redeemed. Entry denied."

            # Atomic redemption
            self.db.conn.execute(
                "UPDATE tickets SET redeemed = 1, redeemed_at = datetime('now'), redeemed_by = ? WHERE id = ? AND redeemed = 0",
                (self.current_user["id"], ticket["id"])
            )
            if self.db.conn.total_changes == 0:
                self.db.conn.rollback()
                return False, "Race condition: ticket was redeemed by another gate."

            self.db.conn.commit()
            self.db.log(self.current_user["id"], "REDEEM_SUCCESS", f"ticket={ticket['id']} booking={ticket['booking_id']}", True)
            return True, f"VALID – Entry granted. Ticket #{ticket['id']} redeemed."
        except Exception as e:
            self.db.conn.rollback()
            self.db.log(self.current_user["id"], "REDEEM_ERROR", str(e)[:100], False)
            return False, f"Validation error: {e}"

    # ----- Admin views (data minimization) -----
    def view_audit_log(self, limit: int = 20) -> List[Dict]:
        if not self.require_role(ROLE_ADMIN):
            return []
        cur = self.db.conn.execute(
            "SELECT id, actor_id, action, details, success, created_at FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_event_stats(self, event_id: int) -> Optional[Dict]:
        if not self.require_role(ROLE_ADMIN, ROLE_GATE):
            return None
        cur = self.db.conn.execute(
            "SELECT title, capacity, seats_left FROM events WHERE id = ?", (event_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        redeemed = self.db.conn.execute(
            "SELECT COUNT(*) FROM tickets WHERE event_id = ? AND redeemed = 1", (event_id,)
        ).fetchone()[0]
        return {
            "title": row["title"],
            "capacity": row["capacity"],
            "seats_left": row["seats_left"],
            "redeemed_tickets": redeemed
        }

# ---------------------------------------------------------------------------
# Simple CLI interface for demonstration
# ---------------------------------------------------------------------------
def print_header(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def main():
    app = SecureETicketApp()
    print_header("Secure E-Ticketing Prototype – Information Security CCP")
    print("Roles: admin / gate_staff / attendee")
    print("Demo accounts: admin, gate1, alice, bob")
    print("Passwords: Admin@123 / Gate@123 / Pass@123")

    while True:
        if not app.current_user:
            print("\n[1] Login   [0] Exit")
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice == "1":
                user = input("Username: ").strip()
                pwd = getpass("Password: ")
                if app.login(user, pwd):
                    print(f"Welcome, {app.current_user['full_name']} ({app.current_user['role']})")
                else:
                    print("Login failed.")
            continue

        role = app.current_user["role"]
        print(f"\nLogged in as: {app.current_user['username']} [{role}]")
        print("-" * 40)

        if role == ROLE_ATTENDEE:
            print("[1] List events")
            print("[2] Book seats")
            print("[3] My bookings")
            print("[4] Generate ticket for booking")
            print("[5] Logout")
        elif role == ROLE_GATE:
            print("[1] Validate & redeem ticket")
            print("[2] Event stats")
            print("[3] Logout")
        elif role == ROLE_ADMIN:
            print("[1] List events")
            print("[2] Create event")
            print("[3] Register user")
            print("[4] Book seats (as admin)")
            print("[5] View all bookings")
            print("[6] Generate ticket")
            print("[7] Validate ticket")
            print("[8] Audit log")
            print("[9] Event stats")
            print("[0] Logout")

        choice = input("Choice: ").strip()

        if role == ROLE_ATTENDEE:
            if choice == "1":
                for e in app.list_events():
                    print(f"  #{e['id']} {e['title']} | seats left: {e['seats_left']}/{e['capacity']} | {e['event_date']}")
            elif choice == "2":
                eid = int(input("Event ID: "))
                seats = int(input("Number of seats: "))
                ok, msg, bid = app.book_seats(eid, seats)
                print(msg)
            elif choice == "3":
                for b in app.my_bookings():
                    print(f"  Booking #{b['id']} | {b['title']} | seats={b['seats']} | {b['status']}")
            elif choice == "4":
                bid = int(input("Booking ID: "))
                ok, msg, ticket = app.generate_ticket(bid)
                print(msg)
                if ticket and "token" in ticket:
                    print(f"  TOKEN: {ticket['token']}")
                    print(f"  (Keep this token safe – present at gate)")
            elif choice == "5":
                app.logout()
                print("Logged out.")

        elif role == ROLE_GATE:
            if choice == "1":
                token = input("Scan / enter ticket token: ").strip()
                ok, msg = app.validate_and_redeem(token)
                print(("✓ " if ok else "✗ ") + msg)
            elif choice == "2":
                eid = int(input("Event ID: "))
                stats = app.get_event_stats(eid)
                if stats:
                    print(f"  {stats['title']}: left={stats['seats_left']}/{stats['capacity']}, redeemed={stats['redeemed_tickets']}")
            elif choice == "3":
                app.logout()

        elif role == ROLE_ADMIN:
            if choice == "1":
                for e in app.list_events():
                    print(f"  #{e['id']} {e['title']} | left {e['seats_left']}/{e['capacity']}")
            elif choice == "2":
                title = input("Title: ")
                desc = input("Description: ")
                cap = int(input("Capacity: "))
                date = input("Date (YYYY-MM-DD): ")
                ok, msg = app.create_event(title, desc, cap, date)
                print(msg)
            elif choice == "3":
                u = input("Username: ")
                p = getpass("Password: ")
                r = input("Role (attendee/gate_staff/admin): ")
                n = input("Full name: ")
                e = input("Email: ")
                ok, msg = app.register_user(u, p, r, n, e)
                print(msg)
            elif choice == "4":
                eid = int(input("Event ID: "))
                seats = int(input("Seats: "))
                ok, msg, _ = app.book_seats(eid, seats)
                print(msg)
            elif choice == "5":
                for b in app.my_bookings():
                    print(f"  #{b['id']} user={b.get('username')} | {b['title']} | seats={b['seats']}")
            elif choice == "6":
                bid = int(input("Booking ID: "))
                ok, msg, ticket = app.generate_ticket(bid)
                print(msg)
                if ticket and "token" in ticket:
                    print(f"  TOKEN: {ticket['token']}")
            elif choice == "7":
                token = input("Token: ").strip()
                ok, msg = app.validate_and_redeem(token)
                print(("✓ " if ok else "✗ ") + msg)
            elif choice == "8":
                for log in app.view_audit_log(15):
                    print(f"  [{log['created_at']}] {log['action']} actor={log['actor_id']} ok={log['success']} {log['details']}")
            elif choice == "9":
                eid = int(input("Event ID: "))
                stats = app.get_event_stats(eid)
                if stats:
                    print(stats)
            elif choice == "0":
                app.logout()

    app.db.close()
    print("Goodbye.")

if __name__ == "__main__":
    main()
