# Secure Online Event Booking & E-Ticketing Prototype

**Information Security – Complex Computing Problem (CCP)**  
Riphah International University – Faculty of Computing  
Students: Hamza Rahim (56776), Rashid Islam (54384)  
Instructor: Dr. Jawaid Iqbal  

## Overview

Local Python + SQLite prototype that demonstrates practical information-security controls for an online event-booking and e-ticketing system:

- Role-based access control (attendee / gate_staff / admin)
- Ownership checks on bookings and tickets
- Salted PBKDF2-HMAC-SHA256 password hashing
- HMAC-SHA256 ticket integrity (forgery prevention)
- Database-backed single-use ticket redemption (atomic)
- SQLite transactions for seat-inventory integrity (overbooking prevention)
- Parameterized SQL queries
- Restricted audit logging and protection of the ticket-signing key

**Scope boundary:** Simulated data only. No production systems, real customer data, live payment gateways, or external scanning.

## Quick Start

### Option A – Modern Web Frontend (Streamlit) ⭐ Recommended

```bash
cd e_ticket_secure
streamlit run src/app_streamlit.py
```

Then open the URL shown in the terminal (usually http://localhost:8501).

### Option B – Original CLI

```bash
cd e_ticket_secure
python3 src/secure_eticket.py
```

### Demo Accounts

| Username | Password   | Role        |
|----------|------------|-------------|
| admin    | Admin@123  | admin       |
| gate1    | Gate@123   | gate_staff  |
| alice    | Pass@123   | attendee    |
| bob      | Pass@123   | attendee    |

## Security Test Suite

```bash
python3 tests/security_tests.py
```

Expected result: **15/15 tests PASSED**

Tests cover:

1. Invalid credentials
2. Role enforcement (attendee cannot create events / redeem tickets)
3. Successful booking & ticket generation
4. Forged/altered token rejection
5. First successful redemption
6. Replay / second-redemption denial
7. Signature alone insufficient
8. Overbooking prevention
9. Ownership check (non-owner cannot generate foreign ticket)
10. Audit-log access control
11. SQL-injection resistance on login

## Project Structure

```
e_ticket_secure/
├── src/
│   ├── secure_eticket.py      # Core security backend (CLI + shared logic)
│   └── app_streamlit.py       # Modern Streamlit web frontend
├── tests/
│   └── security_tests.py      # Automated security test evidence
├── evidence/
│   └── security_test_results.txt
├── docs/
│   ├── Final_Report_Secure_ETicket_CCP.docx
│   └── Presentation_Secure_ETicket_CCP.pptx
└── README.md
```

## Key Design Decisions

| Control                    | Technique                              | Threat mitigated                  |
|---------------------------|----------------------------------------|-----------------------------------|
| Authentication            | PBKDF2-HMAC-SHA256 (260k iterations)  | Credential stuffing / offline cracking |
| Authorization             | Per-request role + ownership checks   | Privilege escalation, IDOR        |
| Ticket integrity          | HMAC-SHA256 over token\|booking\|event| Ticket forgery                    |
| Ticket uniqueness         | Atomic DB update (BEGIN IMMEDIATE)    | Replay / double redemption        |
| Seat integrity            | Transactional seat decrement          | Overbooking / race conditions     |
| Injection prevention      | Parameterized queries only            | SQL injection                     |
| Accountability            | Restricted audit log                  | Lack of forensic evidence         |
| Key protection            | File permissions 0600, not in DB      | Key disclosure                    |

## Ethical & Legal Notes

- Uses only synthetic / demo data.
- No scanning or interaction with real third-party services.
- Follows least privilege, data minimization, and complete mediation principles.
- See the full project report for legal (PECA, data-protection principles), ethical, and professional analysis.

## References

- NIST SP 800-30 Rev. 1 – Guide for Conducting Risk Assessments
- NIST SP 800-63B – Digital Identity Guidelines
- OWASP API Security Top 10 (2023)
- OWASP Application Security Verification Standard (ASVS) v5
