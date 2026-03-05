"""Local self-check for Theatre Chat without deploying to a server.

Usage:
  python scripts/selfcheck.py
"""

import os
import re
import sys
from pathlib import Path

# Configure test environment BEFORE importing app/database modules.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["DB_PATH"] = "selfcheck_theatre_chat.db"
os.environ["INITIAL_INVITE_CODE"] = "SELFTEST-CODE"
os.environ["SECRET_KEY"] = "selfcheck-secret-key"

from app import app  # noqa: E402


def extract_csrf(html_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html_text)
    if not match:
        raise RuntimeError("CSRF token not found in page")
    return match.group(1)


def main() -> None:
    db_file = Path(os.environ["DB_PATH"])
    client = app.test_client()

    # 1) Open register page and get CSRF.
    register_page = client.get("/register")
    assert register_page.status_code == 200
    csrf = extract_csrf(register_page.get_data(as_text=True))

    # 2) Register first user (must become admin) by initial invite code.
    reg_resp = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "invite_code": "SELFTEST-CODE",
            "email": "admin@example.com",
            "first_name": "Admin",
            "last_name": "User",
            "password": "StrongPass123",
            "password_confirm": "StrongPass123",
        },
        follow_redirects=True,
    )
    assert reg_resp.status_code == 200
    assert "Основной чат" in reg_resp.get_data(as_text=True)

    # 3) Send a message.
    with client.session_transaction() as sess:
        csrf_api = sess["csrf_token"]
    send_resp = client.post(
        "/api/messages",
        data={"content": "Тестовое сообщение", "csrf_token": csrf_api},
        headers={"X-CSRF-Token": csrf_api},
    )
    assert send_resp.status_code == 200

    # 4) Create calendar event as admin.
    cal_page = client.get("/calendar")
    csrf_calendar = extract_csrf(cal_page.get_data(as_text=True))
    event_resp = client.post(
        "/calendar",
        data={
            "csrf_token": csrf_calendar,
            "title": "Репетиция",
            "event_date": "2030-01-01",
            "event_time": "18:00",
            "description": "Технический прогон",
        },
        follow_redirects=True,
    )
    assert event_resp.status_code == 200
    page_text = event_resp.get_data(as_text=True)
    assert "Событие создано" in page_text
    assert "Репетиция" in page_text

    # 5) Ensure admin panel is available.
    admin_resp = client.get("/admin")
    assert admin_resp.status_code == 200
    assert "Админ-панель" in admin_resp.get_data(as_text=True)

    print("Self-check passed ✅")

    if db_file.exists():
        db_file.unlink()


if __name__ == "__main__":
    main()
