import hashlib
import html
import os
import re
import sqlite3
from functools import wraps
from secrets import token_hex

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import create_invite, get_db, init_db, now_iso

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or g.user["role"] != "admin":
            flash("Доступ только для администратора.", "error")
            return redirect(url_for("chat"))
        return view(*args, **kwargs)

    return wrapped


def validate_csrf():
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    saved = session.get("csrf_token")
    if not token or not saved:
        return False
    return hashlib.sha256(token.encode()).digest() == hashlib.sha256(saved.encode()).digest()


@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid:
        with get_db() as conn:
            g.user = conn.execute(
                "SELECT id, email, first_name, last_name, role FROM users WHERE id = ?", (uid,)
            ).fetchone()


@app.context_processor
def inject_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = token_hex(16)
    return {"csrf_token": session["csrf_token"]}


@app.template_filter("fmt_dt")
def format_datetime(value):
    if not value:
        return ""
    return value.replace("T", " ")


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("chat"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("chat"))

    if request.method == "POST":
        if not validate_csrf():
            flash("CSRF token invalid.", "error")
            return redirect(url_for("register"))

        invite_code = request.form.get("invite_code", "").strip()
        email = request.form.get("email", "").strip().lower()
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if not EMAIL_RE.match(email):
            flash("Введите корректный email.", "error")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Пароль должен быть не короче 8 символов.", "error")
            return redirect(url_for("register"))
        if password != password_confirm:
            flash("Пароли не совпадают.", "error")
            return redirect(url_for("register"))

        with get_db() as conn:
            invite = conn.execute(
                "SELECT * FROM invitations WHERE code = ? AND is_active = 1", (invite_code,)
            ).fetchone()
            if not invite:
                flash("Код приглашения не найден или уже использован.", "error")
                return redirect(url_for("register"))

            existing = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                flash("Пользователь с таким email уже существует.", "error")
                return redirect(url_for("register"))

            user_count = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
            role = "admin" if user_count == 0 else "member"

            cursor = conn.execute(
                """
                INSERT INTO users(email, first_name, last_name, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    first_name,
                    last_name,
                    generate_password_hash(password),
                    role,
                    now_iso(),
                ),
            )
            user_id = cursor.lastrowid
            conn.execute(
                """
                UPDATE invitations
                SET is_active = 0, used_by = ?, used_at = ?
                WHERE id = ?
                """,
                (user_id, now_iso(), invite["id"]),
            )

        session.clear()
        session["user_id"] = user_id
        session["csrf_token"] = token_hex(16)
        flash("Регистрация прошла успешно.", "success")
        return redirect(url_for("chat"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("chat"))

    if request.method == "POST":
        if not validate_csrf():
            flash("CSRF token invalid.", "error")
            return redirect(url_for("login"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Неверный email или пароль.", "error")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session["csrf_token"] = token_hex(16)
        flash("Добро пожаловать!", "success")
        return redirect(url_for("chat"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not validate_csrf():
        flash("CSRF token invalid.", "error")
        return redirect(url_for("chat"))
    session.clear()
    flash("Вы вышли из системы.", "success")
    return redirect(url_for("index"))


@app.route("/chat")
@login_required
def chat():
    query = request.args.get("q", "").strip()
    search_results = []
    if query:
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT 'message' AS kind, m.id AS entity_id, m.content, m.created_at,
                       u.first_name || ' ' || u.last_name AS author
                FROM messages m
                JOIN users u ON u.id = m.user_id
                WHERE m.content LIKE ?
                UNION ALL
                SELECT 'reply' AS kind, r.id AS entity_id, r.content, r.created_at,
                       u.first_name || ' ' || u.last_name AS author
                FROM thread_replies r
                JOIN users u ON u.id = r.user_id
                WHERE r.content LIKE ?
                ORDER BY created_at DESC
                LIMIT 100
                """,
                (f"%{query}%", f"%{query}%"),
            ).fetchall()
            for row in rows:
                row["content"] = html.escape(row["content"])
                search_results.append(row)

    return render_template("chat.html", query=query, search_results=search_results)


def _fetch_messages(conn, current_user_id: int):
    messages = conn.execute(
        """
        SELECT m.id, m.content, m.created_at, m.user_id,
               u.first_name || ' ' || u.last_name AS author
        FROM messages m
        JOIN users u ON u.id = m.user_id
        ORDER BY m.created_at ASC
        """
    ).fetchall()

    for msg in messages:
        msg["mine"] = msg["user_id"] == current_user_id
        msg["replies"] = conn.execute(
            """
            SELECT r.id, r.content, r.created_at, r.user_id,
                   u.first_name || ' ' || u.last_name AS author
            FROM thread_replies r
            JOIN users u ON u.id = r.user_id
            WHERE r.message_id = ?
            ORDER BY r.created_at ASC
            """,
            (msg["id"],),
        ).fetchall()

        msg_react = conn.execute(
            """
            SELECT mr.user_id, u.first_name || ' ' || u.last_name AS author
            FROM message_reactions mr
            JOIN users u ON u.id = mr.user_id
            WHERE mr.message_id = ? AND mr.emoji = '👍'
            """,
            (msg["id"],),
        ).fetchall()
        msg["reaction_count"] = len(msg_react)
        msg["reaction_users"] = [x["author"] for x in msg_react]
        msg["reacted_by_me"] = any(x["user_id"] == current_user_id for x in msg_react)

        for reply in msg["replies"]:
            reply["mine"] = reply["user_id"] == current_user_id
            reply_react = conn.execute(
                """
                SELECT rr.user_id, u.first_name || ' ' || u.last_name AS author
                FROM reply_reactions rr
                JOIN users u ON u.id = rr.user_id
                WHERE rr.reply_id = ? AND rr.emoji = '👍'
                """,
                (reply["id"],),
            ).fetchall()
            reply["reaction_count"] = len(reply_react)
            reply["reaction_users"] = [x["author"] for x in reply_react]
            reply["reacted_by_me"] = any(x["user_id"] == current_user_id for x in reply_react)
    return messages


@app.route("/api/messages")
@login_required
def api_messages():
    with get_db() as conn:
        data = _fetch_messages(conn, g.user["id"])
    return jsonify(data)


@app.route("/api/messages", methods=["POST"])
@login_required
def api_send_message():
    if not validate_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"error": "Empty message"}), 400
    if len(content) > 2000:
        return jsonify({"error": "Message too long"}), 400

    with get_db() as conn:
        conn.execute(
            "INSERT INTO messages(user_id, content, created_at) VALUES (?, ?, ?)",
            (g.user["id"], content, now_iso()),
        )
    return jsonify({"ok": True})


@app.route("/api/messages/<int:message_id>/reply", methods=["POST"])
@login_required
def api_reply(message_id):
    if not validate_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"error": "Empty reply"}), 400

    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM messages WHERE id = ?", (message_id,)).fetchone()
        if not exists:
            return jsonify({"error": "Message not found"}), 404

        conn.execute(
            """
            INSERT INTO thread_replies(message_id, user_id, content, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (message_id, g.user["id"], content, now_iso()),
        )

    return jsonify({"ok": True})


@app.route("/api/messages/<int:message_id>/react", methods=["POST"])
@login_required
def api_react_message(message_id):
    if not validate_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM messages WHERE id = ?", (message_id,)).fetchone()
        if not exists:
            return jsonify({"error": "Message not found"}), 404

        reaction = conn.execute(
            "SELECT id FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = '👍'",
            (message_id, g.user["id"]),
        ).fetchone()

        if reaction:
            conn.execute("DELETE FROM message_reactions WHERE id = ?", (reaction["id"],))
            active = False
        else:
            conn.execute(
                "INSERT INTO message_reactions(message_id, user_id, emoji, created_at) VALUES (?, ?, '👍', ?)",
                (message_id, g.user["id"], now_iso()),
            )
            active = True

        total = conn.execute(
            "SELECT COUNT(*) AS cnt FROM message_reactions WHERE message_id = ? AND emoji = '👍'",
            (message_id,),
        ).fetchone()["cnt"]

    return jsonify({"ok": True, "active": active, "count": total})


@app.route("/api/replies/<int:reply_id>/react", methods=["POST"])
@login_required
def api_react_reply(reply_id):
    if not validate_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM thread_replies WHERE id = ?", (reply_id,)).fetchone()
        if not exists:
            return jsonify({"error": "Reply not found"}), 404

        reaction = conn.execute(
            "SELECT id FROM reply_reactions WHERE reply_id = ? AND user_id = ? AND emoji = '👍'",
            (reply_id, g.user["id"]),
        ).fetchone()

        if reaction:
            conn.execute("DELETE FROM reply_reactions WHERE id = ?", (reaction["id"],))
            active = False
        else:
            conn.execute(
                "INSERT INTO reply_reactions(reply_id, user_id, emoji, created_at) VALUES (?, ?, '👍', ?)",
                (reply_id, g.user["id"], now_iso()),
            )
            active = True

        total = conn.execute(
            "SELECT COUNT(*) AS cnt FROM reply_reactions WHERE reply_id = ? AND emoji = '👍'",
            (reply_id,),
        ).fetchone()["cnt"]

    return jsonify({"ok": True, "active": active, "count": total})


@app.route("/calendar", methods=["GET", "POST"])
@login_required
def calendar_view():
    if request.method == "POST":
        if g.user["role"] != "admin":
            flash("Только админ может создавать события.", "error")
            return redirect(url_for("calendar_view"))
        if not validate_csrf():
            flash("CSRF token invalid.", "error")
            return redirect(url_for("calendar_view"))

        title = request.form.get("title", "").strip()
        event_date = request.form.get("event_date", "").strip()
        event_time = request.form.get("event_time", "").strip()
        description = request.form.get("description", "").strip()

        if not title or not event_date or not event_time:
            flash("Заполните обязательные поля события.", "error")
            return redirect(url_for("calendar_view"))

        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events(title, event_date, event_time, description, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, event_date, event_time, description, g.user["id"], now_iso()),
            )
            event_id = cursor.lastrowid
            conn.execute(
                """
                INSERT INTO messages(user_id, content, created_at, event_id)
                VALUES (?, ?, ?, ?)
                """,
                (
                    g.user["id"],
                    f"🗓 СОБЫТИЕ: {title}, {event_date} в {event_time}",
                    now_iso(),
                    event_id,
                ),
            )
        flash("Событие создано.", "success")
        return redirect(url_for("calendar_view"))

    with get_db() as conn:
        events = conn.execute(
            """
            SELECT e.*, u.first_name || ' ' || u.last_name AS creator
            FROM events e
            JOIN users u ON u.id = e.created_by
            ORDER BY e.event_date ASC, e.event_time ASC
            """
        ).fetchall()
    return render_template("calendar.html", events=events)


@app.route("/calendar/<int:event_id>/edit", methods=["POST"])
@admin_required
def edit_event(event_id):
    if not validate_csrf():
        flash("CSRF token invalid.", "error")
        return redirect(url_for("calendar_view"))

    title = request.form.get("title", "").strip()
    event_date = request.form.get("event_date", "").strip()
    event_time = request.form.get("event_time", "").strip()
    description = request.form.get("description", "").strip()
    if not title or not event_date or not event_time:
        flash("Заполните обязательные поля.", "error")
        return redirect(url_for("calendar_view"))

    with get_db() as conn:
        conn.execute(
            """
            UPDATE events
            SET title = ?, event_date = ?, event_time = ?, description = ?
            WHERE id = ?
            """,
            (title, event_date, event_time, description, event_id),
        )
    flash("Событие обновлено.", "success")
    return redirect(url_for("calendar_view"))


@app.route("/calendar/<int:event_id>/delete", methods=["POST"])
@admin_required
def delete_event(event_id):
    if not validate_csrf():
        flash("CSRF token invalid.", "error")
        return redirect(url_for("calendar_view"))

    with get_db() as conn:
        conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
    flash("Событие удалено.", "success")
    return redirect(url_for("calendar_view"))


@app.route("/admin")
@admin_required
def admin_panel():
    with get_db() as conn:
        invites = conn.execute(
            """
            SELECT i.*, u.first_name || ' ' || u.last_name AS creator
            FROM invitations i
            LEFT JOIN users u ON u.id = i.created_by
            ORDER BY i.created_at DESC
            """
        ).fetchall()
        users = conn.execute(
            "SELECT id, email, first_name, last_name, role, created_at FROM users ORDER BY created_at ASC"
        ).fetchall()
        messages = conn.execute(
            """
            SELECT m.id, m.content, m.created_at, u.first_name || ' ' || u.last_name AS author
            FROM messages m
            JOIN users u ON u.id = m.user_id
            ORDER BY m.created_at DESC LIMIT 100
            """
        ).fetchall()
    return render_template("admin.html", invites=invites, users=users, messages=messages)


@app.route("/admin/invites", methods=["POST"])
@admin_required
def admin_create_invite():
    if not validate_csrf():
        flash("CSRF token invalid.", "error")
        return redirect(url_for("admin_panel"))

    with get_db() as conn:
        code = create_invite(conn, g.user["id"])
    flash(f"Новый код приглашения: {code}", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if not validate_csrf():
        flash("CSRF token invalid.", "error")
        return redirect(url_for("admin_panel"))

    if user_id == g.user["id"]:
        flash("Нельзя удалить самого себя.", "error")
        return redirect(url_for("admin_panel"))

    with get_db() as conn:
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            flash("Пользователь не найден.", "error")
        elif user["role"] == "admin":
            flash("Нельзя удалить другого администратора.", "error")
        else:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            flash("Пользователь удален.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/messages/<int:message_id>/delete", methods=["POST"])
@admin_required
def admin_delete_message(message_id):
    if not validate_csrf():
        flash("CSRF token invalid.", "error")
        return redirect(url_for("admin_panel"))

    with get_db() as conn:
        conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    flash("Сообщение удалено.", "success")
    return redirect(url_for("admin_panel"))


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
    response.headers["Content-Security-Policy"] = csp
    return response


@app.errorhandler(sqlite3.Error)
def handle_db_error(error):
    return render_template("error.html", message=f"Database error: {error}"), 500


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
else:
    init_db()
