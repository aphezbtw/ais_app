"""
Маршруты аутентификации и регистрации пользователей.
Закрывает замечания аудита:
1.1 — Роль agent недоступна для самоназначения (только 'user').
1.2 — Полный аудит авторизации (LOGIN_OK, LOGIN_FAIL, LOGIN_BLOCKED, REGISTER_OK, etc.) с защитой PII.
2.2 — Инвалидация прежних сессий при входе и маршрут /logout-all.
2.4 — logout и logout-all принимают ТОЛЬКО метод POST.
2.5 — Единая стратегия сессий через безопасную сессию Flask (session['user_id'], session['sid']).
3.3 — Бизнес-логика вынесена в services.authenticate и services.register_user.
"""
import sqlite3
from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from app.constants import (
    PASSWORD_MAX_LEN,
    PASSWORD_MIN_LEN,
    RATE_LIMIT_LOGIN,
    RATE_LIMIT_REGISTER,
    USERNAME_MAX_LEN,
    USERNAME_MIN_LEN,
)
from app.db import get_db
from app.security import (
    check_rate_limit,
    hash_identifier,
    login_required,
    start_session,
    terminate_all_user_sessions,
    terminate_session,
)
from app.services import authenticate, log_auth_event, register_user

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Аутентификация пользователя с защитой от брутфорса, тайминг-атак и полным аудитом."""
    if getattr(g, "current_user", None) or session.get("user_id"):
        return redirect(url_for("tickets.index"))

    if request.method == "POST":
        db = get_db()
        client_ip = request.remote_addr or "127.0.0.1"
        ip_hash = hash_identifier(client_ip)

        # Проверка rate-limit
        limit, window = RATE_LIMIT_LOGIN
        if not check_rate_limit(db, "login", client_ip, limit, window):
            log_auth_event("LOGIN_BLOCKED", ip_hash=ip_hash)
            flash("Слишком много неудачных попыток входа. Пожалуйста, подождите.", "danger")
            return render_template("auth/login.html", seed_demo_enabled=current_app.config["SEED_DEMO"]), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # Аутентификация через сервисный слой (пункт 3.3)
        user = authenticate(db, username, password)

        if not user:
            # Не логируем сырой username (защита PII 1.2)
            log_auth_event("LOGIN_FAIL", username_hash=hash_identifier(username), ip_hash=ip_hash)
            flash("Неверное имя пользователя или пароль.", "danger")
            return render_template("auth/login.html", seed_demo_enabled=current_app.config["SEED_DEMO"]), 401

        # Успешный вход (2.2, 2.5)
        raw_token = start_session(db, user["id"], lifetime_days=current_app.config["SESSION_LIFETIME_DAYS"])

        session.clear()
        session["user_id"] = user["id"]
        session["sid"] = raw_token
        session.permanent = True

        log_auth_event("LOGIN_OK", user_id=user["id"], ip_hash=ip_hash)

        next_url = request.args.get("next")
        if not next_url or not next_url.startswith("/"):
            next_url = url_for("tickets.index")

        flash(f"Добро пожаловать, {user['username']}!", "success")
        return redirect(next_url)

    return render_template("auth/login.html", seed_demo_enabled=current_app.config["SEED_DEMO"])


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Регистрация нового пользователя.
    1.1: Роль строго 'user'.
    1.2: Аудит регистрации (REGISTER_OK, REGISTER_CONFLICT).
    2.4: Атомарная обработка конфликтов логина.
    3.3: Бизнес-логика в register_user.
    """
    if getattr(g, "current_user", None) or session.get("user_id"):
        return redirect(url_for("tickets.index"))

    if request.method == "POST":
        db = get_db()
        client_ip = request.remote_addr or "127.0.0.1"
        ip_hash = hash_identifier(client_ip)

        limit, window = RATE_LIMIT_REGISTER
        if not check_rate_limit(db, "register", client_ip, limit, window):
            flash("Слишком много регистраций с вашего IP. Попробуйте позже.", "danger")
            return render_template("auth/register.html"), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or request.form.get("password2") or ""

        if password != confirm_password:
            flash("Пароли не совпадают.", "danger")
            return render_template("auth/register.html"), 400

        try:
            user_id = register_user(db, username, password)
        except ValueError as err:
            flash(str(err), "danger")
            return render_template("auth/register.html"), 400
        except sqlite3.IntegrityError:
            log_auth_event("REGISTER_CONFLICT", username_hash=hash_identifier(username), ip_hash=ip_hash)
            flash("Пользователь с таким именем уже зарегистрирован.", "danger")
            return render_template("auth/register.html"), 409

        # Авторизация после успешной регистрации (2.5)
        raw_token = start_session(db, user_id, lifetime_days=current_app.config["SESSION_LIFETIME_DAYS"])

        session.clear()
        session["user_id"] = user_id
        session["sid"] = raw_token
        session.permanent = True

        log_auth_event("REGISTER_OK", user_id=user_id, ip_hash=ip_hash)
        flash("Регистрация успешно завершена! Добро пожаловать в систему.", "success")
        return redirect(url_for("tickets.index"))

    return render_template("auth/register.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Выход из текущей сессии (пункт 2.4 — только метод POST)."""
    db = get_db()
    sid = session.get("sid")
    user_id = session.get("user_id")

    if sid:
        terminate_session(db, sid)

    if user_id:
        log_auth_event("LOGOUT", user_id=user_id)

    session.clear()
    flash("Вы успешно вышли из системы.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/logout-all", methods=["POST"])
@login_required
def logout_all():
    """Завершение всех активных сессий пользователя на всех устройствах (пункты 2.2, 2.4)."""
    db = get_db()
    uid = (g.current_user["id"] if getattr(g, "current_user", None) else None) or session.get("user_id")

    if uid:
        terminate_all_user_sessions(db, uid)
        log_auth_event("LOGOUT_ALL", user_id=uid)

    session.clear()
    flash("Все ваши активные сессии на всех устройствах завершены.", "info")
    return redirect(url_for("auth.login"))
