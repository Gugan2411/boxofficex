from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Depends
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from datetime import date
import os
import secrets
import re
import psycopg
from pydantic import BaseModel
from xml.sax.saxutils import escape as xml_escape


# ============================================================
# BOXOFFICEX BASE DIRECTORY
# ============================================================

LOCAL_BASE_DIR = Path(r"C:\Users\gugan\boxofficex")
BASE_DIR = Path(
    os.getenv(
        "BOXOFFICEX_BASE_DIR",
        str(LOCAL_BASE_DIR if LOCAL_BASE_DIR.exists() else Path(__file__).resolve().parent)
    )
).resolve()

POSTERS_DIR = BASE_DIR / "posters"
ACTORS_DIR = BASE_DIR / "actors"
ARTICLE_IMAGES_DIR = BASE_DIR / "article-images"
ARTICLE_IMAGES_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MOVIE_POSTER = "coming-soon.png"
DEFAULT_ACTOR_PHOTO = "default-actor.png"


def safe_movie_poster(filename):
    """Return a real poster filename or the BoxOfficeX fallback."""
    if filename:
        filename = str(filename).strip()
        if filename and (POSTERS_DIR / filename).is_file():
            return filename
    return DEFAULT_MOVIE_POSTER


def safe_actor_photo(filename):
    """Return a real actor-photo filename or the BoxOfficeX fallback."""
    if filename:
        filename = str(filename).strip()
        if filename and (ACTORS_DIR / filename).is_file():
            return filename
    return DEFAULT_ACTOR_PHOTO



print("BOXOFFICEX BASE DIR:", BASE_DIR)
print("POSTERS FOLDER EXISTS:", POSTERS_DIR.exists())
print("ACTORS FOLDER EXISTS:", ACTORS_DIR.exists())
print("ARTICLE IMAGES FOLDER:", ARTICLE_IMAGES_DIR)
print("ARTICLE IMAGES FOLDER EXISTS:", ARTICLE_IMAGES_DIR.exists())
print("LEO POSTER EXISTS:", (POSTERS_DIR / "leo.jpg").exists())


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(title="BoxOfficeX API")


# ============================================================
# MULTI-ADMIN SECURITY + ROLES + OWNER AUDIT
# ============================================================

import hashlib
import hmac
from datetime import datetime, timezone, time
from zoneinfo import ZoneInfo
from typing import Optional, Literal


SESSION_SECRET = os.getenv(
    "BOXOFFICEX_SESSION_SECRET",
    "CHANGE_ME_BOXOFFICEX_SESSION_SECRET_2026"
)

# The first Owner is bootstrapped from your current admin password so
# switching to multi-admin does not lock you out.
BOOTSTRAP_OWNER_EMAIL = os.getenv(
    "BOXOFFICEX_OWNER_EMAIL",
    "ownername1@boxoffice-x.com"
).strip().lower()

BOOTSTRAP_OWNER_PASSWORD = os.getenv(
    "BOXOFFICEX_OWNER_PASSWORD",
    os.getenv(
        "BOXOFFICEX_ADMIN_PASSWORD",
        "CHANGE_ME_BOXOFFICEX_ADMIN_PASSWORD"
    )
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="boxofficex_admin_session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=os.getenv(
        "BOXOFFICEX_HTTPS_ONLY",
        "false"
    ).strip().lower() in {"1", "true", "yes", "on"}
)


def hash_admin_password(password: str) -> str:
    """PBKDF2-SHA256 password hash. No plain admin passwords are stored."""
    salt = os.urandom(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{salt.hex()}${digest.hex()}"
    )


def verify_admin_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations)
        )

        return hmac.compare_digest(
            candidate.hex(),
            digest_hex
        )
    except Exception:
        return False


class AdminLoginData(BaseModel):
    email: str
    password: str


class AdminCreateData(BaseModel):
    email: str
    password: str
    display_name: str
    role: Literal["owner", "editor", "data_admin"]


class AdminUpdateData(BaseModel):
    display_name: Optional[str] = None
    role: Optional[Literal["owner", "editor", "data_admin"]] = None
    is_active: Optional[bool] = None


class AdminPasswordResetData(BaseModel):
    new_password: str


class AdminSelfPasswordChangeData(BaseModel):
    current_password: str
    new_password: str


def current_admin(request: Request):
    admin_id = request.session.get("admin_id")
    email = request.session.get("admin_email")
    role = request.session.get("admin_role")

    if not admin_id or not email or not role:
        return None

    return {
        "id": int(admin_id),
        "email": email,
        "display_name": request.session.get("admin_display_name") or email,
        "role": role,
        "session_id": request.session.get("admin_session_id")
    }


def _role_can_access(role: str, request: Request) -> bool:
    """
    owner      -> everything
    editor     -> article/content admin only
    data_admin -> movies, actors, release status and box-office data
    """
    if role == "owner":
        return True

    path = request.url.path
    method = request.method.upper()

    # All logged-in roles may read their session and log out.
    if path in {"/admin/session", "/admin/logout"}:
        return True

    # HTML admin pages.
    if method == "GET" and path.endswith(".html"):
        if role == "editor":
            return path == "/admin-articles.html"
        if role == "data_admin":
            return path in {
                "/admin.html",
                "/admin-new-movies.html",
                "/admin-daily-boxoffice.html",
                "/admin-regional-boxoffice.html",
            }

    # Article editor permissions.
    if role == "editor":
        return (
            path.startswith("/admin/articles")
            or path.startswith("/admin/article-blocks")
            or path.startswith("/admin/article-images")
        )

    # Movie/actor/box-office permissions.
    if role == "data_admin":
        if path.startswith("/admin/movies"):
            return True
        if path.startswith("/admin/actors"):
            return True
        if path.startswith("/admin/actor-movies"):
            return True
        if path.startswith("/admin/movie-collections"):
            return True
        if path in {
            "/admin/upload/movie-poster",
            "/admin/upload/actor-photo",
        }:
            return True

        # Existing protected POST /movies route.
        if path == "/movies" and method == "POST":
            return True

    return False


def require_admin(request: Request):
    admin = current_admin(request)

    if not admin:
        raise HTTPException(
            status_code=401,
            detail="Admin login required"
        )

    # Re-check active state on every protected request.
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT is_active, role, display_name
                FROM admins
                WHERE id = %s
            """, (admin["id"],))
            row = cur.fetchone()

    if not row or not row[0]:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Admin account is disabled"
        )

    live_role = row[1]

    # Keep session role/name synchronized with the database.
    request.session["admin_role"] = live_role
    request.session["admin_display_name"] = row[2]

    if not _role_can_access(live_role, request):
        raise HTTPException(
            status_code=403,
            detail="Your admin role does not have permission for this action"
        )

    return {
        **admin,
        "role": live_role,
        "display_name": row[2]
    }


def require_owner(request: Request):
    admin = require_admin(request)

    if admin["role"] != "owner":
        raise HTTPException(
            status_code=403,
            detail="Owner access required"
        )

    return admin


def record_admin_activity(
    admin_id: int,
    action: str,
    request_path: str,
    method: str,
    details: Optional[str] = None
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO admin_activity_logs (
                    admin_id,
                    action,
                    request_path,
                    http_method,
                    details
                )
                VALUES (%s, %s, %s, %s, %s)
            """, (
                admin_id,
                action,
                request_path,
                method,
                details
            ))
        conn.commit()


@app.middleware("http")
async def admin_audit_middleware(request: Request, call_next):
    response = await call_next(request)

    try:
        admin = current_admin(request)

        if admin:
            now = datetime.now(timezone.utc)

            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE admin_sessions
                        SET last_activity_at = %s
                        WHERE id = %s
                          AND admin_id = %s
                          AND logout_at IS NULL
                    """, (
                        now,
                        admin.get("session_id"),
                        admin["id"]
                    ))

                    cur.execute("""
                        UPDATE admins
                        SET last_activity_at = %s
                        WHERE id = %s
                    """, (now, admin["id"]))

                conn.commit()

            # Log successful data-changing requests automatically.
            if (
                request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                and response.status_code < 400
                and request.url.path not in {
                    "/admin/login",
                    "/admin/logout"
                }
            ):
                record_admin_activity(
                    admin["id"],
                    "data_change",
                    request.url.path,
                    request.method.upper(),
                    f"HTTP {response.status_code}"
                )
    except Exception as exc:
        # Audit failure must never break the public/admin request itself.
        print("ADMIN AUDIT WARNING:", exc)

    return response


@app.on_event("startup")
def initialize_multi_admin_security():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id BIGSERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL
                        CHECK (role IN ('owner', 'editor', 'data_admin')),
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_login_at TIMESTAMPTZ,
                    last_activity_at TIMESTAMPTZ
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                    login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    logout_at TIMESTAMPTZ
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS admin_activity_logs (
                    id BIGSERIAL PRIMARY KEY,
                    admin_id BIGINT REFERENCES admins(id) ON DELETE SET NULL,
                    action TEXT NOT NULL,
                    request_path TEXT,
                    http_method TEXT,
                    details TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            cur.execute("""
                SELECT id
                FROM admins
                WHERE email = %s
            """, (BOOTSTRAP_OWNER_EMAIL,))

            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO admins (
                        email,
                        password_hash,
                        display_name,
                        role,
                        is_active
                    )
                    VALUES (%s, %s, %s, 'owner', TRUE)
                """, (
                    BOOTSTRAP_OWNER_EMAIL,
                    hash_admin_password(BOOTSTRAP_OWNER_PASSWORD),
                    "BoxOfficeX Owner"
                ))

        conn.commit()


@app.post("/admin/login")
def admin_login(
    data: AdminLoginData,
    request: Request
):
    email = (data.email or "").strip().lower()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    email,
                    password_hash,
                    display_name,
                    role,
                    is_active
                FROM admins
                WHERE LOWER(email) = LOWER(%s)
            """, (email,))
            row = cur.fetchone()

            if (
                not row
                or not row[5]
                or not verify_admin_password(data.password, row[2])
            ):
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect email or password"
                )

            now = datetime.now(timezone.utc)

            cur.execute("""
                UPDATE admins
                SET
                    last_login_at = %s,
                    last_activity_at = %s
                WHERE id = %s
            """, (now, now, row[0]))

            cur.execute("""
                INSERT INTO admin_sessions (
                    admin_id,
                    login_at,
                    last_activity_at
                )
                VALUES (%s, %s, %s)
                RETURNING id
            """, (row[0], now, now))

            session_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO admin_activity_logs (
                    admin_id,
                    action,
                    request_path,
                    http_method,
                    details
                )
                VALUES (%s, 'login', '/admin/login', 'POST', 'Login successful')
            """, (row[0],))

        conn.commit()

    request.session.clear()
    request.session["boxofficex_admin"] = True
    request.session["admin_id"] = row[0]
    request.session["admin_email"] = row[1]
    request.session["admin_display_name"] = row[3]
    request.session["admin_role"] = row[4]
    request.session["admin_session_id"] = session_id

    return {
        "success": True,
        "message": "Login successful",
        "admin": {
            "id": row[0],
            "email": row[1],
            "display_name": row[3],
            "role": row[4]
        }
    }


@app.post("/admin/logout")
def admin_logout(request: Request):
    admin = current_admin(request)

    if admin:
        now = datetime.now(timezone.utc)

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE admin_sessions
                    SET
                        last_activity_at = %s,
                        logout_at = %s
                    WHERE id = %s
                      AND admin_id = %s
                      AND logout_at IS NULL
                """, (
                    now,
                    now,
                    admin.get("session_id"),
                    admin["id"]
                ))

                cur.execute("""
                    INSERT INTO admin_activity_logs (
                        admin_id,
                        action,
                        request_path,
                        http_method,
                        details
                    )
                    VALUES (%s, 'logout', '/admin/logout', 'POST', 'Logout successful')
                """, (admin["id"],))

            conn.commit()

    request.session.clear()

    return {
        "success": True,
        "message": "Logged out successfully"
    }


@app.get("/admin/session")
def admin_session(request: Request):
    admin = current_admin(request)

    return {
        "logged_in": bool(admin),
        "admin": admin
    }


@app.put("/admin/change-password", dependencies=[Depends(require_admin)])
def admin_change_own_password(
    data: AdminSelfPasswordChangeData,
    request: Request
):
    admin = current_admin(request)

    if not admin:
        raise HTTPException(
            status_code=401,
            detail="Admin login required"
        )

    if len(data.new_password) < 10:
        raise HTTPException(
            status_code=400,
            detail="New password must be at least 10 characters"
        )

    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different from current password"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT password_hash
                FROM admins
                WHERE id = %s
                  AND is_active = TRUE
            """, (admin["id"],))

            row = cur.fetchone()

            if not row or not verify_admin_password(
                data.current_password,
                row[0]
            ):
                raise HTTPException(
                    status_code=401,
                    detail="Current password is incorrect"
                )

            cur.execute("""
                UPDATE admins
                SET password_hash = %s
                WHERE id = %s
            """, (
                hash_admin_password(data.new_password),
                admin["id"]
            ))

            cur.execute("""
                INSERT INTO admin_activity_logs (
                    admin_id,
                    action,
                    request_path,
                    http_method,
                    details
                )
                VALUES (
                    %s,
                    'password_change',
                    '/admin/change-password',
                    'PUT',
                    'Changed own password'
                )
            """, (admin["id"],))

        conn.commit()

    return {
        "success": True,
        "message": "Password changed successfully"
    }



# ============================================================
# OWNER: ADMIN MANAGEMENT + WORK/AUDIT DATA
# ============================================================

@app.get("/admin/team", dependencies=[Depends(require_owner)])
def owner_list_admins():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id,
                    a.email,
                    a.display_name,
                    a.role,
                    a.is_active,
                    a.created_at,
                    a.last_login_at,
                    a.last_activity_at,
                    COALESCE(COUNT(s.id), 0) AS session_count,
                    COALESCE(
                        SUM(
                            EXTRACT(
                                EPOCH FROM (
                                    COALESCE(s.logout_at, s.last_activity_at)
                                    - s.login_at
                                )
                            )
                        ),
                        0
                    ) AS worked_seconds
                FROM admins a
                LEFT JOIN admin_sessions s
                    ON s.admin_id = a.id
                GROUP BY a.id
                ORDER BY
                    CASE a.role
                        WHEN 'owner' THEN 1
                        WHEN 'editor' THEN 2
                        ELSE 3
                    END,
                    a.email
            """)
            rows = cur.fetchall()

    return {
        "admins": [
            {
                "id": row[0],
                "email": row[1],
                "display_name": row[2],
                "role": row[3],
                "is_active": row[4],
                "created_at": row[5].isoformat() if row[5] else None,
                "last_login_at": row[6].isoformat() if row[6] else None,
                "last_activity_at": row[7].isoformat() if row[7] else None,
                "session_count": row[8],
                "worked_seconds": float(row[9] or 0),
                "worked_hours": round(float(row[9] or 0) / 3600, 2)
            }
            for row in rows
        ]
    }


@app.post("/admin/team", dependencies=[Depends(require_owner)])
def owner_create_admin(
    data: AdminCreateData,
    request: Request
):
    email = (data.email or "").strip().lower()

    if not email.endswith("@boxoffice-x.com"):
        raise HTTPException(
            status_code=400,
            detail="Admin email must use @boxoffice-x.com"
        )

    if len(data.password) < 10:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 10 characters"
        )

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO admins (
                        email,
                        password_hash,
                        display_name,
                        role,
                        is_active
                    )
                    VALUES (%s, %s, %s, %s, TRUE)
                    RETURNING id
                """, (
                    email,
                    hash_admin_password(data.password),
                    data.display_name.strip() or email,
                    data.role
                ))
                admin_id = cur.fetchone()[0]
            conn.commit()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(
            status_code=409,
            detail="An admin with this email already exists"
        )

    return {
        "success": True,
        "admin_id": admin_id,
        "email": email,
        "role": data.role
    }


@app.put("/admin/team/{admin_id}", dependencies=[Depends(require_owner)])
def owner_update_admin(
    admin_id: int,
    data: AdminUpdateData,
    request: Request
):
    owner = current_admin(request)

    if owner and owner["id"] == admin_id and data.is_active is False:
        raise HTTPException(
            status_code=400,
            detail="You cannot disable your own Owner account"
        )

    fields = []
    values = []

    if data.display_name is not None:
        fields.append("display_name = %s")
        values.append(data.display_name.strip())

    if data.role is not None:
        fields.append("role = %s")
        values.append(data.role)

    if data.is_active is not None:
        fields.append("is_active = %s")
        values.append(data.is_active)

    if not fields:
        raise HTTPException(
            status_code=400,
            detail="No admin changes supplied"
        )

    values.append(admin_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                    UPDATE admins
                    SET {", ".join(fields)}
                    WHERE id = %s
                """,
                tuple(values)
            )

            if cur.rowcount == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )
        conn.commit()

    return {"success": True}


@app.put(
    "/admin/team/{admin_id}/password",
    dependencies=[Depends(require_owner)]
)
def owner_reset_admin_password(
    admin_id: int,
    data: AdminPasswordResetData
):
    if len(data.new_password) < 10:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 10 characters"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE admins
                SET password_hash = %s
                WHERE id = %s
            """, (
                hash_admin_password(data.new_password),
                admin_id
            ))

            if cur.rowcount == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )
        conn.commit()

    return {
        "success": True,
        "message": "Admin password reset successfully"
    }


@app.get(
    "/admin/team/activity",
    dependencies=[Depends(require_owner)]
)
def owner_admin_activity(
    admin_id: Optional[int] = None,
    limit: int = 200
):
    limit = max(1, min(limit, 500))

    with get_connection() as conn:
        with conn.cursor() as cur:
            if admin_id:
                cur.execute("""
                    SELECT
                        l.id,
                        l.admin_id,
                        a.email,
                        a.display_name,
                        a.role,
                        l.action,
                        l.request_path,
                        l.http_method,
                        l.details,
                        l.created_at
                    FROM admin_activity_logs l
                    LEFT JOIN admins a ON a.id = l.admin_id
                    WHERE l.admin_id = %s
                    ORDER BY l.created_at DESC
                    LIMIT %s
                """, (admin_id, limit))
            else:
                cur.execute("""
                    SELECT
                        l.id,
                        l.admin_id,
                        a.email,
                        a.display_name,
                        a.role,
                        l.action,
                        l.request_path,
                        l.http_method,
                        l.details,
                        l.created_at
                    FROM admin_activity_logs l
                    LEFT JOIN admins a ON a.id = l.admin_id
                    ORDER BY l.created_at DESC
                    LIMIT %s
                """, (limit,))

            rows = cur.fetchall()

    return {
        "activity": [
            {
                "id": row[0],
                "admin_id": row[1],
                "email": row[2],
                "display_name": row[3],
                "role": row[4],
                "action": row[5],
                "request_path": row[6],
                "http_method": row[7],
                "details": row[8],
                "created_at": row[9].isoformat() if row[9] else None
            }
            for row in rows
        ]
    }



@app.get(
    "/admin/team/work-report",
    dependencies=[Depends(require_owner)]
)
def owner_admin_work_report(
    admin_id: int,
    work_date: date,
    timezone_name: str = "Asia/Kolkata"
):
    try:
        tz = ZoneInfo(timezone_name)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid timezone"
        )

    local_start = datetime.combine(
        work_date,
        time.min,
        tzinfo=tz
    )
    local_end = datetime.combine(
        work_date,
        time.max,
        tzinfo=tz
    )

    start_utc = local_start.astimezone(timezone.utc)
    end_utc = local_end.astimezone(timezone.utc)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    email,
                    display_name,
                    role,
                    is_active
                FROM admins
                WHERE id = %s
            """, (admin_id,))
            admin_row = cur.fetchone()

            if not admin_row:
                raise HTTPException(
                    status_code=404,
                    detail="Admin not found"
                )

            cur.execute("""
                SELECT
                    id,
                    login_at,
                    last_activity_at,
                    logout_at
                FROM admin_sessions
                WHERE admin_id = %s
                  AND login_at <= %s
                  AND COALESCE(logout_at, last_activity_at) >= %s
                ORDER BY login_at ASC
            """, (
                admin_id,
                end_utc,
                start_utc
            ))

            rows = cur.fetchall()

    sessions = []
    total_seconds = 0.0
    first_login = None
    last_logout = None

    for row in rows:
        session_id = row[0]
        login_at = row[1]
        last_activity_at = row[2]
        logout_at = row[3]

        effective_end = logout_at or last_activity_at

        clipped_start = max(login_at, start_utc)
        clipped_end = min(effective_end, end_utc)

        seconds = max(
            0.0,
            (clipped_end - clipped_start).total_seconds()
        )

        if seconds <= 0:
            continue

        total_seconds += seconds

        login_local = login_at.astimezone(tz)
        activity_local = last_activity_at.astimezone(tz)
        logout_local = logout_at.astimezone(tz) if logout_at else None

        if first_login is None or login_local < first_login:
            first_login = login_local

        if logout_local and (
            last_logout is None or logout_local > last_logout
        ):
            last_logout = logout_local

        sessions.append({
            "session_id": session_id,
            "login_at": login_local.isoformat(),
            "last_activity_at": activity_local.isoformat(),
            "logout_at": logout_local.isoformat() if logout_local else None,
            "worked_seconds": round(seconds, 2),
            "worked_hours": round(seconds / 3600, 2),
            "status": "logged_out" if logout_at else "open_or_no_logout",
        })

    return {
        "admin": {
            "id": admin_row[0],
            "email": admin_row[1],
            "display_name": admin_row[2],
            "role": admin_row[3],
            "is_active": admin_row[4],
        },
        "work_date": work_date.isoformat(),
        "timezone": timezone_name,
        "summary": {
            "session_count": len(sessions),
            "total_worked_seconds": round(total_seconds, 2),
            "total_worked_hours": round(total_seconds / 3600, 2),
            "first_login_at": first_login.isoformat() if first_login else None,
            "last_logout_at": last_logout.isoformat() if last_logout else None,
        },
        "sessions": sessions,
    }


@app.get(
    "/admin/team/sessions",
    dependencies=[Depends(require_owner)]
)
def owner_admin_sessions(
    admin_id: Optional[int] = None,
    limit: int = 200
):
    limit = max(1, min(limit, 500))

    with get_connection() as conn:
        with conn.cursor() as cur:
            params = []
            where = ""

            if admin_id:
                where = "WHERE s.admin_id = %s"
                params.append(admin_id)

            params.append(limit)

            cur.execute(f"""
                SELECT
                    s.id,
                    s.admin_id,
                    a.email,
                    a.display_name,
                    a.role,
                    s.login_at,
                    s.last_activity_at,
                    s.logout_at,
                    EXTRACT(
                        EPOCH FROM (
                            COALESCE(s.logout_at, s.last_activity_at)
                            - s.login_at
                        )
                    ) AS worked_seconds
                FROM admin_sessions s
                JOIN admins a ON a.id = s.admin_id
                {where}
                ORDER BY s.login_at DESC
                LIMIT %s
            """, tuple(params))

            rows = cur.fetchall()

    return {
        "sessions": [
            {
                "id": row[0],
                "admin_id": row[1],
                "email": row[2],
                "display_name": row[3],
                "role": row[4],
                "login_at": row[5].isoformat() if row[5] else None,
                "last_activity_at": row[6].isoformat() if row[6] else None,
                "logout_at": row[7].isoformat() if row[7] else None,
                "worked_seconds": float(row[8] or 0),
                "worked_hours": round(float(row[8] or 0) / 3600, 2)
            }
            for row in rows
        ]
    }


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# STATIC FILES
# ============================================================

app.mount(
    "/posters",
    StaticFiles(directory=POSTERS_DIR),
    name="posters"
)

app.mount(
    "/actor-images",
    StaticFiles(directory=ACTORS_DIR),
    name="actor-images"
)

app.mount(
    "/article-images",
    StaticFiles(directory=ARTICLE_IMAGES_DIR),
    name="article-images"
)



# ============================================================
# ADMIN MOVIE / ACTOR IMAGE UPLOADS
# ============================================================

def _safe_uploaded_image_name(
    original_name: str,
    default_stem: str,
    extension: str
):
    stem = Path(original_name or default_stem).stem
    stem = re.sub(
        r"[^a-zA-Z0-9_-]+",
        "-",
        stem
    ).strip("-").lower()

    if not stem:
        stem = default_stem

    return (
        f"{stem}-"
        f"{secrets.token_hex(4)}"
        f"{extension}"
    )


async def _save_admin_image(
    file: UploadFile,
    destination_dir: Path,
    default_stem: str
):
    allowed_types = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Only JPG, PNG and WEBP images are allowed"
        )

    raw = await file.read()

    if not raw:
        raise HTTPException(
            status_code=400,
            detail="Uploaded image is empty"
        )

    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Image must be 8 MB or smaller"
        )

    extension = allowed_types[file.content_type]

    filename = _safe_uploaded_image_name(
        file.filename or default_stem,
        default_stem,
        extension
    )

    destination_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    destination = destination_dir / filename
    destination.write_bytes(raw)

    if not destination.is_file():
        raise HTTPException(
            status_code=500,
            detail="Image could not be saved"
        )

    return filename


@app.post(
    "/admin/upload/movie-poster",
    dependencies=[Depends(require_admin)]
)
async def admin_upload_movie_poster(
    file: UploadFile = File(...)
):
    filename = await _save_admin_image(
        file,
        POSTERS_DIR,
        "movie-poster"
    )

    return {
        "success": True,
        "filename": filename,
        "url": f"/posters/{filename}",
    }


@app.post(
    "/admin/upload/actor-photo",
    dependencies=[Depends(require_admin)]
)
async def admin_upload_actor_photo(
    file: UploadFile = File(...)
):
    filename = await _save_admin_image(
        file,
        ACTORS_DIR,
        "actor-photo"
    )

    return {
        "success": True,
        "filename": filename,
        "url": f"/actor-images/{filename}",
    }


# ============================================================
# DATABASE CONNECTION
# ============================================================

LOCAL_DATABASE_URL = os.getenv(
    "BOXOFFICEX_LOCAL_DATABASE_URL",
    "postgresql://postgres:5432@localhost/boxofficex"
)

DATABASE_URL = os.getenv("DATABASE_URL", LOCAL_DATABASE_URL)


def get_connection():
    """
    Use Render/production DATABASE_URL when available.
    Falls back to the existing local PostgreSQL database on this laptop.
    """
    return psycopg.connect(DATABASE_URL)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "BoxOfficeX API is working!"
    }




# ============================================================
# SEO FILES
# ============================================================

@app.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    """
    Dynamic BoxOfficeX sitemap.

    Includes:
    - Main public/static pages
    - Every movie from PostgreSQL
    - Every actor from PostgreSQL
    - Published articles only

    Draft/archived articles and admin/API pages are excluded.
    """

    site_url = "https://boxoffice-x.com"

    static_pages = [
        ("/", "daily", "1.0"),
        ("/new-movies.html", "daily", "0.9"),
        ("/movie-rankings.html", "daily", "0.9"),
        ("/actors.html", "weekly", "0.8"),
        ("/articles.html", "daily", "0.9"),
        ("/compare-select.html", "weekly", "0.7"),
        ("/movie-compare-select.html", "weekly", "0.7"),
        ("/about.html", "monthly", "0.5"),
        ("/contact.html", "monthly", "0.5"),
        ("/privacy.html", "yearly", "0.3"),
        ("/terms.html", "yearly", "0.3"),
        ("/disclaimer.html", "yearly", "0.3"),
    ]

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT id, release_date
                FROM movies
                ORDER BY id
            """)
            movie_rows = cur.fetchall()

            cur.execute("""
                SELECT id
                FROM actors
                ORDER BY id
            """)
            actor_rows = cur.fetchall()

            cur.execute("""
                SELECT
                    slug,
                    COALESCE(updated_at, published_at, created_at)
                FROM articles
                WHERE status = 'published'
                  AND slug IS NOT NULL
                  AND TRIM(slug) <> ''
                ORDER BY id
            """)
            article_rows = cur.fetchall()

    urls = []

    def add_url(path, changefreq=None, priority=None, lastmod=None):
        loc = xml_escape(site_url + path)

        parts = [
            "  <url>",
            f"    <loc>{loc}</loc>",
        ]

        if lastmod:
            if hasattr(lastmod, "date"):
                lastmod_value = lastmod.date().isoformat()
            else:
                lastmod_value = str(lastmod)[:10]

            parts.append(
                f"    <lastmod>{xml_escape(lastmod_value)}</lastmod>"
            )

        if changefreq:
            parts.append(
                f"    <changefreq>{changefreq}</changefreq>"
            )

        if priority:
            parts.append(
                f"    <priority>{priority}</priority>"
            )

        parts.append("  </url>")
        urls.append("\n".join(parts))

    for path, changefreq, priority in static_pages:
        add_url(
            path,
            changefreq=changefreq,
            priority=priority
        )

    for movie_id, release_date in movie_rows:
        add_url(
            f"/movie.html?id={movie_id}",
            changefreq="weekly",
            priority="0.8",
            lastmod=release_date
        )

    for (actor_id,) in actor_rows:
        add_url(
            f"/actor.html?id={actor_id}",
            changefreq="weekly",
            priority="0.7"
        )

    for slug, last_modified in article_rows:
        add_url(
            f"/article/{slug}",
            changefreq="monthly",
            priority="0.8",
            lastmod=last_modified
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    return Response(
        content=xml,
        media_type="application/xml"
    )

@app.get("/robots.txt", include_in_schema=False)
def robots_txt():
    robots_file = BASE_DIR / "robots.txt"

    if not robots_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="robots.txt not found"
        )

    return FileResponse(
        robots_file,
        media_type="text/plain"
    )


# ============================================================
# HTML PAGES
# ============================================================

@app.get("/index.html")
def index_page():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/movie.html")
def movie_page():
    return FileResponse(BASE_DIR / "movie.html")


@app.get("/movie-rankings.html")
def movie_rankings_page():
    return FileResponse(BASE_DIR / "movie-rankings.html")


@app.get("/actor-movies.html")
def actor_movies_page():
    return FileResponse(BASE_DIR / "actor-movies.html")


@app.get("/actor.html")
def actor_page():
    return FileResponse(BASE_DIR / "actor.html")


@app.get("/actors.html")
def actors_page():
    return FileResponse(BASE_DIR / "actors.html")


@app.get("/compare-select.html")
def compare_select_page():
    return FileResponse(BASE_DIR / "compare-select.html")


@app.get("/compare.html")
def compare_page():
    return FileResponse(BASE_DIR / "compare.html")




@app.get("/admin-login.html")
def admin_login_page():
    return FileResponse(
        BASE_DIR / "admin-login.html"
    )


@app.get("/admin.html", dependencies=[Depends(require_admin)])
def admin_page():
    return FileResponse(BASE_DIR / "admin.html")


@app.get("/admin-team.html", dependencies=[Depends(require_owner)])
def admin_team_page():
    return FileResponse(BASE_DIR / "admin-team.html")

@app.get("/new-movies.html")
def new_movies_page():
    return FileResponse(BASE_DIR / "new-movies.html")


@app.get("/rankings.html")
def rankings_page():
    return FileResponse(BASE_DIR / "rankings.html")


@app.get("/disclaimer.html")
def disclaimer_page():
    return FileResponse(
        BASE_DIR / "disclaimer.html"
    )


@app.get("/privacy.html")
def privacy_page():

    return FileResponse(
        BASE_DIR / "privacy.html"
    )


@app.get("/terms.html")
def terms_page():

    return FileResponse(
        BASE_DIR / "terms.html"
    )

@app.get("/about.html")
def about_page():

    return FileResponse(
        BASE_DIR / "about.html"
    )

@app.get("/contact.html")
def contact_page():

    return FileResponse(
        BASE_DIR / "contact.html"
    )




# ============================================================
# MOVIES
# ============================================================

@app.get("/movies")
def get_movies():

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    worldwide_collection_crore,
                    verdict,
                    director,
                    poster
                FROM movies
                ORDER BY id;
            """)

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]),
            "language": row[3],
            "worldwide_collection_crore": float(row[4]) if row[4] is not None else None,
            "verdict": row[5],
            "director": row[6],
            "poster": safe_movie_poster(row[7])
        })

    return {
        "movies": movies
    }



# ============================================================
# ADD NEW MOVIE
# ============================================================

from fastapi import HTTPException
from pydantic import BaseModel


class MovieCreate(BaseModel):

    title: str
    language: str
    industry: str
    release_date: str
    genre: str
    budget_crore: float
    india_collection_crore: float = 0
    overseas_collection_crore: float = 0
    worldwide_collection_crore: float = 0
    verdict: str
    director: str
    poster: str


@app.post("/movies", dependencies=[Depends(require_admin)])
def add_movie(movie: MovieCreate):

    try:

        with get_connection() as conn:

            with conn.cursor() as cur:

                cur.execute("""
                    INSERT INTO movies (
                        title,
                        language,
                        industry,
                        release_date,
                        genre,
                        budget_crore,
                        india_collection_crore,
                        overseas_collection_crore,
                        worldwide_collection_crore,
                        verdict,
                        director,
                        poster
                    )

                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )

                    RETURNING id;
                """, (
                    movie.title,
                    movie.language,
                    movie.industry,
                    movie.release_date,
                    movie.genre,
                    movie.budget_crore,
                    movie.india_collection_crore,
                    movie.overseas_collection_crore,
                    movie.worldwide_collection_crore,
                    movie.verdict,
                    movie.director,
                    movie.poster
                ))

                movie_id = cur.fetchone()[0]

            conn.commit()

        return {
            "success": True,
            "message": "Movie added successfully",
            "movie_id": movie_id,
            "movie_url": f"/movie.html?id={movie_id}"
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# ============================================================
# TOP 10 MOVIES
# ============================================================

@app.get("/movies/top10")
def top10_movies():

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    language,
                    industry,
                    release_date,
                    worldwide_collection_crore,
                    verdict,
                    poster
                FROM movies
                ORDER BY worldwide_collection_crore DESC
                LIMIT 10;
            """)

            rows = cur.fetchall()

    movies = []

    for position, row in enumerate(rows, start=1):

        movies.append({
            "rank": position,
            "id": row[0],
            "title": row[1],
            "language": row[2],
            "industry": row[3],
            "release_date": str(row[4]),
            "worldwide_collection": float(row[5] or 0),
            "verdict": row[6],
            "poster": safe_movie_poster(row[7])
        })

    return {
        "movies": movies
    }


# ============================================================
# TOP 10 INDIAN MOVIES
# ============================================================

@app.get("/movies/top10-indian")
def top10_indian_movies():

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    language,
                    industry,
                    release_date,
                    worldwide_collection_crore,
                    verdict,
                    poster
                FROM movies
                WHERE industry IN (
                    'Kollywood',
                    'Tollywood',
                    'Bollywood',
                    'Sandalwood',
                    'Mollywood'
                )
                ORDER BY worldwide_collection_crore DESC
                LIMIT 10;
            """)

            rows = cur.fetchall()

    movies = []

    for position, row in enumerate(rows, start=1):

        movies.append({
            "rank": position,
            "id": row[0],
            "title": row[1],
            "language": row[2],
            "industry": row[3],
            "release_date": str(row[4]),
            "worldwide_collection": float(row[5]),
            "verdict": row[6],
            "poster": safe_movie_poster(row[7])
        })

    return {
        "movies": movies
    }



@app.get("/movies/new")
def get_new_movies():

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    genre,
                    worldwide_collection_crore,
                    verdict,
                    director,
                    poster
                FROM movies
                WHERE release_date IS NOT NULL
                ORDER BY release_date DESC
                LIMIT 30
            """)

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]),
            "language": row[3],
            "genre": row[4],
            "worldwide_collection_crore": float(row[5] or 0),
            "verdict": row[6],
            "director": row[7],
            "poster": safe_movie_poster(row[8])
        })

    return {
        "movies": movies
    }


# ============================================================
# SINGLE MOVIE
# THIS MUST COME AFTER /movies/new
# ============================================================



# ============================================================
# LATEST MOVIES
# IMPORTANT: KEEP THIS BEFORE /movies/{movie_id}
# ============================================================

@app.get("/movies/latest")
def get_latest_movies():

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    genre,
                    director,
                    budget_crore,
                    india_collection_crore,
                    overseas_collection_crore,
                    worldwide_collection_crore,
                    verdict,
                    poster
                FROM movies
                WHERE release_date IS NOT NULL
                ORDER BY release_date DESC
                LIMIT 12;
            """)

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "language": row[3],
            "genre": row[4],
            "director": row[5],
            "budget_crore": float(row[6] or 0),
            "india_collection_crore": float(row[7] or 0),
            "overseas_collection_crore": float(row[8] or 0),
            "worldwide_collection_crore": float(row[9] or 0),
            "verdict": row[10],
            "poster": safe_movie_poster(row[11])
        })

    return {
        "movies": movies
    }


# ============================================================
# BOXOFFICEX NEW MOVIE SYSTEM
# Running / Upcoming / Recently Released
# ============================================================

@app.get("/movies/new-system")
def get_new_movie_system():

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    genre,
                    director,
                    india_collection_crore,
                    overseas_collection_crore,
                    worldwide_collection_crore,
                    verdict,
                    poster,
                    COALESCE(boxoffice_status, 'final') AS boxoffice_status
                FROM movies
                WHERE release_date IS NOT NULL
                ORDER BY release_date DESC;
            """)

            rows = cur.fetchall()

    today = date.today()

    running = []
    upcoming = []
    recent = []

    def movie_dict(row):
        release_date = row[2]

        return {
            "id": row[0],
            "title": row[1],
            "release_date": str(release_date) if release_date else None,
            "language": row[3],
            "genre": row[4],
            "director": row[5],
            "india_collection_crore": float(row[6]) if row[6] is not None else None,
            "overseas_collection_crore": float(row[7]) if row[7] is not None else None,
            "worldwide_collection_crore": float(row[8]) if row[8] is not None else None,
            "verdict": row[9],
            "poster": safe_movie_poster(row[10]),
            "boxoffice_status": row[11],
        }

    for row in rows:

        release_date = row[2]
        status = (row[11] or "final").lower()
        movie = movie_dict(row)

        if release_date and release_date > today:
            movie["boxoffice_status"] = "upcoming"
            upcoming.append(movie)

        elif status == "running":
            running.append(movie)

        elif release_date and (today - release_date).days <= 90:
            recent.append(movie)

    upcoming.sort(key=lambda m: m["release_date"] or "")
    running.sort(key=lambda m: m["release_date"] or "", reverse=True)
    recent.sort(key=lambda m: m["release_date"] or "", reverse=True)

    return {
        "running": running,
        "upcoming": upcoming[:30],
        "recent": recent[:30],
    }


class MovieBoxOfficeStatusUpdate(BaseModel):
    status: str


@app.put(
    "/admin/movies/{movie_id}/boxoffice-status",
    dependencies=[Depends(require_admin)]
)
def admin_update_movie_boxoffice_status(
    movie_id: int,
    data: MovieBoxOfficeStatusUpdate
):

    status = (data.status or "").strip().lower()

    if status not in {"running", "final", "upcoming"}:
        raise HTTPException(
            status_code=400,
            detail="Status must be running, final or upcoming"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT id
                FROM movies
                WHERE id = %s
            """, (movie_id,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Movie not found"
                )

        # Before locking a movie as Final, capture the latest
        # accumulated regional totals one last time.
        if status == "final":
            sync_running_movie_totals(
                conn,
                movie_id,
                force=True
            )

        with conn.cursor() as cur:

            cur.execute("""
                UPDATE movies
                SET boxoffice_status = %s
                WHERE id = %s
            """, (status, movie_id))

        # If an existing movie is switched to Running, immediately
        # rebuild its headline totals from any saved regional data.
        if status == "running":
            sync_running_movie_totals(
                conn,
                movie_id
            )

        conn.commit()

    return {
        "success": True,
        "movie_id": movie_id,
        "boxoffice_status": status,
    }


@app.get("/movies/{movie_id}")
def get_movie(movie_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    genre,
                    budget_crore,
                    india_collection_crore,
                    overseas_collection_crore,
                    worldwide_collection_crore,
                    verdict,
                    director,
                    poster
                FROM movies
                WHERE id = %s;
            """, (movie_id,))

            row = cur.fetchone()

    if row is None:
        return {
            "error": "Movie not found"
        }

    return {
        "id": row[0],
        "title": row[1],
        "release_date": str(row[2]),
        "language": row[3],
        "genre": row[4],
        "budget_crore": float(row[5]) if row[5] is not None else None,
        "india_collection_crore": float(row[6]) if row[6] is not None else None,
        "overseas_collection_crore": float(row[7]) if row[7] is not None else None,
        "worldwide_collection_crore": float(row[8]) if row[8] is not None else None,
        "verdict": row[9],
        "director": row[10],
        "poster": safe_movie_poster(row[11])
    }


# ============================================================
# SINGLE MOVIE
# ============================================================





@app.get("/movies/{movie_id}")



@app.get("/movies/new")




@app.get("/movies/{movie_id}/daily-collections")
def get_daily_collections(movie_id: int):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    collection_date,
                    collection_crore
                FROM movie_daily_collections
                WHERE movie_id = %s
                  AND state IS NULL
                ORDER BY collection_date
            """, (movie_id,))

            rows = cur.fetchall()

    collections = []

    for row in rows:

        collections.append({
            "date": str(row[0]),
            "collection_crore": float(row[1] or 0)
        })

    return {
        "movie_id": movie_id,
        "collections": collections
    }

@app.get("/movies/{movie_id}/state-collections")
def get_state_collections(movie_id: int):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    state,
                    SUM(collection_crore) AS total_collection
                FROM movie_daily_collections
                WHERE movie_id = %s
                  AND state IS NOT NULL
                GROUP BY state
                ORDER BY total_collection DESC
            """, (movie_id,))

            rows = cur.fetchall()

    collections = []

    for row in rows:

        collections.append({
            "state": row[0],
            "collection_crore": float(row[1] or 0)
        })

    return {
        "movie_id": movie_id,
        "collections": collections
    }


    




# ============================================================
# MOVIE DAY + STATE BREAKDOWN
# Raw records used by movie.html for Day 1-7 state breakdown
# ============================================================

@app.get("/movies/{movie_id}/collection-breakdown")
def get_movie_collection_breakdown(movie_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    collection_date,
                    state,
                    collection_crore
                FROM movie_daily_collections
                WHERE movie_id = %s
                ORDER BY
                    collection_date ASC,
                    CASE
                        WHEN state IS NULL THEN 999
                        WHEN state = 'Tamil Nadu' THEN 1
                        WHEN state = 'Kerala' THEN 2
                        WHEN state = 'Karnataka' THEN 3
                        WHEN state = 'Andhra Pradesh' THEN 4
                        WHEN state = 'Telangana' THEN 5
                        WHEN state = 'Maharashtra' THEN 6
                        WHEN state = 'West Bengal' THEN 7
                        WHEN state = 'Delhi' THEN 8
                        WHEN state = 'Rest of India' THEN 9
                        ELSE 50
                    END,
                    state ASC;
            """, (movie_id,))

            rows = cur.fetchall()

    records = []

    for row in rows:
        records.append({
            "date": str(row[0]),
            "state": row[1],
            "collection_crore": float(row[2] or 0)
        })

    return {
        "movie_id": movie_id,
        "records": records
    }


# ============================================================
# ACTORS
# ============================================================





@app.get("/actors")
def get_actors():

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    name,
                    profession,
                    photo,
                    bio
                FROM actors
                ORDER BY id;
            """)

            rows = cur.fetchall()

    actors = []

    for row in rows:

        actors.append({
            "id": row[0],
            "name": row[1],
            "profession": row[2],
            "photo": safe_actor_photo(row[3]),
            "bio": row[4]
        })

    return {
        "actors": actors
    }


# ============================================================
# ACTOR SEARCH
# IMPORTANT: THIS MUST COME BEFORE /actors/{actor_id}
# ============================================================

@app.get("/actors/search")
def search_actors(q: str):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    name,
                    profession,
                    photo
                FROM actors
                WHERE name ILIKE %s
                ORDER BY name;
            """, (f"%{q}%",))

            rows = cur.fetchall()

    actors = []

    for row in rows:

        actors.append({
            "id": row[0],
            "name": row[1],
            "profession": row[2],
            "photo": safe_actor_photo(row[3])
        })

    return {
        "actors": actors
    }


# ============================================================
# SINGLE ACTOR
# ============================================================

@app.get("/actors/{actor_id}")
def get_actor(actor_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    name,
                    profession,
                    photo,
                    bio
                FROM actors
                WHERE id = %s;
            """, (actor_id,))

            row = cur.fetchone()

    if not row:
        return {
            "error": "Actor not found"
        }

    return {
        "id": row[0],
        "name": row[1],
        "profession": row[2],
        "photo": safe_actor_photo(row[3]),
        "bio": row[4]
    }


# ============================================================
# ACTOR MOVIES
# ============================================================

@app.get("/actors/{actor_id}/movies")
def get_actor_movies(actor_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    movies.id,
                    movies.title,
                    movies.poster,
                    movies.release_date,
                    movies.worldwide_collection_crore,
                    movies.verdict
                FROM actor_movies
                JOIN movies
                    ON actor_movies.movie_id = movies.id
                WHERE actor_movies.actor_id = %s
                ORDER BY movies.release_date DESC;
            """, (actor_id,))

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "poster": safe_movie_poster(row[2]),
            "release_date": str(row[3]),
            "worldwide_collection_crore": float(row[4]) if row[4] is not None else None,
            "verdict": row[5]
        })

    return {
        "movies": movies
    }


# ============================================================
# ACTOR MOVIES BY VERDICT
# ============================================================

@app.get("/actors/{actor_id}/movies/verdict/{verdict}")
def get_actor_movies_by_verdict(
    actor_id: int,
    verdict: str
):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    movies.id,
                    movies.title,
                    movies.poster,
                    movies.release_date,
                    movies.worldwide_collection_crore,
                    movies.verdict
                FROM actor_movies
                JOIN movies
                    ON actor_movies.movie_id = movies.id
                WHERE actor_movies.actor_id = %s
                AND LOWER(movies.verdict) = LOWER(%s)
                ORDER BY movies.release_date DESC;
            """, (actor_id, verdict))

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "poster": safe_movie_poster(row[2]),
            "release_date": str(row[3]),
            "worldwide_collection_crore": float(row[4]) if row[4] is not None else None,
            "verdict": row[5]
        })

    return {
        "movies": movies
    }


# ============================================================
# ACTOR STATS
# ============================================================

@app.get("/actors/{actor_id}/stats")
def get_actor_stats(actor_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    COUNT(m.id),
                    COALESCE(SUM(m.worldwide_collection_crore), 0),
                    COALESCE(AVG(m.worldwide_collection_crore), 0),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Blockbuster'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Hit'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Average'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Flop'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    )

                FROM actor_movies am

                JOIN movies m
                    ON am.movie_id = m.id

                WHERE am.actor_id = %s;
            """, (actor_id,))

            row = cur.fetchone()

    return {
        "movie_count": row[0],
        "total_worldwide": float(row[1]),
        "average_worldwide": float(row[2]),
        "blockbusters": row[3],
        "hits": row[4],
        "average_movies": row[5],
        "flops": row[6]
    }


# ============================================================
# ACTOR HIGHEST GROSSING
# ============================================================

@app.get("/actors/{actor_id}/highest-grossing")
def get_actor_highest_grossing(actor_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    m.id,
                    m.title,
                    m.poster,
                    m.worldwide_collection_crore,
                    m.verdict

                FROM actor_movies am

                JOIN movies m
                    ON am.movie_id = m.id

                WHERE am.actor_id = %s

                ORDER BY m.worldwide_collection_crore DESC NULLS LAST

                LIMIT 1;
            """, (actor_id,))

            row = cur.fetchone()

    if not row:
        return {
            "movie": None
        }

    return {
        "movie": {
            "id": row[0],
            "title": row[1],
            "poster": safe_movie_poster(row[2]),
            "worldwide_collection_crore": float(row[3]) if row[3] is not None else None,
            "verdict": row[4]
        }
    }


# ============================================================
# ACTOR COMPARISON
# ============================================================

@app.get("/compare/actors/{actor1_id}/{actor2_id}")
def compare_actors(
    actor1_id: int,
    actor2_id: int
):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    a.id,
                    a.name,
                    a.photo,

                    COUNT(DISTINCT m.id) AS movie_count,

                    COALESCE(
                        SUM(m.worldwide_collection_crore),
                        0
                    ) AS total_worldwide,

                    COALESCE(
                        AVG(m.worldwide_collection_crore),
                        0
                    ) AS average_worldwide,

                    COUNT(
                        DISTINCT CASE
                            WHEN m.verdict = 'Blockbuster'
                            THEN m.id
                        END
                    ) AS blockbusters,

                    COUNT(
                        DISTINCT CASE
                            WHEN m.verdict = 'Hit'
                            THEN m.id
                        END
                    ) AS hits,

                    COUNT(
                        DISTINCT CASE
                            WHEN m.verdict = 'Average'
                            THEN m.id
                        END
                    ) AS average_movies,

                    COUNT(
                        DISTINCT CASE
                            WHEN m.verdict = 'Flop'
                            THEN m.id
                        END
                    ) AS flops

                FROM actors a

                LEFT JOIN actor_movies am
                    ON a.id = am.actor_id

                LEFT JOIN movies m
                    ON am.movie_id = m.id

                WHERE a.id IN (%s, %s)

                GROUP BY
                    a.id,
                    a.name,
                    a.photo

                ORDER BY a.id;
            """, (actor1_id, actor2_id))

            rows = cur.fetchall()

    result = []

    for row in rows:

        result.append({
            "id": row[0],
            "name": row[1],
            "photo": safe_actor_photo(row[2]),
            "movie_count": row[3],
            "total_worldwide": float(row[4]),
            "average_worldwide": float(row[5]),
            "blockbusters": row[6],
            "hits": row[7],
            "average_movies": row[8],
            "flops": row[9]
        })

    return {
        "comparison": result
    }


# ============================================================
# ACTOR OVERVIEW
# ============================================================

@app.get("/actors/{actor_id}/overview")
def get_actor_overview(actor_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    COUNT(m.id),

                    COALESCE(
                        SUM(m.worldwide_collection_crore),
                        0
                    ),

                    COALESCE(
                        MAX(m.worldwide_collection_crore),
                        0
                    ),

                    (
                        SELECT m2.title

                        FROM actor_movies am2

                        JOIN movies m2
                            ON am2.movie_id = m2.id

                        WHERE am2.actor_id = %s

                        ORDER BY
                            m2.worldwide_collection_crore DESC NULLS LAST

                        LIMIT 1
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Blockbuster'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Hit'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Average'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    ),

                    COALESCE(
                        SUM(
                            CASE
                                WHEN m.verdict = 'Flop'
                                THEN 1
                                ELSE 0
                            END
                        ),
                        0
                    )

                FROM actor_movies am

                JOIN movies m
                    ON am.movie_id = m.id

                WHERE am.actor_id = %s;
            """, (actor_id, actor_id))

            row = cur.fetchone()

    return {
        "movie_count": row[0],
        "total_worldwide": float(row[1]),
        "highest_worldwide": float(row[2]),
        "highest_movie": row[3],
        "blockbusters": row[4],
        "hits": row[5],
        "average_movies": row[6],
        "flops": row[7]
    }


# ============================================================
# ACTOR TOP 5 MOVIES
# ============================================================

@app.get("/actors/{actor_id}/top-movies")
def get_actor_top_movies(actor_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    m.id,
                    m.title,
                    m.poster,
                    m.release_date,
                    m.worldwide_collection_crore,
                    m.verdict

                FROM actor_movies am

                JOIN movies m
                    ON am.movie_id = m.id

                WHERE am.actor_id = %s

                ORDER BY
                    m.worldwide_collection_crore DESC NULLS LAST

                LIMIT 5;
            """, (actor_id,))

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "poster": safe_movie_poster(row[2]),
            "release_date": str(row[3]),
            "worldwide_collection": float(row[4]) if row[4] is not None else None,
            "verdict": row[5]
        })

    return {
        "movies": movies
    }


# ============================================================
# ACTOR RANKINGS
# ============================================================

@app.get("/rankings/actors")
def actor_rankings(language: str = "All"):

    with get_connection() as conn:
        with conn.cursor() as cur:

            if language.lower() == "all":

                cur.execute("""
                    SELECT
                        a.id,
                        a.name,
                        a.photo,

                        COUNT(DISTINCT m.id)
                            AS movie_count,

                        COALESCE(
                            SUM(m.worldwide_collection_crore),
                            0
                        )
                            AS total_worldwide,

                        COALESCE(
                            AVG(m.worldwide_collection_crore),
                            0
                        )
                            AS average_worldwide,

                        COUNT(
                            DISTINCT CASE
                                WHEN m.verdict = 'Blockbuster'
                                THEN m.id
                            END
                        )
                            AS blockbusters

                    FROM actors a

                    JOIN actor_movies am
                        ON a.id = am.actor_id

                    JOIN movies m
                        ON am.movie_id = m.id

                    GROUP BY
                        a.id,
                        a.name,
                        a.photo

                    ORDER BY
                        total_worldwide DESC

                    LIMIT 100;
                """)

            else:

                cur.execute("""
                    SELECT
                        a.id,
                        a.name,
                        a.photo,

                        COUNT(DISTINCT m.id)
                            AS movie_count,

                        COALESCE(
                            SUM(m.worldwide_collection_crore),
                            0
                        )
                            AS total_worldwide,

                        COALESCE(
                            AVG(m.worldwide_collection_crore),
                            0
                        )
                            AS average_worldwide,

                        COUNT(
                            DISTINCT CASE
                                WHEN m.verdict = 'Blockbuster'
                                THEN m.id
                            END
                        )
                            AS blockbusters

                    FROM actors a

                    JOIN actor_movies am
                        ON a.id = am.actor_id

                    JOIN movies m
                        ON am.movie_id = m.id

                    WHERE LOWER(m.language) = LOWER(%s)

                    GROUP BY
                        a.id,
                        a.name,
                        a.photo

                    ORDER BY
                        total_worldwide DESC

                    LIMIT 100;
                """, (language,))

            rows = cur.fetchall()

    rankings = []

    for position, row in enumerate(rows, start=1):

        rankings.append({
            "rank": position,
            "id": row[0],
            "name": row[1],
            "photo": safe_actor_photo(row[2]),
            "movie_count": row[3],
            "total_worldwide": float(row[4]),
            "average_worldwide": float(row[5]),
            "blockbusters": row[6]
        })

    return {
        "language": language,
        "rankings": rankings
    }


# ============================================================
# MOVIE RANKINGS
# ============================================================

# ============================================================
# MOVIE RANKINGS
# ============================================================

@app.get("/rankings/movies")
def movie_rankings(industry: str = "All"):

    with get_connection() as conn:

        with conn.cursor() as cur:

            # ==========================================
            # GLOBAL RANKINGS
            # ==========================================

            if industry.lower() == "all":

                cur.execute("""
                    SELECT
                        id,
                        title,
                        language,
                        industry,
                        release_date,
                        worldwide_collection_crore,
                        verdict,
                        poster
                    FROM movies
                    WHERE worldwide_collection_crore IS NOT NULL
                      AND worldwide_collection_crore > 0
                    ORDER BY
                        worldwide_collection_crore DESC
                    LIMIT 100;
                """)

            # ==========================================
            # INDUSTRY RANKINGS
            # ==========================================

            else:

                cur.execute("""
                    SELECT
                        id,
                        title,
                        language,
                        industry,
                        release_date,
                        worldwide_collection_crore,
                        verdict,
                        poster
                    FROM movies
                    WHERE LOWER(industry) = LOWER(%s)
                      AND worldwide_collection_crore IS NOT NULL
                      AND worldwide_collection_crore > 0
                    ORDER BY
                        worldwide_collection_crore DESC
                    LIMIT 100;
                """, (industry,))

            rows = cur.fetchall()


    rankings = []

    for position, row in enumerate(rows, start=1):

        rankings.append({

            "rank": position,

            "id": row[0],

            "title": row[1],

            "language": row[2],

            "industry": row[3],

            "release_date":
                str(row[4])
                if row[4]
                else None,

            "worldwide_collection":
                float(row[5] or 0),

            "verdict":
                row[6],

            "poster":
                safe_movie_poster(row[7])

        })


    return {

        "industry": industry,

        "rankings": rankings

    }


@app.get("/movies/{movie_id}/daily-collections")


@app.get("/movies/{movie_id}/state-collections")


@app.get("/movies/new")



# ============================================================
# ADD NEW MOVIE
# ============================================================

@app.post("/movies", dependencies=[Depends(require_admin)])


@app.get("/admin/movies", dependencies=[Depends(require_admin)])
def admin_get_movies():

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    industry,
                    genre,
                    director,
                    budget_crore,
                    india_collection_crore,
                    overseas_collection_crore,
                    worldwide_collection_crore,
                    verdict,
                    poster
                FROM movies
                ORDER BY release_date DESC NULLS LAST, title
            """)

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "language": row[3],
            "industry": row[4],
            "genre": row[5],
            "director": row[6],
            "budget_crore": float(row[7] or 0),
            "india_collection_crore": float(row[8] or 0),
            "overseas_collection_crore": float(row[9] or 0),
            "worldwide_collection_crore": float(row[10] or 0),
            "verdict": row[11],
            "poster": safe_movie_poster(row[12])
        })

    return {
        "movies": movies
    }



from pydantic import BaseModel
from typing import Optional
from datetime import date



# ============================================================
# RUNNING MOVIE LIVE TOTAL SYNCHRONIZATION
# ============================================================

LIVE_INDIA_REGIONS = (
    "Tamil Nadu",
    "Kerala",
    "Karnataka",
    "Telugu States",
    "Rest of India",
)


def sync_running_movie_totals(
    conn,
    movie_id: int,
    force: bool = False
):
    """
    Recalculate headline box-office totals from saved regional data.

    Running movies sync automatically.
    force=True is used once when a movie is marked Final so the
    last regional totals become the locked final headline totals.
    """

    with conn.cursor() as cur:

        cur.execute("""
            SELECT
                COALESCE(boxoffice_status, 'final')
            FROM movies
            WHERE id = %s
        """, (movie_id,))

        row = cur.fetchone()

        if not row:
            return None

        current_status = (
            row[0] or "final"
        ).strip().lower()

        if (
            current_status != "running"
            and not force
        ):
            return None

        cur.execute("""
            SELECT
                COALESCE(
                    SUM(collection_crore)
                    FILTER (
                        WHERE state = ANY(%s)
                    ),
                    0
                ) AS india_total,

                COALESCE(
                    SUM(collection_crore)
                    FILTER (
                        WHERE state = 'Overseas'
                    ),
                    0
                ) AS overseas_total

            FROM movie_daily_collections

            WHERE movie_id = %s
        """, (
            list(LIVE_INDIA_REGIONS),
            movie_id
        ))

        totals = cur.fetchone()

        india_total = float(
            totals[0] or 0
        )

        overseas_total = float(
            totals[1] or 0
        )

        worldwide_total = (
            india_total +
            overseas_total
        )

        cur.execute("""
            UPDATE movies
            SET
                india_collection_crore = %s,
                overseas_collection_crore = %s,
                worldwide_collection_crore = %s
            WHERE id = %s
        """, (
            india_total,
            overseas_total,
            worldwide_total,
            movie_id
        ))

        return {
            "india_collection_crore":
                india_total,
            "overseas_collection_crore":
                overseas_total,
            "worldwide_collection_crore":
                worldwide_total,
        }


class CollectionUpdate(BaseModel):

    movie_id: int

    collection_date: date

    state: Optional[str] = None

    collection_crore: float


@app.post("/admin/movie-collections", dependencies=[Depends(require_admin)])
def admin_add_collection(
    data: CollectionUpdate
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO movie_daily_collections (
                    movie_id,
                    collection_date,
                    state,
                    collection_crore
                )

                VALUES (
                    %s,
                    %s,
                    %s,
                    %s
                )

                ON CONFLICT (
                    movie_id,
                    collection_date,
                    state
                )

                DO UPDATE SET
                    collection_crore =
                        EXCLUDED.collection_crore
            """, (
                data.movie_id,
                data.collection_date,
                data.state,
                data.collection_crore
            ))

        live_totals = sync_running_movie_totals(
            conn,
            data.movie_id
        )

        conn.commit()

    return {
        "success": True,
        "message": "Collection saved successfully",
        "live_totals": live_totals
    }


from pydantic import BaseModel
from typing import Optional
from datetime import date


class AdminMovieData(BaseModel):

    title: str

    release_date: Optional[date] = None

    language: Optional[str] = None

    industry: Optional[str] = None

    genre: Optional[str] = None

    director: Optional[str] = None

    budget_crore: float = 0

    india_collection_crore: float = 0

    overseas_collection_crore: float = 0

    worldwide_collection_crore: float = 0

    verdict: Optional[str] = None

    poster: Optional[str] = None


@app.get("/admin/movie-collections", dependencies=[Depends(require_admin)])
def admin_get_collections(movie_id: int | None = None):

    with get_connection() as conn:

        with conn.cursor() as cur:

            if movie_id:

                cur.execute("""
                    SELECT
                        c.id,
                        c.movie_id,
                        m.title,
                        c.collection_date,
                        c.state,
                        c.collection_crore
                    FROM movie_daily_collections c
                    JOIN movies m
                        ON m.id = c.movie_id
                    WHERE c.movie_id = %s
                    ORDER BY
                        c.collection_date DESC,
                        c.state NULLS FIRST
                """, (movie_id,))

            else:

                cur.execute("""
                    SELECT
                        c.id,
                        c.movie_id,
                        m.title,
                        c.collection_date,
                        c.state,
                        c.collection_crore
                    FROM movie_daily_collections c
                    JOIN movies m
                        ON m.id = c.movie_id
                    ORDER BY
                        c.collection_date DESC,
                        c.state NULLS FIRST
                """)

            rows = cur.fetchall()

    collections = []

    for row in rows:

        collections.append({
            "id": row[0],
            "movie_id": row[1],
            "movie_title": row[2],
            "collection_date": str(row[3]),
            "state": row[4],
            "collection_crore": float(row[5])
        })

    return {
        "collections": collections
    }



@app.put("/admin/movie-collections/{collection_id}", dependencies=[Depends(require_admin)])
def admin_update_collection(
    collection_id: int,
    data: CollectionUpdate
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                UPDATE movie_daily_collections

                SET
                    movie_id = %s,
                    collection_date = %s,
                    state = %s,
                    collection_crore = %s

                WHERE id = %s
            """, (
                data.movie_id,
                data.collection_date,
                data.state,
                data.collection_crore,
                collection_id
            ))

            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Collection record not found"
                )

        conn.commit()

    return {
        "success": True,
        "message": "Collection updated successfully"
    }


@app.delete("/admin/movie-collections/{collection_id}", dependencies=[Depends(require_admin)])
def admin_delete_collection(
    collection_id: int
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                DELETE FROM movie_daily_collections
                WHERE id = %s
            """, (collection_id,))

            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Collection record not found"
                )

        conn.commit()

    return {
        "success": True,
        "message": "Collection deleted successfully"
    }



@app.post("/admin/movies", dependencies=[Depends(require_admin)])
def admin_add_movie(data: AdminMovieData):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO movies (
                    title,
                    release_date,
                    language,
                    industry,
                    genre,
                    director,
                    budget_crore,
                    india_collection_crore,
                    overseas_collection_crore,
                    worldwide_collection_crore,
                    verdict,
                    poster
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                RETURNING id
            """, (
                data.title,
                data.release_date,
                data.language,
                data.industry,
                data.genre,
                data.director,
                data.budget_crore,
                data.india_collection_crore,
                data.overseas_collection_crore,
                data.worldwide_collection_crore,
                data.verdict,
                data.poster
            ))

            movie_id = cur.fetchone()[0]

        conn.commit()

    return {
        "success": True,
        "message": "Movie added successfully",
        "movie_id": movie_id
    }


@app.put("/admin/movies/{movie_id}", dependencies=[Depends(require_admin)])
def admin_update_movie(
    movie_id: int,
    data: AdminMovieData
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                UPDATE movies

                SET
                    title = %s,
                    release_date = %s,
                    language = %s,
                    industry = %s,
                    genre = %s,
                    director = %s,
                    budget_crore = %s,
                    india_collection_crore = %s,
                    overseas_collection_crore = %s,
                    worldwide_collection_crore = %s,
                    verdict = %s,
                    poster = %s

                WHERE id = %s
            """, (

                data.title,

                data.release_date,

                data.language,

                data.industry,

                data.genre,

                data.director,

                data.budget_crore,

                data.india_collection_crore,

                data.overseas_collection_crore,

                data.worldwide_collection_crore,

                data.verdict,

                data.poster,

                movie_id

            ))


            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Movie not found"
                )

        conn.commit()


    return {

        "success": True,

        "message":
            "Movie updated successfully"

    }


@app.delete("/admin/movies/{movie_id}", dependencies=[Depends(require_admin)])
def admin_delete_movie(
    movie_id: int
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                DELETE FROM movies
                WHERE id = %s
            """, (movie_id,))


            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Movie not found"
                )

        conn.commit()


    return {

        "success": True,

        "message":
            "Movie deleted successfully"

    }


class AdminActorData(BaseModel):

    name: str

    profession: str | None = None

    photo: str | None = None

    bio: str | None = None

    
class ActorMovieLink(BaseModel):
    actor_id: int
    movie_id: int


@app.get("/admin/actors", dependencies=[Depends(require_admin)])
def admin_get_actors():

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    name,
                    profession,
                    photo,
                    bio
                FROM actors
                ORDER BY name
            """)

            rows = cur.fetchall()

    actors = []

    for row in rows:

        actors.append({
            "id": row[0],
            "name": row[1],
            "profession": row[2],
            "photo": safe_actor_photo(row[3]),
            "bio": row[4]
        })

    return {
        "actors": actors
    }

@app.post("/admin/actors", dependencies=[Depends(require_admin)])
def admin_add_actor(
    data: AdminActorData
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO actors (
                    name,
                    profession,
                    photo,
                    bio
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s
                )
                RETURNING id
            """, (
                data.name,
                data.profession,
                data.photo,
                data.bio
            ))

            actor_id = cur.fetchone()[0]

        conn.commit()

    return {
        "success": True,
        "message": "Actor added successfully",
        "actor_id": actor_id
    }


@app.put("/admin/actors/{actor_id}", dependencies=[Depends(require_admin)])
def admin_update_actor(
    actor_id: int,
    data: AdminActorData
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                UPDATE actors
                SET
                    name = %s,
                    profession = %s,
                    photo = %s,
                    bio = %s
                WHERE id = %s
            """, (
                data.name,
                data.profession,
                data.photo,
                data.bio,
                actor_id
            ))

            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Actor not found"
                )

        conn.commit()

    return {
        "success": True,
        "message": "Actor updated successfully"
    }


@app.delete("/admin/actors/{actor_id}", dependencies=[Depends(require_admin)])
def admin_delete_actor(
    actor_id: int
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                DELETE FROM actors
                WHERE id = %s
            """, (actor_id,))

            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Actor not found"
                )

        conn.commit()

    return {
        "success": True,
        "message": "Actor deleted successfully"
    } 



@app.post("/admin/actor-movies", dependencies=[Depends(require_admin)])
def admin_link_actor_movie(
    data: ActorMovieLink
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO actor_movies (
                    actor_id,
                    movie_id
                )
                VALUES (
                    %s,
                    %s
                )
                ON CONFLICT DO NOTHING
            """, (
                data.actor_id,
                data.movie_id
            ))

        conn.commit()

    return {
        "success": True,
        "message": "Actor linked to movie successfully"
    }


@app.get("/admin/actors/{actor_id}/movies", dependencies=[Depends(require_admin)])
def admin_get_actor_movies(
    actor_id: int
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    m.id,
                    m.title,
                    m.release_date,
                    m.poster,
                    m.verdict
                FROM actor_movies am
                JOIN movies m
                    ON m.id = am.movie_id
                WHERE am.actor_id = %s
                ORDER BY m.release_date DESC NULLS LAST
            """, (actor_id,))

            rows = cur.fetchall()

    movies = []

    for row in rows:

        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "poster": safe_movie_poster(row[3]),
            "verdict": row[4]
        })

    return {
        "movies": movies
    }



@app.delete(
    "/admin/actor-movies/{actor_id}/{movie_id}",
    dependencies=[Depends(require_admin)])
def admin_unlink_actor_movie(
    actor_id: int,
    movie_id: int
):

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute("""
                DELETE FROM actor_movies
                WHERE actor_id = %s
                  AND movie_id = %s
            """, (
                actor_id,
                movie_id
            ))

            if cur.rowcount == 0:

                raise HTTPException(
                    status_code=404,
                    detail="Actor/movie link not found"
                )

        conn.commit()

    return {
        "success": True,
        "message": "Actor unlinked from movie successfully"
    }



# ============================================================

@app.get("/article.html")
def article_page():
    return FileResponse(BASE_DIR / "article.html")


@app.get("/article/{slug}")
def article_pretty_page(slug: str):
    return FileResponse(BASE_DIR / "article.html")


# BOXOFFICEX ARTICLES API
# ============================================================

@app.get("/articles")
def get_articles():
    with psycopg.connect("host=localhost dbname=boxofficex user=postgres password=5432") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,title,slug,subtitle,category,author,hero_image,
                       hero_caption,hero_credit,views,published_at,updated_at
                FROM articles
                WHERE status='published'
                ORDER BY published_at DESC NULLS LAST,id DESC
            """)
            rows=cur.fetchall()
    return {"articles":[
        {"id":r[0],"title":r[1],"slug":r[2],"subtitle":r[3],
         "category":r[4],"author":r[5],"hero_image":r[6],
         "hero_caption":r[7],"hero_credit":r[8],"views":r[9],
         "published_at":r[10],"updated_at":r[11]}
        for r in rows
    ]}


@app.get("/articles/latest")
def get_latest_articles(limit: int = 10):
    limit=max(1,min(limit,50))
    with psycopg.connect("host=localhost dbname=boxofficex user=postgres password=5432") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,title,slug,subtitle,category,author,hero_image,views,published_at
                FROM articles
                WHERE status='published'
                ORDER BY published_at DESC NULLS LAST,id DESC
                LIMIT %s
            """,(limit,))
            rows=cur.fetchall()
    return {"articles":[
        {"id":r[0],"title":r[1],"slug":r[2],"subtitle":r[3],
         "category":r[4],"author":r[5],"hero_image":r[6],
         "views":r[7],"published_at":r[8]}
        for r in rows
    ]}


@app.get("/movies/{movie_id}/articles")
def get_movie_articles(movie_id: int):
    with psycopg.connect("host=localhost dbname=boxofficex user=postgres password=5432") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.id,a.title,a.slug,a.subtitle,a.category,a.author,a.hero_image,a.published_at
                FROM article_movies am
                JOIN articles a ON a.id=am.article_id
                WHERE am.movie_id=%s AND a.status='published'
                ORDER BY a.published_at DESC NULLS LAST,a.id DESC
            """,(movie_id,))
            rows=cur.fetchall()
    return {"articles":[
        {"id":r[0],"title":r[1],"slug":r[2],"subtitle":r[3],
         "category":r[4],"author":r[5],"hero_image":r[6],"published_at":r[7]}
        for r in rows
    ]}


@app.get("/actors/{actor_id}/articles")
def get_actor_articles(actor_id: int):
    with psycopg.connect("host=localhost dbname=boxofficex user=postgres password=5432") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.id,a.title,a.slug,a.subtitle,a.category,a.author,a.hero_image,a.published_at
                FROM article_actors aa
                JOIN articles a ON a.id=aa.article_id
                WHERE aa.actor_id=%s AND a.status='published'
                ORDER BY a.published_at DESC NULLS LAST,a.id DESC
            """,(actor_id,))
            rows=cur.fetchall()
    return {"articles":[
        {"id":r[0],"title":r[1],"slug":r[2],"subtitle":r[3],
         "category":r[4],"author":r[5],"hero_image":r[6],"published_at":r[7]}
        for r in rows
    ]}


@app.get("/articles/{slug}/blocks")
def get_article_blocks(slug: str):
    with psycopg.connect("host=localhost dbname=boxofficex user=postgres password=5432") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ab.id,ab.block_order,ab.block_type,ab.content,
                       ab.image,ab.image_caption,ab.image_credit,ab.extra_data
                FROM article_blocks ab
                JOIN articles a ON a.id=ab.article_id
                WHERE a.slug=%s AND a.status='published'
                ORDER BY ab.block_order
            """,(slug,))
            rows=cur.fetchall()
    return {"blocks":[
        {"id":r[0],"block_order":r[1],"block_type":r[2],"content":r[3],
         "image":r[4],"image_caption":r[5],"image_credit":r[6],"extra_data":r[7] or {}}
        for r in rows
    ]}


@app.get("/articles/{slug}")
def get_article(slug: str):
    with psycopg.connect("host=localhost dbname=boxofficex user=postgres password=5432") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,title,slug,subtitle,category,author,hero_image,
                       hero_caption,hero_credit,status,meta_title,meta_description,
                       views,published_at,created_at,updated_at
                FROM articles
                WHERE slug=%s AND status='published'
                LIMIT 1
            """,(slug,))
            a=cur.fetchone()

            if not a:
                return {"error":"Article not found"}

            cur.execute("""
                SELECT id,block_order,block_type,content,image,
                       image_caption,image_credit,extra_data
                FROM article_blocks
                WHERE article_id=%s
                ORDER BY block_order
            """,(a[0],))
            blocks=cur.fetchall()

            cur.execute("SELECT movie_id FROM article_movies WHERE article_id=%s ORDER BY movie_id",(a[0],))
            movie_ids=[r[0] for r in cur.fetchall()]

            cur.execute("SELECT actor_id FROM article_actors WHERE article_id=%s ORDER BY actor_id",(a[0],))
            actor_ids=[r[0] for r in cur.fetchall()]

    return {"article":{
        "id":a[0],"title":a[1],"slug":a[2],"subtitle":a[3],
        "category":a[4],"author":a[5],"hero_image":a[6],
        "hero_caption":a[7],"hero_credit":a[8],"status":a[9],
        "meta_title":a[10],"meta_description":a[11],"views":a[12],
        "published_at":a[13],"created_at":a[14],"updated_at":a[15],
        "movie_ids":movie_ids,"actor_ids":actor_ids,
        "blocks":[
            {"id":r[0],"block_order":r[1],"block_type":r[2],"content":r[3],
             "image":r[4],"image_caption":r[5],"image_credit":r[6],"extra_data":r[7] or {}}
            for r in blocks
        ]
    }}



# ============================================================
# BOXOFFICEX ADMIN ARTICLE API
# Draft / edit / publish / blocks / image upload
# ============================================================

from typing import Optional, Any
from datetime import datetime
import re


class AdminArticleCreate(BaseModel):
    title: str
    slug: str
    subtitle: Optional[str] = None
    category: str = "News"
    author: str = "BoxOfficeX"
    hero_image: Optional[str] = None
    hero_caption: Optional[str] = None
    hero_credit: Optional[str] = None
    status: str = "draft"
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    published_at: Optional[datetime] = None


class AdminArticleBlock(BaseModel):
    block_order: int
    block_type: str
    content: Optional[str] = None
    image: Optional[str] = None
    image_caption: Optional[str] = None
    image_credit: Optional[str] = None
    extra_data: dict[str, Any] = {}


class AdminArticleLink(BaseModel):
    movie_ids: list[int] = []
    actor_ids: list[int] = []


def normalize_article_slug(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value


def validate_article_status(value: str) -> str:
    allowed = {"draft", "published", "archived"}
    value = (value or "draft").lower().strip()
    if value not in allowed:
        raise HTTPException(status_code=400, detail="Invalid article status")
    return value


def validate_block_type(value: str) -> str:
    allowed = {
        "paragraph", "heading", "image", "quote", "gallery",
        "boxoffice", "movie", "actor", "video"
    }
    value = (value or "").lower().strip()
    if value not in allowed:
        raise HTTPException(status_code=400, detail="Invalid article block type")
    return value


@app.get("/admin/articles", dependencies=[Depends(require_admin)])
def admin_list_articles():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id, title, slug, subtitle, category, author,
                    hero_image, status, views,
                    published_at, created_at, updated_at
                FROM articles
                ORDER BY created_at DESC, id DESC
            """)
            rows = cur.fetchall()

    return {
        "articles": [
            {
                "id": r[0],
                "title": r[1],
                "slug": r[2],
                "subtitle": r[3],
                "category": r[4],
                "author": r[5],
                "hero_image": r[6],
                "status": r[7],
                "views": r[8],
                "published_at": r[9],
                "created_at": r[10],
                "updated_at": r[11],
            }
            for r in rows
        ]
    }


@app.get("/admin/articles/{article_id}", dependencies=[Depends(require_admin)])
def admin_get_article(article_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id, title, slug, subtitle, category, author,
                    hero_image, hero_caption, hero_credit,
                    status, meta_title, meta_description,
                    views, published_at, created_at, updated_at
                FROM articles
                WHERE id = %s
            """, (article_id,))
            a = cur.fetchone()

            if not a:
                raise HTTPException(status_code=404, detail="Article not found")

            cur.execute("""
                SELECT
                    id, block_order, block_type, content, image,
                    image_caption, image_credit, extra_data
                FROM article_blocks
                WHERE article_id = %s
                ORDER BY block_order
            """, (article_id,))
            blocks = cur.fetchall()

            cur.execute("""
                SELECT movie_id
                FROM article_movies
                WHERE article_id = %s
                ORDER BY movie_id
            """, (article_id,))
            movie_ids = [r[0] for r in cur.fetchall()]

            cur.execute("""
                SELECT actor_id
                FROM article_actors
                WHERE article_id = %s
                ORDER BY actor_id
            """, (article_id,))
            actor_ids = [r[0] for r in cur.fetchall()]

    return {
        "article": {
            "id": a[0],
            "title": a[1],
            "slug": a[2],
            "subtitle": a[3],
            "category": a[4],
            "author": a[5],
            "hero_image": a[6],
            "hero_caption": a[7],
            "hero_credit": a[8],
            "status": a[9],
            "meta_title": a[10],
            "meta_description": a[11],
            "views": a[12],
            "published_at": a[13],
            "created_at": a[14],
            "updated_at": a[15],
            "movie_ids": movie_ids,
            "actor_ids": actor_ids,
            "blocks": [
                {
                    "id": r[0],
                    "block_order": r[1],
                    "block_type": r[2],
                    "content": r[3],
                    "image": r[4],
                    "image_caption": r[5],
                    "image_credit": r[6],
                    "extra_data": r[7] or {},
                }
                for r in blocks
            ],
        }
    }


@app.post("/admin/articles", dependencies=[Depends(require_admin)])
def admin_create_article(data: AdminArticleCreate):
    slug = normalize_article_slug(data.slug or data.title)
    if not slug:
        raise HTTPException(status_code=400, detail="Article slug is required")

    status = validate_article_status(data.status)
    published_at = data.published_at

    if status == "published" and published_at is None:
        published_at = datetime.now()

    with get_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO articles (
                        title, slug, subtitle, category, author,
                        hero_image, hero_caption, hero_credit,
                        status, meta_title, meta_description,
                        published_at, updated_at
                    )
                    VALUES (
                        %s,%s,%s,%s,%s,
                        %s,%s,%s,
                        %s,%s,%s,
                        %s,CURRENT_TIMESTAMP
                    )
                    RETURNING id
                """, (
                    data.title.strip(),
                    slug,
                    data.subtitle,
                    data.category.strip() or "News",
                    data.author.strip() or "BoxOfficeX",
                    data.hero_image,
                    data.hero_caption,
                    data.hero_credit,
                    status,
                    data.meta_title,
                    data.meta_description,
                    published_at,
                ))
                article_id = cur.fetchone()[0]
            except psycopg.errors.UniqueViolation:
                raise HTTPException(status_code=409, detail="Article slug already exists")

        conn.commit()

    return {
        "success": True,
        "article_id": article_id,
        "slug": slug,
        "article_url": f"/article/{slug}",
    }


@app.put("/admin/articles/{article_id}", dependencies=[Depends(require_admin)])
def admin_update_article(article_id: int, data: AdminArticleCreate):
    slug = normalize_article_slug(data.slug or data.title)
    if not slug:
        raise HTTPException(status_code=400, detail="Article slug is required")

    status = validate_article_status(data.status)
    published_at = data.published_at

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT published_at
                FROM articles
                WHERE id = %s
            """, (article_id,))
            existing = cur.fetchone()

            if not existing:
                raise HTTPException(status_code=404, detail="Article not found")

            if status == "published" and published_at is None:
                published_at = existing[0] or datetime.now()

            try:
                cur.execute("""
                    UPDATE articles
                    SET
                        title = %s,
                        slug = %s,
                        subtitle = %s,
                        category = %s,
                        author = %s,
                        hero_image = %s,
                        hero_caption = %s,
                        hero_credit = %s,
                        status = %s,
                        meta_title = %s,
                        meta_description = %s,
                        published_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (
                    data.title.strip(),
                    slug,
                    data.subtitle,
                    data.category.strip() or "News",
                    data.author.strip() or "BoxOfficeX",
                    data.hero_image,
                    data.hero_caption,
                    data.hero_credit,
                    status,
                    data.meta_title,
                    data.meta_description,
                    published_at,
                    article_id,
                ))
            except psycopg.errors.UniqueViolation:
                raise HTTPException(status_code=409, detail="Article slug already exists")

        conn.commit()

    return {
        "success": True,
        "article_id": article_id,
        "slug": slug,
        "article_url": f"/article/{slug}",
    }


@app.delete("/admin/articles/{article_id}", dependencies=[Depends(require_admin)])
def admin_delete_article(article_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM articles
                WHERE id = %s
            """, (article_id,))

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Article not found")

        conn.commit()

    return {"success": True, "message": "Article deleted successfully"}


@app.post("/admin/articles/{article_id}/blocks", dependencies=[Depends(require_admin)])
def admin_add_article_block(article_id: int, data: AdminArticleBlock):
    block_type = validate_block_type(data.block_type)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM articles WHERE id=%s", (article_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Article not found")

            try:
                cur.execute("""
                    INSERT INTO article_blocks (
                        article_id, block_order, block_type,
                        content, image, image_caption,
                        image_credit, extra_data
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (
                    article_id,
                    data.block_order,
                    block_type,
                    data.content,
                    data.image,
                    data.image_caption,
                    data.image_credit,
                    psycopg.types.json.Jsonb(data.extra_data or {}),
                ))
                block_id = cur.fetchone()[0]
            except psycopg.errors.UniqueViolation:
                raise HTTPException(
                    status_code=409,
                    detail="That block order already exists for this article"
                )

        conn.commit()

    return {"success": True, "block_id": block_id}


@app.put("/admin/article-blocks/{block_id}", dependencies=[Depends(require_admin)])
def admin_update_article_block(block_id: int, data: AdminArticleBlock):
    block_type = validate_block_type(data.block_type)

    with get_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("""
                    UPDATE article_blocks
                    SET
                        block_order = %s,
                        block_type = %s,
                        content = %s,
                        image = %s,
                        image_caption = %s,
                        image_credit = %s,
                        extra_data = %s
                    WHERE id = %s
                """, (
                    data.block_order,
                    block_type,
                    data.content,
                    data.image,
                    data.image_caption,
                    data.image_credit,
                    psycopg.types.json.Jsonb(data.extra_data or {}),
                    block_id,
                ))
            except psycopg.errors.UniqueViolation:
                raise HTTPException(
                    status_code=409,
                    detail="That block order already exists for this article"
                )

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Article block not found")

        conn.commit()

    return {"success": True, "block_id": block_id}


@app.delete("/admin/article-blocks/{block_id}", dependencies=[Depends(require_admin)])
def admin_delete_article_block(block_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM article_blocks
                WHERE id = %s
            """, (block_id,))

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Article block not found")

        conn.commit()

    return {"success": True}


@app.put("/admin/articles/{article_id}/links", dependencies=[Depends(require_admin)])
def admin_update_article_links(article_id: int, data: AdminArticleLink):
    movie_ids = list(dict.fromkeys(data.movie_ids or []))
    actor_ids = list(dict.fromkeys(data.actor_ids or []))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM articles WHERE id=%s", (article_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Article not found")

            cur.execute("DELETE FROM article_movies WHERE article_id=%s", (article_id,))
            cur.execute("DELETE FROM article_actors WHERE article_id=%s", (article_id,))

            for movie_id in movie_ids:
                cur.execute("""
                    INSERT INTO article_movies(article_id, movie_id)
                    SELECT %s, id
                    FROM movies
                    WHERE id = %s
                    ON CONFLICT DO NOTHING
                """, (article_id, movie_id))

            for actor_id in actor_ids:
                cur.execute("""
                    INSERT INTO article_actors(article_id, actor_id)
                    SELECT %s, id
                    FROM actors
                    WHERE id = %s
                    ON CONFLICT DO NOTHING
                """, (article_id, actor_id))

        conn.commit()

    return {
        "success": True,
        "movie_ids": movie_ids,
        "actor_ids": actor_ids,
    }


@app.post("/admin/article-images/upload", dependencies=[Depends(require_admin)])
async def admin_upload_article_image(
    file: UploadFile = File(...)
):
    allowed_types = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Only JPG, PNG and WEBP images are allowed"
        )

    raw = await file.read()

    # 10 MB upload ceiling
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Image must be 10 MB or smaller"
        )

    extension = allowed_types[file.content_type]
    original_stem = Path(file.filename or "article-image").stem
    safe_stem = re.sub(r"[^a-zA-Z0-9_-]+", "-", original_stem).strip("-").lower()
    if not safe_stem:
        safe_stem = "article-image"

    filename = f"{safe_stem}-{secrets.token_hex(4)}{extension}"
    destination = ARTICLE_IMAGES_DIR / filename

    destination.write_bytes(raw)

    return {
        "success": True,
        "filename": filename,
        "url": f"/article-images/{filename}",
    }


@app.post("/admin/articles/{article_id}/publish", dependencies=[Depends(require_admin)])
def admin_publish_article(article_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE articles
                SET
                    status='published',
                    published_at=COALESCE(published_at,CURRENT_TIMESTAMP),
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=%s
            """, (article_id,))

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Article not found")

        conn.commit()

    return {"success": True, "message": "Article published successfully"}


@app.post("/admin/articles/{article_id}/draft", dependencies=[Depends(require_admin)])
def admin_unpublish_article(article_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE articles
                SET status='draft', updated_at=CURRENT_TIMESTAMP
                WHERE id=%s
            """, (article_id,))

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Article not found")

        conn.commit()

    return {"success": True, "message": "Article moved to draft"}

@app.get("/admin-articles.html", dependencies=[Depends(require_admin)])
def admin_articles_page():
    return FileResponse(BASE_DIR / "admin-articles.html")



@app.get("/articles.html")
def articles_page():
    return FileResponse(BASE_DIR / "articles.html")



# ============================================================
# BOXOFFICEX MOVIE COMPARISON API
# ============================================================

@app.get("/compare/movies/{movie1_id}/{movie2_id}")
def compare_movies(movie1_id: int, movie2_id: int):

    if movie1_id == movie2_id:
        raise HTTPException(
            status_code=400,
            detail="Choose two different movies"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    industry,
                    genre,
                    director,
                    budget_crore,
                    india_collection_crore,
                    overseas_collection_crore,
                    worldwide_collection_crore,
                    verdict,
                    poster
                FROM movies
                WHERE id IN (%s, %s)
                ORDER BY id
            """, (movie1_id, movie2_id))

            rows = cur.fetchall()

    if len(rows) != 2:
        found_ids = {row[0] for row in rows}

        missing = []

        if movie1_id not in found_ids:
            missing.append(movie1_id)

        if movie2_id not in found_ids:
            missing.append(movie2_id)

        raise HTTPException(
            status_code=404,
            detail=f"Movie not found: {', '.join(map(str, missing))}"
        )

    def movie_to_dict(row):

        return {
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "language": row[3],
            "industry": row[4],
            "genre": row[5],
            "director": row[6],
            "budget_crore": float(row[7]) if row[7] is not None else None,
            "india_collection_crore": float(row[8]) if row[8] is not None else None,
            "overseas_collection_crore": float(row[9]) if row[9] is not None else None,
            "worldwide_collection_crore": float(row[10]) if row[10] is not None else None,
            "verdict": row[11],
            "poster": safe_movie_poster(row[12])
        }

    movies_by_id = {
        row[0]: movie_to_dict(row)
        for row in rows
    }

    movie1 = movies_by_id[movie1_id]
    movie2 = movies_by_id[movie2_id]

    def compare_metric(field, higher_is_better=True):

        a = movie1.get(field)
        b = movie2.get(field)

        if a is None and b is None:
            return {
                "winner": None,
                "reason": "Data unavailable for both movies"
            }

        if a is None:
            return {
                "winner": movie2_id,
                "reason": "Only Movie B has available data"
            }

        if b is None:
            return {
                "winner": movie1_id,
                "reason": "Only Movie A has available data"
            }

        if a == b:
            return {
                "winner": "tie",
                "reason": "Both values are equal"
            }

        if higher_is_better:
            winner = movie1_id if a > b else movie2_id
        else:
            winner = movie1_id if a < b else movie2_id

        return {
            "winner": winner,
            "reason": "higher" if higher_is_better else "lower"
        }

    winners = {
        "budget": compare_metric(
            "budget_crore",
            higher_is_better=False
        ),
        "india_collection": compare_metric(
            "india_collection_crore"
        ),
        "overseas_collection": compare_metric(
            "overseas_collection_crore"
        ),
        "worldwide_collection": compare_metric(
            "worldwide_collection_crore"
        )
    }

    return {
        "movie1": movie1,
        "movie2": movie2,
        "winners": winners
    }



@app.get("/movie-compare-select.html")
def movie_compare_select_page():
    return FileResponse(BASE_DIR / "movie-compare-select.html")


@app.get("/movie-compare.html")
def movie_compare_page():
    return FileResponse(BASE_DIR / "movie-compare.html")




@app.get("/admin-new-movies.html", dependencies=[Depends(require_admin)])
def admin_new_movies_page():
    return FileResponse(BASE_DIR / "admin-new-movies.html")



@app.get("/admin-daily-boxoffice.html", dependencies=[Depends(require_admin)])
def admin_daily_boxoffice_page():
    return FileResponse(BASE_DIR / "admin-daily-boxoffice.html")



@app.get("/admin-regional-boxoffice.html", dependencies=[Depends(require_admin)])
def admin_regional_boxoffice_page():
    return FileResponse(BASE_DIR / "admin-regional-boxoffice.html")
