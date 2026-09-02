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
IMAGES_DIR = BASE_DIR / "images"
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

IS_PRODUCTION = (
    os.getenv("BOXOFFICEX_ENV", "").strip().lower() == "production"
    or bool(os.getenv("RENDER"))
)

app = FastAPI(
    title="BoxOfficeX API",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)


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

if IS_PRODUCTION and SESSION_SECRET == "CHANGE_ME_BOXOFFICEX_SESSION_SECRET_2026":
    raise RuntimeError(
        "BOXOFFICEX_SESSION_SECRET must be set to a strong random value in production."
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

if IS_PRODUCTION:
    if BOOTSTRAP_OWNER_PASSWORD == "CHANGE_ME_BOXOFFICEX_ADMIN_PASSWORD":
        raise RuntimeError(
            "BOXOFFICEX_OWNER_PASSWORD must be set in production."
        )
    if len(BOOTSTRAP_OWNER_PASSWORD) < 12:
        raise RuntimeError(
            "BOXOFFICEX_OWNER_PASSWORD must be at least 12 characters in production."
        )

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="boxofficex_admin_session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=(
        IS_PRODUCTION
        or os.getenv(
            "BOXOFFICEX_HTTPS_ONLY",
            "false"
        ).strip().lower() in {"1", "true", "yes", "on"}
    )
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

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "BOXOFFICEX_CORS_ORIGINS",
        (
            "https://boxoffice-x.com,"
            "https://www.boxoffice-x.com"
            if IS_PRODUCTION
            else
            "http://127.0.0.1:8000,http://localhost:8000"
        )
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type"],
)


# ============================================================
# PRODUCTION SECURITY HEADERS
# ============================================================

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


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

app.mount(
    "/images",
    StaticFiles(directory=IMAGES_DIR),
    name="images"
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

DATABASE_URL = os.getenv("DATABASE_URL")

if IS_PRODUCTION and not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL must be set in production."
    )

if not DATABASE_URL:
    DATABASE_URL = LOCAL_DATABASE_URL


def get_connection():
    """
    Production uses DATABASE_URL.
    Local development falls back to BOXOFFICEX_LOCAL_DATABASE_URL.
    """
    return psycopg.connect(DATABASE_URL)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "index.html")




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
# UPCOMING MOVIES
# Future releases ordered by nearest release date
# IMPORTANT: KEEP THIS BEFORE /movies/{movie_id}
# ============================================================

@app.get("/movies/upcoming")
def upcoming_movies(limit: int = 10):
    limit = max(1, min(int(limit or 10), 50))

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
                    poster,
                    industry,
                    boxoffice_status,
                    (release_date - CURRENT_DATE) AS days_until_release
                FROM movies
                WHERE release_date IS NOT NULL
                  AND release_date > CURRENT_DATE
                ORDER BY release_date ASC, id ASC
                LIMIT %s
            """, (limit,))

            rows = cur.fetchall()

    return {
        "movies": [
            {
                "rank": position,
                "id": row[0],
                "title": row[1],
                "release_date": row[2].isoformat() if row[2] else None,
                "language": row[3],
                "genre": row[4],
                "director": row[5],
                "poster": safe_movie_poster(row[6]),
                "industry": row[7],
                "boxoffice_status": row[8],
                "days_until_release": int(row[9]) if row[9] is not None else None,
                "url": f"/movie.html?id={row[0]}",
            }
            for position, row in enumerate(rows, start=1)
        ]
    }


# ============================================================
# TRENDING MOVIES
# Recent 7-day audience activity ranking
# IMPORTANT: KEEP THIS BEFORE /movies/{movie_id}
# ============================================================

@app.get("/movies/trending")
def trending_movies(limit: int = 10):
    limit = max(1, min(int(limit or 10), 50))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                WITH movie_activity AS (
                    SELECT
                        m.id,
                        m.title,
                        m.language,
                        m.industry,
                        m.release_date,
                        m.poster,

                        COUNT(DISTINCT v.id) FILTER (
                            WHERE v.viewed_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS view_count,

                        COUNT(DISTINCT f.id) FILTER (
                            WHERE f.created_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS fan_count,

                        COUNT(DISTINCT h.id) FILTER (
                            WHERE h.created_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS hype_count,

                        COUNT(DISTINCT fv.id) FILTER (
                            WHERE fv.created_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS vote_count,

                        COUNT(DISTINCT c.id) FILTER (
                            WHERE c.created_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS comment_count

                    FROM movies m
                    LEFT JOIN movie_views v
                        ON v.movie_id = m.id
                    LEFT JOIN movie_fans f
                        ON f.movie_id = m.id
                    LEFT JOIN movie_hype h
                        ON h.movie_id = m.id
                    LEFT JOIN movie_fan_votes fv
                        ON fv.movie_id = m.id
                    LEFT JOIN movie_comments c
                        ON c.movie_id = m.id

                    GROUP BY
                        m.id,
                        m.title,
                        m.language,
                        m.industry,
                        m.release_date,
                        m.poster
                ),
                ranked AS (
                    SELECT
                        *,
                        (
                            view_count
                            + (fan_count * 2)
                            + (hype_count * 3)
                            + (vote_count * 2)
                            + (comment_count * 3)
                        )::bigint AS trending_score
                    FROM movie_activity
                )
                SELECT
                    id,
                    title,
                    language,
                    industry,
                    release_date,
                    poster,
                    view_count,
                    fan_count,
                    hype_count,
                    vote_count,
                    comment_count,
                    trending_score
                FROM ranked
                WHERE trending_score > 0
                ORDER BY
                    trending_score DESC,
                    hype_count DESC,
                    view_count DESC,
                    release_date DESC NULLS LAST,
                    id DESC
                LIMIT %s
            """, (limit,))

            rows = cur.fetchall()

    movies = []

    for position, row in enumerate(rows, start=1):
        movies.append({
            "rank": position,
            "id": row[0],
            "title": row[1],
            "language": row[2],
            "industry": row[3],
            "release_date": str(row[4]) if row[4] else None,
            "poster": safe_movie_poster(row[5]),
            "view_count": int(row[6] or 0),
            "fan_count": int(row[7] or 0),
            "hype_count": int(row[8] or 0),
            "vote_count": int(row[9] or 0),
            "comment_count": int(row[10] or 0),
            "trending_score": int(row[11] or 0),
        })

    return {
        "period_days": 7,
        "movies": movies,
    }


# ============================================================
# BOXOFFICEX NEW MOVIE SYSTEM
# Running / Upcoming / Recently Released
# ============================================================
# MOST HYPED MOVIES
# Dynamic ranking from unique visitor hype votes
# ============================================================

@app.get("/movies/most-hyped")
def most_hyped_movies(limit: int = 10):
    limit = max(1, min(int(limit or 10), 50))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    m.id,
                    m.title,
                    m.language,
                    m.industry,
                    m.release_date,
                    m.poster,
                    COUNT(h.id) AS hype_count
                FROM movies m
                JOIN movie_hype h
                  ON h.movie_id = m.id
                GROUP BY
                    m.id, m.title, m.language, m.industry,
                    m.release_date, m.poster
                ORDER BY hype_count DESC, m.release_date DESC NULLS LAST, m.id DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()

    movies = []
    for position, row in enumerate(rows, start=1):
        movies.append({
            "rank": position,
            "id": row[0],
            "title": row[1],
            "language": row[2],
            "industry": row[3],
            "release_date": str(row[4]) if row[4] else None,
            "poster": safe_movie_poster(row[5]),
            "hype_count": int(row[6] or 0)
        })

    return {"movies": movies}

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



# ============================================================
# RELATED CONTENT FOR MOVIE PAGE
# Related movies + published articles
# IMPORTANT: KEEP BEFORE /movies/{movie_id}
# ============================================================

@app.get("/movies/{movie_id}/related")
def get_related_movie_content(movie_id: int, limit: int = 6):
    limit = max(1, min(int(limit or 6), 12))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, language, industry, genre, director
                FROM movies
                WHERE id = %s
            """, (movie_id,))
            source = cur.fetchone()

            if not source:
                raise HTTPException(status_code=404, detail="Movie not found")

            _, source_title, language, industry, genre, director = source

            cur.execute("""
                SELECT
                    m.id,
                    m.title,
                    m.release_date,
                    m.language,
                    m.genre,
                    m.worldwide_collection_crore,
                    m.verdict,
                    m.poster,
                    (
                        CASE WHEN m.language = %s THEN 4 ELSE 0 END +
                        CASE WHEN m.industry = %s THEN 3 ELSE 0 END +
                        CASE WHEN m.genre = %s THEN 3 ELSE 0 END +
                        CASE WHEN m.director = %s THEN 2 ELSE 0 END +
                        (
                            SELECT COUNT(*) * 5
                            FROM actor_movies source_am
                            JOIN actor_movies candidate_am
                              ON candidate_am.actor_id = source_am.actor_id
                            WHERE source_am.movie_id = %s
                              AND candidate_am.movie_id = m.id
                        )
                    ) AS relevance_score
                FROM movies m
                WHERE m.id <> %s
                ORDER BY
                    relevance_score DESC,
                    m.release_date DESC NULLS LAST,
                    m.worldwide_collection_crore DESC NULLS LAST,
                    m.id DESC
                LIMIT %s
            """, (
                language, industry, genre, director,
                movie_id, movie_id, limit
            ))
            movie_rows = cur.fetchall()

            # Articles explicitly linked to this movie rank first.
            # Same-title matches provide a safe fallback for older articles.
            cur.execute("""
                SELECT DISTINCT
                    a.id,
                    a.title,
                    a.slug,
                    a.subtitle,
                    a.category,
                    a.author,
                    a.hero_image,
                    a.published_at,
                    CASE
                        WHEN am.movie_id IS NOT NULL THEN 10
                        WHEN LOWER(a.title) LIKE LOWER(%s) THEN 5
                        ELSE 0
                    END AS relevance_score
                FROM articles a
                LEFT JOIN article_movies am
                  ON am.article_id = a.id
                 AND am.movie_id = %s
                WHERE a.status = 'published'
                  AND (
                      am.movie_id IS NOT NULL
                      OR LOWER(a.title) LIKE LOWER(%s)
                  )
                ORDER BY
                    relevance_score DESC,
                    a.published_at DESC NULLS LAST,
                    a.id DESC
                LIMIT %s
            """, (
                f"%{source_title}%",
                movie_id,
                f"%{source_title}%",
                limit
            ))
            article_rows = cur.fetchall()

    return {
        "movie_id": movie_id,
        "related_movies": [
            {
                "id": r[0],
                "title": r[1],
                "release_date": str(r[2]) if r[2] else None,
                "language": r[3],
                "genre": r[4],
                "worldwide_collection_crore": float(r[5] or 0),
                "verdict": r[6],
                "poster": safe_movie_poster(r[7]),
                "relevance_score": int(r[8] or 0),
                "url": f"/movie.html?id={r[0]}",
            }
            for r in movie_rows
        ],
        "related_articles": [
            {
                "id": r[0],
                "title": r[1],
                "slug": r[2],
                "subtitle": r[3],
                "category": r[4],
                "author": r[5],
                "hero_image": r[6],
                "published_at": r[7].isoformat() if r[7] else None,
                "relevance_score": int(r[8] or 0),
                "url": f"/article/{r[2]}",
            }
            for r in article_rows
        ],
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
# BOXOFFICEX UNIFIED SEARCH
# Movies + Actors + Published Articles
# ============================================================

@app.get("/search")
def unified_search(q: str = "", limit: int = 8):
    query = (q or "").strip()
    limit = max(1, min(int(limit or 8), 20))

    if len(query) < 2:
        return {
            "query": query,
            "movies": [],
            "actors": [],
            "articles": [],
            "total": 0,
        }

    contains = f"%{query}%"
    starts = f"{query}%"

    with get_connection() as conn:
        with conn.cursor() as cur:

            # Movies:
            # exact title > title starts with > title contains >
            # director/language/industry/genre contains.
            cur.execute("""
                SELECT
                    id,
                    title,
                    release_date,
                    language,
                    industry,
                    genre,
                    director,
                    worldwide_collection_crore,
                    verdict,
                    poster
                FROM movies
                WHERE
                    title ILIKE %s
                    OR director ILIKE %s
                    OR language ILIKE %s
                    OR industry ILIKE %s
                    OR genre ILIKE %s
                ORDER BY
                    CASE
                        WHEN LOWER(title) = LOWER(%s) THEN 0
                        WHEN title ILIKE %s THEN 1
                        WHEN title ILIKE %s THEN 2
                        WHEN director ILIKE %s THEN 3
                        WHEN language ILIKE %s THEN 4
                        WHEN industry ILIKE %s THEN 5
                        WHEN genre ILIKE %s THEN 6
                        ELSE 7
                    END,
                    worldwide_collection_crore DESC NULLS LAST,
                    release_date DESC NULLS LAST,
                    id DESC
                LIMIT %s
            """, (
                contains, contains, contains, contains, contains,
                query, starts, contains, contains, contains, contains, contains,
                limit
            ))
            movie_rows = cur.fetchall()

            # Actors:
            # exact name > name starts with > name contains > profession contains.
            cur.execute("""
                SELECT
                    id,
                    name,
                    profession,
                    photo,
                    bio
                FROM actors
                WHERE
                    name ILIKE %s
                    OR profession ILIKE %s
                ORDER BY
                    CASE
                        WHEN LOWER(name) = LOWER(%s) THEN 0
                        WHEN name ILIKE %s THEN 1
                        WHEN name ILIKE %s THEN 2
                        WHEN profession ILIKE %s THEN 3
                        ELSE 4
                    END,
                    name ASC,
                    id ASC
                LIMIT %s
            """, (
                contains, contains,
                query, starts, contains, contains,
                limit
            ))
            actor_rows = cur.fetchall()

            # Articles:
            # published only. Exact title > title starts with > title/subtitle/category contains.
            cur.execute("""
                SELECT
                    id,
                    title,
                    slug,
                    subtitle,
                    category,
                    author,
                    hero_image,
                    published_at
                FROM articles
                WHERE
                    status = 'published'
                    AND (
                        title ILIKE %s
                        OR COALESCE(subtitle, '') ILIKE %s
                        OR COALESCE(category, '') ILIKE %s
                    )
                ORDER BY
                    CASE
                        WHEN LOWER(title) = LOWER(%s) THEN 0
                        WHEN title ILIKE %s THEN 1
                        WHEN title ILIKE %s THEN 2
                        WHEN COALESCE(subtitle, '') ILIKE %s THEN 3
                        WHEN COALESCE(category, '') ILIKE %s THEN 4
                        ELSE 5
                    END,
                    published_at DESC NULLS LAST,
                    id DESC
                LIMIT %s
            """, (
                contains, contains, contains,
                query, starts, contains, contains, contains,
                limit
            ))
            article_rows = cur.fetchall()

    movies = [
        {
            "type": "movie",
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "language": row[3],
            "industry": row[4],
            "genre": row[5],
            "director": row[6],
            "worldwide_collection_crore": float(row[7] or 0),
            "verdict": row[8],
            "poster": safe_movie_poster(row[9]),
            "url": f"/movie.html?id={row[0]}",
        }
        for row in movie_rows
    ]

    actors = [
        {
            "type": "actor",
            "id": row[0],
            "name": row[1],
            "profession": row[2],
            "photo": safe_actor_photo(row[3]),
            "bio": row[4],
            "url": f"/actor.html?id={row[0]}",
        }
        for row in actor_rows
    ]

    articles = [
        {
            "type": "article",
            "id": row[0],
            "title": row[1],
            "slug": row[2],
            "subtitle": row[3],
            "category": row[4],
            "author": row[5],
            "hero_image": row[6],
            "published_at": row[7].isoformat() if row[7] else None,
            "url": f"/article/{row[2]}",
        }
        for row in article_rows
    ]

    return {
        "query": query,
        "movies": movies,
        "actors": actors,
        "articles": articles,
        "total": len(movies) + len(actors) + len(articles),
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

    # Industry -> language fallback
    industry_language_map = {
        "kollywood": "Tamil",
        "tollywood": "Telugu",
        "bollywood": "Hindi",
        "sandalwood": "Kannada",
        "mollywood": "Malayalam",
        "hollywood": "English",
    }

    requested_industry = (industry or "All").strip()
    industry_key = requested_industry.lower()

    with get_connection() as conn:

        with conn.cursor() as cur:

            # ==========================================
            # GLOBAL RANKINGS
            # ==========================================

            if industry_key == "all":

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
                    ORDER BY worldwide_collection_crore DESC
                    LIMIT 100;
                """)

            # ==========================================
            # INDUSTRY RANKINGS
            # ==========================================

            else:

                language = industry_language_map.get(industry_key)

                if language:

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
                        WHERE (
                            LOWER(TRIM(COALESCE(industry, ''))) = LOWER(%s)
                            OR LOWER(TRIM(COALESCE(language, ''))) = LOWER(%s)
                        )
                          AND worldwide_collection_crore IS NOT NULL
                          AND worldwide_collection_crore > 0
                        ORDER BY worldwide_collection_crore DESC
                        LIMIT 100;
                    """, (requested_industry, language))

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
                        WHERE LOWER(TRIM(COALESCE(industry, ''))) = LOWER(%s)
                          AND worldwide_collection_crore IS NOT NULL
                          AND worldwide_collection_crore > 0
                        ORDER BY worldwide_collection_crore DESC
                        LIMIT 100;
                    """, (requested_industry,))

            rows = cur.fetchall()

    rankings = []

    for position, row in enumerate(rows, start=1):

        rankings.append({
            "rank": position,
            "id": row[0],
            "title": row[1],
            "language": row[2],
            "industry": row[3],
            "release_date": str(row[4]) if row[4] else None,
            "worldwide_collection": float(row[5] or 0),
            "verdict": row[6],
            "poster": safe_movie_poster(row[7])
        })

    return {
        "industry": requested_industry,
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



class BulkMovieCollectionDay(BaseModel):
    date: date
    tamil_nadu: float = 0
    kerala: float = 0
    karnataka: float = 0
    telugu_states: float = 0
    rest_of_india: float = 0
    overseas: float = 0


class BulkMovieCollectionSync(BaseModel):
    movie_id: int
    days: list[BulkMovieCollectionDay]


@app.post("/admin/movie-collections/bulk-sync", dependencies=[Depends(require_admin)])
def admin_bulk_sync_movie_collections(data: BulkMovieCollectionSync):
    """Replace one movie's daily territory rows in one DB transaction."""
    territories = (
        ("Tamil Nadu", "tamil_nadu"),
        ("Kerala", "kerala"),
        ("Karnataka", "karnataka"),
        ("Telugu States", "telugu_states"),
        ("Rest of India", "rest_of_india"),
        ("Overseas", "overseas"),
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM movies WHERE id = %s", (data.movie_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Movie not found")

            cur.execute(
                "DELETE FROM movie_daily_collections WHERE movie_id = %s",
                (data.movie_id,)
            )

            rows = []
            india_total = 0.0
            overseas_total = 0.0

            for day in data.days:
                for state, field in territories:
                    amount = float(getattr(day, field) or 0)
                    rows.append((data.movie_id, day.date, state, amount))
                    if state == "Overseas":
                        overseas_total += amount
                    else:
                        india_total += amount

            if rows:
                cur.executemany("""
                    INSERT INTO movie_daily_collections
                        (movie_id, collection_date, state, collection_crore)
                    VALUES (%s, %s, %s, %s)
                """, rows)

            worldwide_total = india_total + overseas_total
            cur.execute("""
                UPDATE movies
                SET india_collection_crore = %s,
                    overseas_collection_crore = %s,
                    worldwide_collection_crore = %s
                WHERE id = %s
            """, (
                india_total,
                overseas_total,
                worldwide_total,
                data.movie_id
            ))

        conn.commit()

    return {
        "success": True,
        "movie_id": data.movie_id,
        "days_saved": len(data.days),
        "rows_saved": len(rows),
        "india_collection_crore": round(india_total, 2),
        "overseas_collection_crore": round(overseas_total, 2),
        "worldwide_collection_crore": round(worldwide_total, 2),
    }


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
    with get_connection() as conn:
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



# ============================================================
# TRENDING ARTICLES
# Recent 7-day reader activity ranking
# IMPORTANT: KEEP BEFORE /articles/{article_id}/... routes
# ============================================================

@app.get("/articles/trending")
def trending_articles(limit: int = 10):
    limit = max(1, min(int(limit or 10), 50))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                WITH article_activity AS (
                    SELECT
                        a.id,
                        a.title,
                        a.slug,
                        a.subtitle,
                        a.category,
                        a.author,
                        a.hero_image,
                        a.published_at,

                        (
                            SELECT COUNT(*)
                            FROM article_views v
                            WHERE v.article_id = a.id
                              AND v.viewed_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS view_count,

                        (
                            SELECT COUNT(*)
                            FROM article_likes l
                            WHERE l.article_id = a.id
                              AND l.created_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS like_count,

                        (
                            SELECT COUNT(*)
                            FROM article_hype h
                            WHERE h.article_id = a.id
                              AND h.created_at >= NOW() - INTERVAL '7 days'
                        )::bigint AS hype_count,

                        (
                            SELECT COUNT(*)
                            FROM article_comments c
                            WHERE c.article_id = a.id
                              AND c.created_at >= NOW() - INTERVAL '7 days'
                              AND c.is_hidden = FALSE
                              AND c.is_deleted = FALSE
                        )::bigint AS comment_count

                    FROM articles a
                    WHERE a.status = 'published'
                ),
                ranked AS (
                    SELECT
                        *,
                        (
                            view_count
                            + (like_count * 2)
                            + (hype_count * 3)
                            + (comment_count * 3)
                        )::bigint AS trending_score
                    FROM article_activity
                )
                SELECT
                    id,
                    title,
                    slug,
                    subtitle,
                    category,
                    author,
                    hero_image,
                    published_at,
                    view_count,
                    like_count,
                    hype_count,
                    comment_count,
                    trending_score
                FROM ranked
                WHERE trending_score > 0
                ORDER BY
                    trending_score DESC,
                    hype_count DESC,
                    view_count DESC,
                    published_at DESC NULLS LAST,
                    id DESC
                LIMIT %s
            """, (limit,))

            rows = cur.fetchall()

    articles = []

    for position, row in enumerate(rows, start=1):
        articles.append({
            "rank": position,
            "id": row[0],
            "title": row[1],
            "slug": row[2],
            "subtitle": row[3],
            "category": row[4],
            "author": row[5],
            "hero_image": row[6],
            "published_at": row[7].isoformat() if row[7] else None,
            "view_count": int(row[8] or 0),
            "like_count": int(row[9] or 0),
            "hype_count": int(row[10] or 0),
            "comment_count": int(row[11] or 0),
            "trending_score": int(row[12] or 0),
            "url": f"/article/{row[2]}",
        })

    return {
        "period_days": 7,
        "articles": articles,
    }


@app.get("/articles/latest")
def get_latest_articles(limit: int = 10):
    limit=max(1,min(limit,50))
    with get_connection() as conn:
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
    with get_connection() as conn:
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
    with get_connection() as conn:
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
    with get_connection() as conn:
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
    with get_connection() as conn:
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



# ============================================================
# ARTICLE EDITOR -> CENTRAL MOVIE BOX OFFICE SYNC
# ============================================================

class ArticleMovieBoxOfficeDay(BaseModel):
    date: date
    tamil_nadu: float = 0
    kerala: float = 0
    karnataka: float = 0
    telugu_states: float = 0
    rest_of_india: float = 0
    overseas: float = 0


class ArticleMovieBoxOfficeSync(BaseModel):
    movie_id: int
    budget: Optional[float] = None
    verdict: Optional[str] = None
    days: list[ArticleMovieBoxOfficeDay] = []


@app.post(
    "/admin/articles/movie-boxoffice-sync",
    dependencies=[Depends(require_admin)]
)
def admin_article_sync_movie_boxoffice(
    data: ArticleMovieBoxOfficeSync
):
    """
    Article Admin is the editing surface, while movie_daily_collections
    remains the single source of truth used by movie.html and articles.
    """

    territory_fields = (
        ("Tamil Nadu", "tamil_nadu"),
        ("Kerala", "kerala"),
        ("Karnataka", "karnataka"),
        ("Telugu States", "telugu_states"),
        ("Rest of India", "rest_of_india"),
        ("Overseas", "overseas"),
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id
                FROM movies
                WHERE id = %s
            """, (data.movie_id,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Linked movie not found"
                )

            # The Article Box Office block becomes authoritative for this movie.
            # Removing a day from the block also removes that day's old DB rows.
            cur.execute("""
                DELETE FROM movie_daily_collections
                WHERE movie_id = %s
            """, (data.movie_id,))

            india_total = 0.0
            overseas_total = 0.0

            for day in data.days:
                for territory, field_name in territory_fields:
                    amount = float(getattr(day, field_name) or 0)

                    cur.execute("""
                        INSERT INTO movie_daily_collections (
                            movie_id,
                            collection_date,
                            state,
                            collection_crore
                        )
                        VALUES (%s, %s, %s, %s)
                    """, (
                        data.movie_id,
                        day.date,
                        territory,
                        amount
                    ))

                    if territory == "Overseas":
                        overseas_total += amount
                    else:
                        india_total += amount

            worldwide_total = india_total + overseas_total

            cur.execute("""
                UPDATE movies
                SET
                    budget_crore = COALESCE(%s, budget_crore),
                    verdict = COALESCE(NULLIF(%s, ''), verdict),
                    india_collection_crore = %s,
                    overseas_collection_crore = %s,
                    worldwide_collection_crore = %s
                WHERE id = %s
            """, (
                data.budget,
                (data.verdict or "").strip(),
                india_total,
                overseas_total,
                worldwide_total,
                data.movie_id
            ))

        conn.commit()

    return {
        "success": True,
        "movie_id": data.movie_id,
        "days_saved": len(data.days),
        "india_collection_crore": round(india_total, 2),
        "overseas_collection_crore": round(overseas_total, 2),
        "worldwide_collection_crore": round(worldwide_total, 2),
    }


# Public normalized collection feed used by linked Article movie blocks.
@app.get("/movies/{movie_id}/collections")
def get_movie_collections_for_articles(movie_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, release_date, poster
                FROM movies
                WHERE id = %s
            """, (movie_id,))
            movie = cur.fetchone()

            if not movie:
                raise HTTPException(
                    status_code=404,
                    detail="Movie not found"
                )

            cur.execute("""
                SELECT
                    collection_date,
                    state,
                    collection_crore
                FROM movie_daily_collections
                WHERE movie_id = %s
                ORDER BY collection_date ASC, state ASC
            """, (movie_id,))
            rows = cur.fetchall()

    by_date = {}

    for collection_date, state, amount in rows:
        key = collection_date
        if key not in by_date:
            by_date[key] = {
                "Tamil Nadu": 0.0,
                "Kerala": 0.0,
                "Karnataka": 0.0,
                "Telugu States": 0.0,
                "Rest of India": 0.0,
                "Overseas": 0.0,
            }

        normalized_state = (state or "").strip()

        # Compatibility with any older Andhra/Telangana rows.
        if normalized_state in {"Andhra Pradesh", "Telangana"}:
            normalized_state = "Telugu States"

        if normalized_state in by_date[key]:
            by_date[key][normalized_state] += float(amount or 0)

    collections = []
    cumulative = {
        "Tamil Nadu": 0.0,
        "Kerala": 0.0,
        "Karnataka": 0.0,
        "Telugu States": 0.0,
        "Rest of India": 0.0,
        "Overseas": 0.0,
    }

    for index, collection_date in enumerate(sorted(by_date.keys()), start=1):
        values = by_date[collection_date]

        india = (
            values["Tamil Nadu"]
            + values["Kerala"]
            + values["Karnataka"]
            + values["Telugu States"]
            + values["Rest of India"]
        )
        worldwide = india + values["Overseas"]

        for territory in cumulative:
            cumulative[territory] += values[territory]

        cumulative_india = (
            cumulative["Tamil Nadu"]
            + cumulative["Kerala"]
            + cumulative["Karnataka"]
            + cumulative["Telugu States"]
            + cumulative["Rest of India"]
        )
        cumulative_worldwide = (
            cumulative_india
            + cumulative["Overseas"]
        )

        collections.append({
            "day_number": index,
            "collection_date": str(collection_date),
            "Tamil Nadu": round(values["Tamil Nadu"], 2),
            "Kerala": round(values["Kerala"], 2),
            "Karnataka": round(values["Karnataka"], 2),
            "Telugu States": round(values["Telugu States"], 2),
            "Rest of India": round(values["Rest of India"], 2),
            "India Total": round(india, 2),
            "Overseas": round(values["Overseas"], 2),
            "Worldwide Total": round(worldwide, 2),
            "cumulative": {
                "Tamil Nadu": round(cumulative["Tamil Nadu"], 2),
                "Kerala": round(cumulative["Kerala"], 2),
                "Karnataka": round(cumulative["Karnataka"], 2),
                "Telugu States": round(cumulative["Telugu States"], 2),
                "Rest of India": round(cumulative["Rest of India"], 2),
                "India Total": round(cumulative_india, 2),
                "Overseas": round(cumulative["Overseas"], 2),
                "Worldwide Total": round(cumulative_worldwide, 2),
            }
        })

    final_total = collections[-1]["cumulative"] if collections else {}

    return {
        "movie": {
            "id": movie[0],
            "title": movie[1],
            "release_date": str(movie[2]) if movie[2] else None,
            "poster": movie[3],
        },
        "collections": collections,
        "final_total": final_total,
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



# ============================================================
# BOXOFFICEX FAN ENGAGEMENT API - V1
# Movie Fans + Hype + Fan Verdict + Comments + Comment Likes
# ============================================================

class VisitorActionData(BaseModel):
    visitor_id: str


class FanVoteData(BaseModel):
    visitor_id: str
    verdict: Literal["Blockbuster", "Hit", "Average", "Flop"]


class MovieCommentCreateData(BaseModel):
    visitor_id: str
    display_name: str
    comment_text: str


class CommentReportData(BaseModel):
    visitor_id: str
    reason: Optional[str] = None


def _clean_visitor_id(visitor_id: str) -> str:
    value = (visitor_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", value):
        raise HTTPException(status_code=400, detail="Invalid visitor ID")
    return value


def _clean_public_text(value: str, field: str, min_len: int, max_len: int) -> str:
    value = re.sub(r"\s+", " ", (value or "").strip())
    if len(value) < min_len or len(value) > max_len:
        raise HTTPException(
            status_code=400,
            detail=f"{field} must be between {min_len} and {max_len} characters"
        )
    if any(ord(ch) < 32 for ch in value):
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    return value


def _ensure_movie_exists(cur, movie_id: int):
    cur.execute("SELECT 1 FROM movies WHERE id = %s", (movie_id,))
    if not cur.fetchone():
        raise HTTPException(status_code=404, detail="Movie not found")


def _movie_engagement_summary(cur, movie_id: int, visitor_id: Optional[str] = None):
    cur.execute("SELECT COUNT(*) FROM movie_fans WHERE movie_id = %s", (movie_id,))
    fan_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM movie_hype WHERE movie_id = %s", (movie_id,))
    hype_count = cur.fetchone()[0]

    cur.execute("""
        SELECT verdict, COUNT(*)
        FROM movie_fan_votes
        WHERE movie_id = %s
        GROUP BY verdict
    """, (movie_id,))
    vote_counts = {"Blockbuster": 0, "Hit": 0, "Average": 0, "Flop": 0}
    for verdict, count in cur.fetchall():
        if verdict in vote_counts:
            vote_counts[verdict] = count

    total_votes = sum(vote_counts.values())
    percentages = {
        key: round((value / total_votes) * 100, 1) if total_votes else 0
        for key, value in vote_counts.items()
    }

    is_fan = False
    is_hyped = False
    my_vote = None

    if visitor_id:
        cur.execute(
            "SELECT 1 FROM movie_fans WHERE movie_id = %s AND visitor_id = %s",
            (movie_id, visitor_id)
        )
        is_fan = bool(cur.fetchone())

        cur.execute(
            "SELECT 1 FROM movie_hype WHERE movie_id = %s AND visitor_id = %s",
            (movie_id, visitor_id)
        )
        is_hyped = bool(cur.fetchone())

        cur.execute(
            "SELECT verdict FROM movie_fan_votes WHERE movie_id = %s AND visitor_id = %s",
            (movie_id, visitor_id)
        )
        row = cur.fetchone()
        my_vote = row[0] if row else None

    return {
        "movie_id": movie_id,
        "fan_count": fan_count,
        "hype_count": hype_count,
        "is_fan": is_fan,
        "is_hyped": is_hyped,
        "fan_verdict": {
            "total_votes": total_votes,
            "counts": vote_counts,
            "percentages": percentages,
            "my_vote": my_vote,
        },
    }


@app.get("/movies/{movie_id}/engagement")
def get_movie_engagement(movie_id: int, visitor_id: Optional[str] = None):
    clean_visitor = _clean_visitor_id(visitor_id) if visitor_id else None
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_exists(cur, movie_id)
            return _movie_engagement_summary(cur, movie_id, clean_visitor)


@app.post("/movies/{movie_id}/fan")
def toggle_movie_fan(movie_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_exists(cur, movie_id)
            cur.execute(
                "DELETE FROM movie_fans WHERE movie_id = %s AND visitor_id = %s RETURNING id",
                (movie_id, visitor_id)
            )
            removed = cur.fetchone()
            if removed:
                active = False
            else:
                cur.execute(
                    "INSERT INTO movie_fans (movie_id, visitor_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (movie_id, visitor_id)
                )
                active = True
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM movie_fans WHERE movie_id = %s", (movie_id,))
            count = cur.fetchone()[0]
    return {"success": True, "active": active, "fan_count": count}


@app.post("/movies/{movie_id}/hype")
def toggle_movie_hype(movie_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_exists(cur, movie_id)
            cur.execute(
                "DELETE FROM movie_hype WHERE movie_id = %s AND visitor_id = %s RETURNING id",
                (movie_id, visitor_id)
            )
            removed = cur.fetchone()
            if removed:
                active = False
            else:
                cur.execute(
                    "INSERT INTO movie_hype (movie_id, visitor_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (movie_id, visitor_id)
                )
                active = True
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM movie_hype WHERE movie_id = %s", (movie_id,))
            count = cur.fetchone()[0]
    return {"success": True, "active": active, "hype_count": count}


@app.post("/movies/{movie_id}/fan-vote")
def set_movie_fan_vote(movie_id: int, data: FanVoteData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_exists(cur, movie_id)
            cur.execute("""
                INSERT INTO movie_fan_votes (movie_id, visitor_id, verdict)
                VALUES (%s, %s, %s)
                ON CONFLICT (movie_id, visitor_id)
                DO UPDATE SET verdict = EXCLUDED.verdict, updated_at = NOW()
            """, (movie_id, visitor_id, data.verdict))
            conn.commit()
            return _movie_engagement_summary(cur, movie_id, visitor_id)


@app.get("/movies/{movie_id}/comments")
def get_movie_comments(
    movie_id: int,
    visitor_id: Optional[str] = None,
    sort: Literal["newest", "top"] = "newest",
    limit: int = 30,
    offset: int = 0
):
    clean_visitor = _clean_visitor_id(visitor_id) if visitor_id else None
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    order_sql = "like_count DESC, c.created_at DESC" if sort == "top" else "c.created_at DESC"

    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_exists(cur, movie_id)
            cur.execute(f"""
                SELECT
                    c.id,
                    c.display_name,
                    c.comment_text,
                    c.created_at,
                    COUNT(l.id) AS like_count,
                    EXISTS (
                        SELECT 1
                        FROM movie_comment_likes mine
                        WHERE mine.comment_id = c.id
                          AND mine.visitor_id = %s
                    ) AS liked_by_me,
                    (c.visitor_id = %s) AS is_owner
                FROM movie_comments c
                LEFT JOIN movie_comment_likes l ON l.comment_id = c.id
                WHERE c.movie_id = %s
                  AND c.is_hidden = FALSE
                  AND c.is_deleted = FALSE
                GROUP BY c.id
                ORDER BY {order_sql}
                LIMIT %s OFFSET %s
            """, (clean_visitor or "", clean_visitor or "", movie_id, limit, offset))
            rows = cur.fetchall()

            cur.execute("""
                SELECT COUNT(*)
                FROM movie_comments
                WHERE movie_id = %s
                  AND is_hidden = FALSE
                  AND is_deleted = FALSE
            """, (movie_id,))
            total = cur.fetchone()[0]

    return {
        "movie_id": movie_id,
        "total": total,
        "comments": [
            {
                "id": row[0],
                "display_name": row[1],
                "comment_text": row[2],
                "created_at": row[3].isoformat() if row[3] else None,
                "like_count": row[4],
                "liked_by_me": row[5],
                "is_owner": row[6],
            }
            for row in rows
        ],
    }


@app.post("/movies/{movie_id}/comments")
def post_movie_comment(movie_id: int, data: MovieCommentCreateData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    display_name = _clean_public_text(data.display_name, "Display name", 2, 50)
    comment_text = _clean_public_text(data.comment_text, "Comment", 2, 1000)

    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_exists(cur, movie_id)

            # Simple server-side anti-spam cooldown for V1.
            cur.execute("""
                SELECT created_at
                FROM movie_comments
                WHERE movie_id = %s
                  AND visitor_id = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, (movie_id, visitor_id))
            recent = cur.fetchone()
            if recent and (datetime.now(timezone.utc) - recent[0]).total_seconds() < 30:
                raise HTTPException(
                    status_code=429,
                    detail="Please wait 30 seconds before posting another comment"
                )

            cur.execute("""
                INSERT INTO movie_comments (
                    movie_id, visitor_id, display_name, comment_text
                )
                VALUES (%s, %s, %s, %s)
                RETURNING id, created_at
            """, (movie_id, visitor_id, display_name, comment_text))
            row = cur.fetchone()
            conn.commit()

    return {
        "success": True,
        "comment": {
            "id": row[0],
            "display_name": display_name,
            "comment_text": comment_text,
            "created_at": row[1].isoformat() if row[1] else None,
            "like_count": 0,
            "liked_by_me": False,
            "is_owner": True,
        },
    }


# ============================================================
# OWNER COMMENT MODERATION
# ============================================================

@app.get("/admin/comments", dependencies=[Depends(require_owner)])
def admin_list_movie_comments(
    status: Literal["all", "reported", "visible", "hidden"] = "all",
    limit: int = 100,
    offset: int = 0,
):
    limit = max(1, min(limit, 250))
    offset = max(0, offset)

    where = ["c.is_deleted = FALSE"]
    if status == "reported":
        where.append("EXISTS (SELECT 1 FROM movie_comment_reports rr WHERE rr.comment_id = c.id)")
    elif status == "visible":
        where.append("c.is_hidden = FALSE")
    elif status == "hidden":
        where.append("c.is_hidden = TRUE")

    where_sql = " AND ".join(where)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT
                    c.id,
                    c.movie_id,
                    m.title,
                    c.display_name,
                    c.comment_text,
                    c.is_hidden,
                    c.created_at,
                    COUNT(DISTINCT l.id) AS like_count,
                    COUNT(DISTINCT r.id) AS report_count
                FROM movie_comments c
                JOIN movies m ON m.id = c.movie_id
                LEFT JOIN movie_comment_likes l ON l.comment_id = c.id
                LEFT JOIN movie_comment_reports r ON r.comment_id = c.id
                WHERE {where_sql}
                GROUP BY c.id, c.movie_id, m.title
                ORDER BY
                    COUNT(DISTINCT r.id) DESC,
                    c.created_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            rows = cur.fetchall()

            cur.execute(f"""
                SELECT COUNT(*)
                FROM movie_comments c
                WHERE {where_sql}
            """)
            total = cur.fetchone()[0]

            cur.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE is_deleted = FALSE),
                    COUNT(*) FILTER (WHERE is_deleted = FALSE AND is_hidden = TRUE),
                    COUNT(DISTINCT r.comment_id)
                FROM movie_comments c
                LEFT JOIN movie_comment_reports r ON r.comment_id = c.id
            """)
            summary = cur.fetchone()

    return {
        "total": total,
        "summary": {
            "comments": summary[0] or 0,
            "hidden": summary[1] or 0,
            "reported": summary[2] or 0,
        },
        "comments": [
            {
                "id": row[0],
                "movie_id": row[1],
                "movie_title": row[2],
                "display_name": row[3],
                "comment_text": row[4],
                "is_hidden": row[5],
                "created_at": row[6].isoformat() if row[6] else None,
                "like_count": row[7] or 0,
                "report_count": row[8] or 0,
            }
            for row in rows
        ],
    }


@app.put("/admin/comments/{comment_id}/visibility", dependencies=[Depends(require_owner)])
def admin_toggle_comment_visibility(comment_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE movie_comments
                SET is_hidden = NOT is_hidden, updated_at = NOW()
                WHERE id = %s
                  AND is_deleted = FALSE
                RETURNING is_hidden
            """, (comment_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Comment not found")
            conn.commit()

    return {"success": True, "comment_id": comment_id, "is_hidden": row[0]}


@app.delete("/admin/comments/{comment_id}", dependencies=[Depends(require_owner)])
def admin_delete_movie_comment(comment_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE movie_comments
                SET is_deleted = TRUE, is_hidden = TRUE, updated_at = NOW()
                WHERE id = %s
                  AND is_deleted = FALSE
                RETURNING id
            """, (comment_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Comment not found")
            conn.commit()

    return {"success": True, "deleted": True, "comment_id": comment_id}


@app.delete("/comments/{comment_id}")
def delete_movie_comment(comment_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE movie_comments
                SET is_deleted = TRUE, updated_at = NOW()
                WHERE id = %s
                  AND visitor_id = %s
                  AND is_deleted = FALSE
                RETURNING id
            """, (comment_id, visitor_id))
            deleted = cur.fetchone()

            if not deleted:
                cur.execute("SELECT visitor_id, is_deleted FROM movie_comments WHERE id = %s", (comment_id,))
                row = cur.fetchone()
                if not row or row[1]:
                    raise HTTPException(status_code=404, detail="Comment not found")
                raise HTTPException(status_code=403, detail="You can delete only your own comment")

            conn.commit()

    return {"success": True, "deleted": True, "comment_id": comment_id}


@app.post("/comments/{comment_id}/like")
def toggle_movie_comment_like(comment_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM movie_comments
                WHERE id = %s
                  AND is_hidden = FALSE
                  AND is_deleted = FALSE
            """, (comment_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Comment not found")

            cur.execute(
                "DELETE FROM movie_comment_likes WHERE comment_id = %s AND visitor_id = %s RETURNING id",
                (comment_id, visitor_id)
            )
            removed = cur.fetchone()
            if removed:
                active = False
            else:
                cur.execute(
                    "INSERT INTO movie_comment_likes (comment_id, visitor_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (comment_id, visitor_id)
                )
                active = True
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM movie_comment_likes WHERE comment_id = %s", (comment_id,))
            count = cur.fetchone()[0]

    return {"success": True, "active": active, "like_count": count}


@app.post("/comments/{comment_id}/report")
def report_movie_comment(comment_id: int, data: CommentReportData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    reason = (data.reason or "Other").strip()
    if len(reason) > 100:
        raise HTTPException(status_code=400, detail="Report reason is too long")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM movie_comments
                WHERE id = %s
                  AND is_deleted = FALSE
            """, (comment_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Comment not found")

            cur.execute("""
                INSERT INTO movie_comment_reports (comment_id, visitor_id, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (comment_id, visitor_id) DO NOTHING
            """, (comment_id, visitor_id, reason))
            created = cur.rowcount > 0
            conn.commit()

    return {
        "success": True,
        "reported": True,
        "new_report": created,
        "message": "Comment reported for review"
    }

# ============================================================
# HERO COMPARISON FAN ENGAGEMENT
# ============================================================

class HeroComparisonVoteData(BaseModel):
    visitor_id: str
    choice: Literal["hero1", "tie", "hero2"]


class HeroComparisonCommentCreateData(BaseModel):
    visitor_id: str
    display_name: str
    comment_text: str


def _hero_comparison_pair(actor1_id: int, actor2_id: int):
    if actor1_id == actor2_id:
        raise HTTPException(status_code=400, detail="Choose two different actors")
    return tuple(sorted((int(actor1_id), int(actor2_id))))


def _ensure_hero_comparison_exists(cur, actor1_id: int, actor2_id: int):
    actor1_id, actor2_id = _hero_comparison_pair(actor1_id, actor2_id)
    cur.execute("SELECT id FROM actors WHERE id IN (%s, %s)", (actor1_id, actor2_id))
    found = {row[0] for row in cur.fetchall()}
    if actor1_id not in found or actor2_id not in found:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor1_id, actor2_id


def _hero_comparison_summary(cur, actor1_id: int, actor2_id: int, visitor_id: Optional[str] = None):
    actor1_id, actor2_id = _ensure_hero_comparison_exists(cur, actor1_id, actor2_id)
    cur.execute("SELECT COUNT(*) FROM hero_comparison_likes WHERE actor1_id=%s AND actor2_id=%s", (actor1_id, actor2_id))
    like_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM hero_comparison_hype WHERE actor1_id=%s AND actor2_id=%s", (actor1_id, actor2_id))
    hype_count = cur.fetchone()[0]
    cur.execute("SELECT choice, COUNT(*) FROM hero_comparison_votes WHERE actor1_id=%s AND actor2_id=%s GROUP BY choice", (actor1_id, actor2_id))
    counts = {"hero1": 0, "tie": 0, "hero2": 0}
    for choice, count in cur.fetchall():
        if choice in counts:
            counts[choice] = count
    total = sum(counts.values())
    percentages = {k: round(v * 100 / total, 1) if total else 0 for k, v in counts.items()}
    liked = hyped = False
    my_vote = None
    if visitor_id:
        cur.execute("SELECT 1 FROM hero_comparison_likes WHERE actor1_id=%s AND actor2_id=%s AND visitor_id=%s", (actor1_id, actor2_id, visitor_id))
        liked = bool(cur.fetchone())
        cur.execute("SELECT 1 FROM hero_comparison_hype WHERE actor1_id=%s AND actor2_id=%s AND visitor_id=%s", (actor1_id, actor2_id, visitor_id))
        hyped = bool(cur.fetchone())
        cur.execute("SELECT choice FROM hero_comparison_votes WHERE actor1_id=%s AND actor2_id=%s AND visitor_id=%s", (actor1_id, actor2_id, visitor_id))
        row = cur.fetchone()
        my_vote = row[0] if row else None
    return {"actor1_id": actor1_id, "actor2_id": actor2_id, "like_count": like_count, "hype_count": hype_count,
            "liked": liked, "hyped": hyped,
            "fan_vote": {"total_votes": total, "counts": counts, "percentages": percentages, "my_vote": my_vote}}


@app.get("/hero-comparisons/{actor1_id}/{actor2_id}/engagement")
def get_hero_comparison_engagement(actor1_id: int, actor2_id: int, visitor_id: Optional[str] = None):
    visitor_id = _clean_visitor_id(visitor_id) if visitor_id else None
    with get_connection() as conn:
        with conn.cursor() as cur:
            return _hero_comparison_summary(cur, actor1_id, actor2_id, visitor_id)


@app.post("/hero-comparisons/{actor1_id}/{actor2_id}/like")
def toggle_hero_comparison_like(actor1_id: int, actor2_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            a1, a2 = _ensure_hero_comparison_exists(cur, actor1_id, actor2_id)
            cur.execute("DELETE FROM hero_comparison_likes WHERE actor1_id=%s AND actor2_id=%s AND visitor_id=%s RETURNING id", (a1, a2, visitor_id))
            active = not bool(cur.fetchone())
            if active:
                cur.execute("INSERT INTO hero_comparison_likes(actor1_id,actor2_id,visitor_id) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING", (a1, a2, visitor_id))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM hero_comparison_likes WHERE actor1_id=%s AND actor2_id=%s", (a1, a2))
            count = cur.fetchone()[0]
    return {"success": True, "active": active, "like_count": count}


@app.post("/hero-comparisons/{actor1_id}/{actor2_id}/hype")
def toggle_hero_comparison_hype(actor1_id: int, actor2_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            a1, a2 = _ensure_hero_comparison_exists(cur, actor1_id, actor2_id)
            cur.execute("DELETE FROM hero_comparison_hype WHERE actor1_id=%s AND actor2_id=%s AND visitor_id=%s RETURNING id", (a1, a2, visitor_id))
            active = not bool(cur.fetchone())
            if active:
                cur.execute("INSERT INTO hero_comparison_hype(actor1_id,actor2_id,visitor_id) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING", (a1, a2, visitor_id))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM hero_comparison_hype WHERE actor1_id=%s AND actor2_id=%s", (a1, a2))
            count = cur.fetchone()[0]
    return {"success": True, "active": active, "hype_count": count}


@app.post("/hero-comparisons/{actor1_id}/{actor2_id}/vote")
def set_hero_comparison_vote(actor1_id: int, actor2_id: int, data: HeroComparisonVoteData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    original1 = int(actor1_id)
    a1, a2 = _hero_comparison_pair(actor1_id, actor2_id)
    choice = data.choice
    reversed_order = original1 != a1
    if reversed_order and choice in {"hero1", "hero2"}:
        choice = "hero2" if choice == "hero1" else "hero1"
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_hero_comparison_exists(cur, a1, a2)
            cur.execute("""INSERT INTO hero_comparison_votes(actor1_id,actor2_id,visitor_id,choice)
                           VALUES(%s,%s,%s,%s)
                           ON CONFLICT(actor1_id,actor2_id,visitor_id)
                           DO UPDATE SET choice=EXCLUDED.choice, updated_at=NOW()""", (a1, a2, visitor_id, choice))
            conn.commit()
            result = _hero_comparison_summary(cur, a1, a2, visitor_id)
    if reversed_order:
        c = result["fan_vote"]["counts"]; p = result["fan_vote"]["percentages"]
        result["fan_vote"]["counts"] = {"hero1": c["hero2"], "tie": c["tie"], "hero2": c["hero1"]}
        result["fan_vote"]["percentages"] = {"hero1": p["hero2"], "tie": p["tie"], "hero2": p["hero1"]}
        if result["fan_vote"]["my_vote"] in {"hero1", "hero2"}:
            result["fan_vote"]["my_vote"] = "hero2" if result["fan_vote"]["my_vote"] == "hero1" else "hero1"
    return result


@app.get("/hero-comparisons/{actor1_id}/{actor2_id}/comments")
def get_hero_comparison_comments(actor1_id: int, actor2_id: int, visitor_id: Optional[str] = None,
                                 sort: Literal["newest", "top"] = "newest", limit: int = 30, offset: int = 0):
    visitor_id = _clean_visitor_id(visitor_id) if visitor_id else None
    limit, offset = max(1, min(limit, 100)), max(0, offset)
    order_sql = "like_count DESC, c.created_at DESC" if sort == "top" else "c.created_at DESC"
    with get_connection() as conn:
        with conn.cursor() as cur:
            a1, a2 = _ensure_hero_comparison_exists(cur, actor1_id, actor2_id)
            cur.execute(f"""SELECT c.id,c.display_name,c.comment_text,c.created_at,COUNT(l.id) AS like_count,
                           EXISTS(SELECT 1 FROM hero_comparison_comment_likes mine WHERE mine.comment_id=c.id AND mine.visitor_id=%s),
                           (c.visitor_id=%s)
                           FROM hero_comparison_comments c
                           LEFT JOIN hero_comparison_comment_likes l ON l.comment_id=c.id
                           WHERE c.actor1_id=%s AND c.actor2_id=%s AND c.is_hidden=FALSE AND c.is_deleted=FALSE
                           GROUP BY c.id ORDER BY {order_sql} LIMIT %s OFFSET %s""",
                        (visitor_id or "", visitor_id or "", a1, a2, limit, offset))
            rows = cur.fetchall()
            cur.execute("SELECT COUNT(*) FROM hero_comparison_comments WHERE actor1_id=%s AND actor2_id=%s AND is_hidden=FALSE AND is_deleted=FALSE", (a1, a2))
            total = cur.fetchone()[0]
    return {"actor1_id": a1, "actor2_id": a2, "total": total,
            "comments": [{"id":r[0],"display_name":r[1],"comment_text":r[2],
                          "created_at":r[3].isoformat() if r[3] else None,"like_count":r[4],
                          "liked_by_me":r[5],"is_owner":r[6]} for r in rows]}


@app.post("/hero-comparisons/{actor1_id}/{actor2_id}/comments")
def post_hero_comparison_comment(actor1_id: int, actor2_id: int, data: HeroComparisonCommentCreateData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    display_name = _clean_public_text(data.display_name, "Display name", 2, 50)
    comment_text = _clean_public_text(data.comment_text, "Comment", 2, 1000)
    with get_connection() as conn:
        with conn.cursor() as cur:
            a1, a2 = _ensure_hero_comparison_exists(cur, actor1_id, actor2_id)
            cur.execute("SELECT created_at FROM hero_comparison_comments WHERE actor1_id=%s AND actor2_id=%s AND visitor_id=%s ORDER BY created_at DESC LIMIT 1", (a1,a2,visitor_id))
            recent = cur.fetchone()
            if recent and (datetime.now(timezone.utc)-recent[0]).total_seconds() < 30:
                raise HTTPException(status_code=429, detail="Please wait 30 seconds before posting another comment")
            cur.execute("""INSERT INTO hero_comparison_comments(actor1_id,actor2_id,visitor_id,display_name,comment_text)
                           VALUES(%s,%s,%s,%s,%s) RETURNING id,created_at""", (a1,a2,visitor_id,display_name,comment_text))
            row = cur.fetchone(); conn.commit()
    return {"success":True,"comment":{"id":row[0],"display_name":display_name,"comment_text":comment_text,
            "created_at":row[1].isoformat() if row[1] else None,"like_count":0,"liked_by_me":False,"is_owner":True}}


@app.delete("/hero-comparison-comments/{comment_id}")
def delete_hero_comparison_comment(comment_id: int, data: VisitorActionData):
    visitor_id = _clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE hero_comparison_comments SET is_deleted=TRUE,updated_at=NOW() WHERE id=%s AND visitor_id=%s AND is_deleted=FALSE RETURNING id", (comment_id,visitor_id))
            deleted=cur.fetchone()
            if not deleted:
                cur.execute("SELECT visitor_id,is_deleted FROM hero_comparison_comments WHERE id=%s",(comment_id,))
                row=cur.fetchone()
                if not row or row[1]: raise HTTPException(status_code=404,detail="Comment not found")
                raise HTTPException(status_code=403,detail="You can delete only your own comment")
            conn.commit()
    return {"success":True,"deleted":True,"comment_id":comment_id}


@app.post("/hero-comparison-comments/{comment_id}/like")
def toggle_hero_comparison_comment_like(comment_id: int, data: VisitorActionData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM hero_comparison_comments WHERE id=%s AND is_hidden=FALSE AND is_deleted=FALSE",(comment_id,))
            if not cur.fetchone(): raise HTTPException(status_code=404,detail="Comment not found")
            cur.execute("DELETE FROM hero_comparison_comment_likes WHERE comment_id=%s AND visitor_id=%s RETURNING id",(comment_id,visitor_id))
            active=not bool(cur.fetchone())
            if active:
                cur.execute("INSERT INTO hero_comparison_comment_likes(comment_id,visitor_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",(comment_id,visitor_id))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM hero_comparison_comment_likes WHERE comment_id=%s",(comment_id,))
            count=cur.fetchone()[0]
    return {"success":True,"active":active,"like_count":count}


@app.post("/hero-comparison-comments/{comment_id}/report")
def report_hero_comparison_comment(comment_id: int, data: CommentReportData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    reason=(data.reason or "Other").strip()
    if len(reason)>100: raise HTTPException(status_code=400,detail="Report reason is too long")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM hero_comparison_comments WHERE id=%s AND is_deleted=FALSE",(comment_id,))
            if not cur.fetchone(): raise HTTPException(status_code=404,detail="Comment not found")
            cur.execute("""INSERT INTO hero_comparison_comment_reports(comment_id,visitor_id,reason)
                           VALUES(%s,%s,%s) ON CONFLICT(comment_id,visitor_id) DO NOTHING""",(comment_id,visitor_id,reason))
            created=cur.rowcount>0; conn.commit()
    return {"success":True,"reported":True,"new_report":created,"message":"Comment reported for review"}

# ============================================================
# MOVIE COMPARISON FAN ENGAGEMENT
# ============================================================

class MovieComparisonVoteData(BaseModel):
    visitor_id: str
    choice: Literal["movie1", "tie", "movie2"]


class MovieComparisonCommentCreateData(BaseModel):
    visitor_id: str
    display_name: str
    comment_text: str


def _movie_comparison_pair(movie1_id: int, movie2_id: int):
    if movie1_id == movie2_id:
        raise HTTPException(status_code=400, detail="Choose two different movies")
    return tuple(sorted((int(movie1_id), int(movie2_id))))


def _ensure_movie_comparison_exists(cur, movie1_id: int, movie2_id: int):
    movie1_id, movie2_id = _movie_comparison_pair(movie1_id, movie2_id)
    cur.execute("SELECT id FROM movies WHERE id IN (%s, %s)", (movie1_id, movie2_id))
    found = {row[0] for row in cur.fetchall()}
    if movie1_id not in found or movie2_id not in found:
        raise HTTPException(status_code=404, detail="Movie not found")
    return movie1_id, movie2_id


def _movie_comparison_summary(cur, movie1_id: int, movie2_id: int, visitor_id: Optional[str] = None):
    movie1_id, movie2_id = _ensure_movie_comparison_exists(cur, movie1_id, movie2_id)

    cur.execute(
        "SELECT COUNT(*) FROM movie_comparison_likes WHERE movie1_id=%s AND movie2_id=%s",
        (movie1_id, movie2_id)
    )
    like_count = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM movie_comparison_hype WHERE movie1_id=%s AND movie2_id=%s",
        (movie1_id, movie2_id)
    )
    hype_count = cur.fetchone()[0]

    cur.execute("""
        SELECT choice, COUNT(*)
        FROM movie_comparison_votes
        WHERE movie1_id=%s AND movie2_id=%s
        GROUP BY choice
    """, (movie1_id, movie2_id))

    counts = {"movie1": 0, "tie": 0, "movie2": 0}
    for choice, count in cur.fetchall():
        if choice in counts:
            counts[choice] = count

    total = sum(counts.values())
    percentages = {
        key: round(value * 100 / total, 1) if total else 0
        for key, value in counts.items()
    }

    liked = False
    hyped = False
    my_vote = None

    if visitor_id:
        cur.execute("""
            SELECT 1
            FROM movie_comparison_likes
            WHERE movie1_id=%s AND movie2_id=%s AND visitor_id=%s
        """, (movie1_id, movie2_id, visitor_id))
        liked = bool(cur.fetchone())

        cur.execute("""
            SELECT 1
            FROM movie_comparison_hype
            WHERE movie1_id=%s AND movie2_id=%s AND visitor_id=%s
        """, (movie1_id, movie2_id, visitor_id))
        hyped = bool(cur.fetchone())

        cur.execute("""
            SELECT choice
            FROM movie_comparison_votes
            WHERE movie1_id=%s AND movie2_id=%s AND visitor_id=%s
        """, (movie1_id, movie2_id, visitor_id))
        row = cur.fetchone()
        my_vote = row[0] if row else None

    return {
        "movie1_id": movie1_id,
        "movie2_id": movie2_id,
        "like_count": like_count,
        "hype_count": hype_count,
        "liked": liked,
        "hyped": hyped,
        "fan_vote": {
            "total_votes": total,
            "counts": counts,
            "percentages": percentages,
            "my_vote": my_vote,
        },
    }


@app.get("/movie-comparisons/{movie1_id}/{movie2_id}/engagement")
def get_movie_comparison_engagement(
    movie1_id: int,
    movie2_id: int,
    visitor_id: Optional[str] = None
):
    visitor_id = _clean_visitor_id(visitor_id) if visitor_id else None

    original1 = int(movie1_id)
    normalized1, normalized2 = _movie_comparison_pair(movie1_id, movie2_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            result = _movie_comparison_summary(
                cur,
                normalized1,
                normalized2,
                visitor_id
            )

    if original1 != normalized1:
        counts = result["fan_vote"]["counts"]
        percentages = result["fan_vote"]["percentages"]

        result["fan_vote"]["counts"] = {
            "movie1": counts["movie2"],
            "tie": counts["tie"],
            "movie2": counts["movie1"],
        }

        result["fan_vote"]["percentages"] = {
            "movie1": percentages["movie2"],
            "tie": percentages["tie"],
            "movie2": percentages["movie1"],
        }

        if result["fan_vote"]["my_vote"] == "movie1":
            result["fan_vote"]["my_vote"] = "movie2"
        elif result["fan_vote"]["my_vote"] == "movie2":
            result["fan_vote"]["my_vote"] = "movie1"

    return result


@app.post("/movie-comparisons/{movie1_id}/{movie2_id}/like")
def toggle_movie_comparison_like(
    movie1_id: int,
    movie2_id: int,
    data: VisitorActionData
):
    visitor_id = _clean_visitor_id(data.visitor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            m1, m2 = _ensure_movie_comparison_exists(cur, movie1_id, movie2_id)

            cur.execute("""
                DELETE FROM movie_comparison_likes
                WHERE movie1_id=%s AND movie2_id=%s AND visitor_id=%s
                RETURNING id
            """, (m1, m2, visitor_id))

            active = not bool(cur.fetchone())

            if active:
                cur.execute("""
                    INSERT INTO movie_comparison_likes (
                        movie1_id, movie2_id, visitor_id
                    )
                    VALUES (%s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (m1, m2, visitor_id))

            conn.commit()

            cur.execute("""
                SELECT COUNT(*)
                FROM movie_comparison_likes
                WHERE movie1_id=%s AND movie2_id=%s
            """, (m1, m2))
            count = cur.fetchone()[0]

    return {
        "success": True,
        "active": active,
        "like_count": count,
    }


@app.post("/movie-comparisons/{movie1_id}/{movie2_id}/hype")
def toggle_movie_comparison_hype(
    movie1_id: int,
    movie2_id: int,
    data: VisitorActionData
):
    visitor_id = _clean_visitor_id(data.visitor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            m1, m2 = _ensure_movie_comparison_exists(cur, movie1_id, movie2_id)

            cur.execute("""
                DELETE FROM movie_comparison_hype
                WHERE movie1_id=%s AND movie2_id=%s AND visitor_id=%s
                RETURNING id
            """, (m1, m2, visitor_id))

            active = not bool(cur.fetchone())

            if active:
                cur.execute("""
                    INSERT INTO movie_comparison_hype (
                        movie1_id, movie2_id, visitor_id
                    )
                    VALUES (%s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (m1, m2, visitor_id))

            conn.commit()

            cur.execute("""
                SELECT COUNT(*)
                FROM movie_comparison_hype
                WHERE movie1_id=%s AND movie2_id=%s
            """, (m1, m2))
            count = cur.fetchone()[0]

    return {
        "success": True,
        "active": active,
        "hype_count": count,
    }


@app.post("/movie-comparisons/{movie1_id}/{movie2_id}/vote")
def set_movie_comparison_vote(
    movie1_id: int,
    movie2_id: int,
    data: MovieComparisonVoteData
):
    visitor_id = _clean_visitor_id(data.visitor_id)

    original1 = int(movie1_id)
    normalized1, normalized2 = _movie_comparison_pair(movie1_id, movie2_id)

    choice = data.choice

    if original1 != normalized1:
        if choice == "movie1":
            choice = "movie2"
        elif choice == "movie2":
            choice = "movie1"

    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_movie_comparison_exists(cur, normalized1, normalized2)

            cur.execute("""
                INSERT INTO movie_comparison_votes (
                    movie1_id, movie2_id, visitor_id, choice
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (movie1_id, movie2_id, visitor_id)
                DO UPDATE SET
                    choice=EXCLUDED.choice,
                    updated_at=NOW()
            """, (
                normalized1,
                normalized2,
                visitor_id,
                choice
            ))

            conn.commit()

            result = _movie_comparison_summary(
                cur,
                normalized1,
                normalized2,
                visitor_id
            )

    if original1 != normalized1:
        counts = result["fan_vote"]["counts"]
        percentages = result["fan_vote"]["percentages"]

        result["fan_vote"]["counts"] = {
            "movie1": counts["movie2"],
            "tie": counts["tie"],
            "movie2": counts["movie1"],
        }

        result["fan_vote"]["percentages"] = {
            "movie1": percentages["movie2"],
            "tie": percentages["tie"],
            "movie2": percentages["movie1"],
        }

        if result["fan_vote"]["my_vote"] == "movie1":
            result["fan_vote"]["my_vote"] = "movie2"
        elif result["fan_vote"]["my_vote"] == "movie2":
            result["fan_vote"]["my_vote"] = "movie1"

    return result


@app.get("/movie-comparisons/{movie1_id}/{movie2_id}/comments")
def get_movie_comparison_comments(
    movie1_id: int,
    movie2_id: int,
    visitor_id: Optional[str] = None,
    sort: Literal["newest", "top"] = "newest",
    limit: int = 30,
    offset: int = 0
):
    visitor_id = _clean_visitor_id(visitor_id) if visitor_id else None
    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    order_sql = (
        "like_count DESC, c.created_at DESC"
        if sort == "top"
        else "c.created_at DESC"
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            m1, m2 = _ensure_movie_comparison_exists(cur, movie1_id, movie2_id)

            cur.execute(f"""
                SELECT
                    c.id,
                    c.display_name,
                    c.comment_text,
                    c.created_at,
                    COUNT(l.id) AS like_count,
                    EXISTS (
                        SELECT 1
                        FROM movie_comparison_comment_likes mine
                        WHERE mine.comment_id=c.id
                          AND mine.visitor_id=%s
                    ) AS liked_by_me,
                    (c.visitor_id=%s) AS is_owner
                FROM movie_comparison_comments c
                LEFT JOIN movie_comparison_comment_likes l
                  ON l.comment_id=c.id
                WHERE c.movie1_id=%s
                  AND c.movie2_id=%s
                  AND c.is_hidden=FALSE
                  AND c.is_deleted=FALSE
                GROUP BY c.id
                ORDER BY {order_sql}
                LIMIT %s OFFSET %s
            """, (
                visitor_id or "",
                visitor_id or "",
                m1,
                m2,
                limit,
                offset
            ))

            rows = cur.fetchall()

            cur.execute("""
                SELECT COUNT(*)
                FROM movie_comparison_comments
                WHERE movie1_id=%s
                  AND movie2_id=%s
                  AND is_hidden=FALSE
                  AND is_deleted=FALSE
            """, (m1, m2))

            total = cur.fetchone()[0]

    return {
        "movie1_id": m1,
        "movie2_id": m2,
        "total": total,
        "comments": [
            {
                "id": row[0],
                "display_name": row[1],
                "comment_text": row[2],
                "created_at": row[3].isoformat() if row[3] else None,
                "like_count": row[4],
                "liked_by_me": row[5],
                "is_owner": row[6],
            }
            for row in rows
        ],
    }


@app.post("/movie-comparisons/{movie1_id}/{movie2_id}/comments")
def post_movie_comparison_comment(
    movie1_id: int,
    movie2_id: int,
    data: MovieComparisonCommentCreateData
):
    visitor_id = _clean_visitor_id(data.visitor_id)
    display_name = _clean_public_text(
        data.display_name,
        "Display name",
        2,
        50
    )
    comment_text = _clean_public_text(
        data.comment_text,
        "Comment",
        2,
        1000
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            m1, m2 = _ensure_movie_comparison_exists(cur, movie1_id, movie2_id)

            cur.execute("""
                SELECT created_at
                FROM movie_comparison_comments
                WHERE movie1_id=%s
                  AND movie2_id=%s
                  AND visitor_id=%s
                ORDER BY created_at DESC
                LIMIT 1
            """, (m1, m2, visitor_id))

            recent = cur.fetchone()

            if (
                recent
                and (
                    datetime.now(timezone.utc) - recent[0]
                ).total_seconds() < 30
            ):
                raise HTTPException(
                    status_code=429,
                    detail="Please wait 30 seconds before posting another comment"
                )

            cur.execute("""
                INSERT INTO movie_comparison_comments (
                    movie1_id,
                    movie2_id,
                    visitor_id,
                    display_name,
                    comment_text
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, created_at
            """, (
                m1,
                m2,
                visitor_id,
                display_name,
                comment_text
            ))

            row = cur.fetchone()
            conn.commit()

    return {
        "success": True,
        "comment": {
            "id": row[0],
            "display_name": display_name,
            "comment_text": comment_text,
            "created_at": row[1].isoformat() if row[1] else None,
            "like_count": 0,
            "liked_by_me": False,
            "is_owner": True,
        },
    }


@app.delete("/movie-comparison-comments/{comment_id}")
def delete_movie_comparison_comment(
    comment_id: int,
    data: VisitorActionData
):
    visitor_id = _clean_visitor_id(data.visitor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE movie_comparison_comments
                SET
                    is_deleted=TRUE,
                    updated_at=NOW()
                WHERE id=%s
                  AND visitor_id=%s
                  AND is_deleted=FALSE
                RETURNING id
            """, (comment_id, visitor_id))

            deleted = cur.fetchone()

            if not deleted:
                cur.execute("""
                    SELECT visitor_id, is_deleted
                    FROM movie_comparison_comments
                    WHERE id=%s
                """, (comment_id,))

                row = cur.fetchone()

                if not row or row[1]:
                    raise HTTPException(
                        status_code=404,
                        detail="Comment not found"
                    )

                raise HTTPException(
                    status_code=403,
                    detail="You can delete only your own comment"
                )

            conn.commit()

    return {
        "success": True,
        "deleted": True,
        "comment_id": comment_id,
    }


@app.post("/movie-comparison-comments/{comment_id}/like")
def toggle_movie_comparison_comment_like(
    comment_id: int,
    data: VisitorActionData
):
    visitor_id = _clean_visitor_id(data.visitor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM movie_comparison_comments
                WHERE id=%s
                  AND is_hidden=FALSE
                  AND is_deleted=FALSE
            """, (comment_id,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Comment not found"
                )

            cur.execute("""
                DELETE FROM movie_comparison_comment_likes
                WHERE comment_id=%s
                  AND visitor_id=%s
                RETURNING id
            """, (comment_id, visitor_id))

            active = not bool(cur.fetchone())

            if active:
                cur.execute("""
                    INSERT INTO movie_comparison_comment_likes (
                        comment_id,
                        visitor_id
                    )
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                """, (comment_id, visitor_id))

            conn.commit()

            cur.execute("""
                SELECT COUNT(*)
                FROM movie_comparison_comment_likes
                WHERE comment_id=%s
            """, (comment_id,))

            count = cur.fetchone()[0]

    return {
        "success": True,
        "active": active,
        "like_count": count,
    }


@app.post("/movie-comparison-comments/{comment_id}/report")
def report_movie_comparison_comment(
    comment_id: int,
    data: CommentReportData
):
    visitor_id = _clean_visitor_id(data.visitor_id)

    reason = (data.reason or "Other").strip()

    if len(reason) > 100:
        raise HTTPException(
            status_code=400,
            detail="Report reason is too long"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 1
                FROM movie_comparison_comments
                WHERE id=%s
                  AND is_deleted=FALSE
            """, (comment_id,))

            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Comment not found"
                )

            cur.execute("""
                INSERT INTO movie_comparison_comment_reports (
                    comment_id,
                    visitor_id,
                    reason
                )
                VALUES (%s, %s, %s)
                ON CONFLICT (comment_id, visitor_id)
                DO NOTHING
            """, (
                comment_id,
                visitor_id,
                reason
            ))

            created = cur.rowcount > 0
            conn.commit()

    return {
        "success": True,
        "reported": True,
        "new_report": created,
        "message": "Comment reported for review",
    }

# ============================================================
# ARTICLE READER ENGAGEMENT
# ============================================================

class ArticleCommentCreateData(BaseModel):
    visitor_id: str
    display_name: str
    comment_text: str


def _ensure_article_exists(cur, article_id: int):
    cur.execute("SELECT id FROM articles WHERE id=%s", (article_id,))
    if not cur.fetchone():
        raise HTTPException(status_code=404, detail="Article not found")



# ============================================================
# RELATED CONTENT FOR ARTICLE PAGE
# Related articles + linked movies
# IMPORTANT: KEEP BEFORE dynamic /articles/{article_id}/... routes
# ============================================================

@app.get("/articles/{article_id}/related")
def get_related_article_content(article_id: int, limit: int = 6):
    limit = max(1, min(int(limit or 6), 12))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, category
                FROM articles
                WHERE id = %s
                  AND status = 'published'
            """, (article_id,))
            source = cur.fetchone()

            if not source:
                raise HTTPException(status_code=404, detail="Article not found")

            _, source_title, source_category = source

            cur.execute("""
                SELECT
                    a.id,
                    a.title,
                    a.slug,
                    a.subtitle,
                    a.category,
                    a.author,
                    a.hero_image,
                    a.published_at,
                    (
                        CASE WHEN a.category = %s THEN 4 ELSE 0 END +
                        (
                            SELECT COUNT(*) * 5
                            FROM article_movies source_am
                            JOIN article_movies candidate_am
                              ON candidate_am.movie_id = source_am.movie_id
                            WHERE source_am.article_id = %s
                              AND candidate_am.article_id = a.id
                        ) +
                        (
                            SELECT COUNT(*) * 4
                            FROM article_actors source_aa
                            JOIN article_actors candidate_aa
                              ON candidate_aa.actor_id = source_aa.actor_id
                            WHERE source_aa.article_id = %s
                              AND candidate_aa.article_id = a.id
                        )
                    ) AS relevance_score
                FROM articles a
                WHERE a.status = 'published'
                  AND a.id <> %s
                ORDER BY
                    relevance_score DESC,
                    a.published_at DESC NULLS LAST,
                    a.id DESC
                LIMIT %s
            """, (
                source_category,
                article_id,
                article_id,
                article_id,
                limit
            ))
            article_rows = cur.fetchall()

            cur.execute("""
                SELECT DISTINCT
                    m.id,
                    m.title,
                    m.release_date,
                    m.language,
                    m.genre,
                    m.worldwide_collection_crore,
                    m.verdict,
                    m.poster
                FROM article_movies am
                JOIN movies m ON m.id = am.movie_id
                WHERE am.article_id = %s
                ORDER BY m.release_date DESC NULLS LAST, m.id DESC
                LIMIT %s
            """, (article_id, limit))
            movie_rows = cur.fetchall()

    return {
        "article_id": article_id,
        "related_articles": [
            {
                "id": r[0],
                "title": r[1],
                "slug": r[2],
                "subtitle": r[3],
                "category": r[4],
                "author": r[5],
                "hero_image": r[6],
                "published_at": r[7].isoformat() if r[7] else None,
                "relevance_score": int(r[8] or 0),
                "url": f"/article/{r[2]}",
            }
            for r in article_rows
        ],
        "related_movies": [
            {
                "id": r[0],
                "title": r[1],
                "release_date": str(r[2]) if r[2] else None,
                "language": r[3],
                "genre": r[4],
                "worldwide_collection_crore": float(r[5] or 0),
                "verdict": r[6],
                "poster": safe_movie_poster(r[7]),
                "url": f"/movie.html?id={r[0]}",
            }
            for r in movie_rows
        ],
    }


@app.get("/articles/{article_id}/engagement")
def get_article_engagement(article_id: int, visitor_id: Optional[str] = None):
    visitor_id = _clean_visitor_id(visitor_id) if visitor_id else None
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_article_exists(cur, article_id)
            cur.execute("SELECT COUNT(*) FROM article_likes WHERE article_id=%s", (article_id,))
            like_count=cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM article_hype WHERE article_id=%s", (article_id,))
            hype_count=cur.fetchone()[0]
            liked=hyped=False
            if visitor_id:
                cur.execute("SELECT 1 FROM article_likes WHERE article_id=%s AND visitor_id=%s",(article_id,visitor_id)); liked=bool(cur.fetchone())
                cur.execute("SELECT 1 FROM article_hype WHERE article_id=%s AND visitor_id=%s",(article_id,visitor_id)); hyped=bool(cur.fetchone())
    return {"article_id":article_id,"like_count":like_count,"hype_count":hype_count,"liked":liked,"hyped":hyped}


@app.post("/articles/{article_id}/like")
def toggle_article_like(article_id: int, data: VisitorActionData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_article_exists(cur,article_id)
            cur.execute("DELETE FROM article_likes WHERE article_id=%s AND visitor_id=%s RETURNING id",(article_id,visitor_id))
            active=not bool(cur.fetchone())
            if active:
                cur.execute("INSERT INTO article_likes(article_id,visitor_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",(article_id,visitor_id))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM article_likes WHERE article_id=%s",(article_id,)); count=cur.fetchone()[0]
    return {"success":True,"active":active,"like_count":count}


@app.post("/articles/{article_id}/hype")
def toggle_article_hype(article_id: int, data: VisitorActionData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_article_exists(cur,article_id)
            cur.execute("DELETE FROM article_hype WHERE article_id=%s AND visitor_id=%s RETURNING id",(article_id,visitor_id))
            active=not bool(cur.fetchone())
            if active:
                cur.execute("INSERT INTO article_hype(article_id,visitor_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",(article_id,visitor_id))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM article_hype WHERE article_id=%s",(article_id,)); count=cur.fetchone()[0]
    return {"success":True,"active":active,"hype_count":count}


@app.get("/articles/{article_id}/comments")
def get_article_comments(article_id:int, visitor_id:Optional[str]=None, sort:Literal["newest","top"]="newest", limit:int=30, offset:int=0):
    visitor_id=_clean_visitor_id(visitor_id) if visitor_id else None
    limit=max(1,min(limit,100)); offset=max(0,offset)
    order_sql="like_count DESC, c.created_at DESC" if sort=="top" else "c.created_at DESC"
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_article_exists(cur,article_id)
            cur.execute(f"""
                SELECT c.id,c.display_name,c.comment_text,c.created_at,
                       COUNT(l.id) AS like_count,
                       EXISTS(SELECT 1 FROM article_comment_likes mine WHERE mine.comment_id=c.id AND mine.visitor_id=%s) AS liked_by_me,
                       (c.visitor_id=%s) AS is_owner
                FROM article_comments c
                LEFT JOIN article_comment_likes l ON l.comment_id=c.id
                WHERE c.article_id=%s AND c.is_hidden=FALSE AND c.is_deleted=FALSE
                GROUP BY c.id ORDER BY {order_sql} LIMIT %s OFFSET %s
            """,(visitor_id or "",visitor_id or "",article_id,limit,offset))
            rows=cur.fetchall()
            cur.execute("SELECT COUNT(*) FROM article_comments WHERE article_id=%s AND is_hidden=FALSE AND is_deleted=FALSE",(article_id,))
            total=cur.fetchone()[0]
    return {"article_id":article_id,"total":total,"comments":[{"id":r[0],"display_name":r[1],"comment_text":r[2],"created_at":r[3].isoformat() if r[3] else None,"like_count":r[4],"liked_by_me":r[5],"is_owner":r[6]} for r in rows]}


@app.post("/articles/{article_id}/comments")
def post_article_comment(article_id:int,data:ArticleCommentCreateData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    display_name=_clean_public_text(data.display_name,"Display name",2,50)
    comment_text=_clean_public_text(data.comment_text,"Comment",2,1000)
    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_article_exists(cur,article_id)
            cur.execute("SELECT created_at FROM article_comments WHERE article_id=%s AND visitor_id=%s ORDER BY created_at DESC LIMIT 1",(article_id,visitor_id))
            recent=cur.fetchone()
            if recent and (datetime.now(timezone.utc)-recent[0]).total_seconds()<30:
                raise HTTPException(status_code=429,detail="Please wait 30 seconds before posting another comment")
            cur.execute("""INSERT INTO article_comments(article_id,visitor_id,display_name,comment_text)
                           VALUES(%s,%s,%s,%s) RETURNING id,created_at""",(article_id,visitor_id,display_name,comment_text))
            row=cur.fetchone(); conn.commit()
    return {"success":True,"comment":{"id":row[0],"display_name":display_name,"comment_text":comment_text,"created_at":row[1].isoformat() if row[1] else None,"like_count":0,"liked_by_me":False,"is_owner":True}}


@app.delete("/article-comments/{comment_id}")
def delete_article_comment(comment_id:int,data:VisitorActionData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE article_comments SET is_deleted=TRUE,updated_at=NOW()
                           WHERE id=%s AND visitor_id=%s AND is_deleted=FALSE RETURNING id""",(comment_id,visitor_id))
            deleted=cur.fetchone()
            if not deleted:
                cur.execute("SELECT visitor_id,is_deleted FROM article_comments WHERE id=%s",(comment_id,)); row=cur.fetchone()
                if not row or row[1]: raise HTTPException(status_code=404,detail="Comment not found")
                raise HTTPException(status_code=403,detail="You can delete only your own comment")
            conn.commit()
    return {"success":True,"deleted":True,"comment_id":comment_id}


@app.post("/article-comments/{comment_id}/like")
def toggle_article_comment_like(comment_id:int,data:VisitorActionData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM article_comments WHERE id=%s AND is_hidden=FALSE AND is_deleted=FALSE",(comment_id,))
            if not cur.fetchone(): raise HTTPException(status_code=404,detail="Comment not found")
            cur.execute("DELETE FROM article_comment_likes WHERE comment_id=%s AND visitor_id=%s RETURNING id",(comment_id,visitor_id))
            active=not bool(cur.fetchone())
            if active: cur.execute("INSERT INTO article_comment_likes(comment_id,visitor_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",(comment_id,visitor_id))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM article_comment_likes WHERE comment_id=%s",(comment_id,)); count=cur.fetchone()[0]
    return {"success":True,"active":active,"like_count":count}


@app.post("/article-comments/{comment_id}/report")
def report_article_comment(comment_id:int,data:CommentReportData):
    visitor_id=_clean_visitor_id(data.visitor_id)
    reason=(data.reason or "Other").strip()
    if len(reason)>100: raise HTTPException(status_code=400,detail="Report reason is too long")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM article_comments WHERE id=%s AND is_deleted=FALSE",(comment_id,))
            if not cur.fetchone(): raise HTTPException(status_code=404,detail="Comment not found")
            cur.execute("""INSERT INTO article_comment_reports(comment_id,visitor_id,reason) VALUES(%s,%s,%s)
                           ON CONFLICT(comment_id,visitor_id) DO NOTHING""",(comment_id,visitor_id,reason))
            created=cur.rowcount>0; conn.commit()
    return {"success":True,"reported":True,"new_report":created,"message":"Comment reported for review"}

# ============================================================
# UNIQUE VIEW TRACKING
# Movie + Actor + Article
# ============================================================

class ViewTrackData(BaseModel):
    visitor_id: str


def _track_unique_view(table_name: str, id_column: str, item_id: int, visitor_id: str):
    visitor_id = _clean_visitor_id(visitor_id)

    allowed = {
        ("movie_views", "movie_id", "movies"),
        ("actor_views", "actor_id", "actors"),
        ("article_views", "article_id", "articles"),
    }

    target_table = {
        ("movie_views", "movie_id"): "movies",
        ("actor_views", "actor_id"): "actors",
        ("article_views", "article_id"): "articles",
    }.get((table_name, id_column))

    if not target_table or (table_name, id_column, target_table) not in allowed:
        raise HTTPException(status_code=500, detail="Invalid view tracking target")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT 1 FROM {target_table} WHERE id=%s",
                (item_id,)
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Item not found")

            cur.execute(
                f"""
                INSERT INTO {table_name} ({id_column}, visitor_id)
                VALUES (%s, %s)
                ON CONFLICT ({id_column}, visitor_id) DO NOTHING
                RETURNING id
                """,
                (item_id, visitor_id)
            )
            counted = bool(cur.fetchone())

            cur.execute(
                f"SELECT COUNT(*) FROM {table_name} WHERE {id_column}=%s",
                (item_id,)
            )
            views = int(cur.fetchone()[0] or 0)

        conn.commit()

    return {"counted": counted, "views": views}


def _get_view_count(table_name: str, id_column: str, item_id: int):
    allowed = {
        ("movie_views", "movie_id"),
        ("actor_views", "actor_id"),
        ("article_views", "article_id"),
    }

    if (table_name, id_column) not in allowed:
        raise HTTPException(status_code=500, detail="Invalid view tracking target")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) FROM {table_name} WHERE {id_column}=%s",
                (item_id,)
            )
            views = int(cur.fetchone()[0] or 0)

    return {"views": views}


@app.post("/movies/{movie_id}/view")
def track_movie_view(movie_id: int, data: ViewTrackData):
    result = _track_unique_view("movie_views", "movie_id", movie_id, data.visitor_id)
    return {"movie_id": movie_id, **result}


@app.get("/movies/{movie_id}/views")
def get_movie_views(movie_id: int):
    return {"movie_id": movie_id, **_get_view_count("movie_views", "movie_id", movie_id)}


@app.post("/actors/{actor_id}/view")
def track_actor_view(actor_id: int, data: ViewTrackData):
    result = _track_unique_view("actor_views", "actor_id", actor_id, data.visitor_id)
    return {"actor_id": actor_id, **result}


@app.get("/actors/{actor_id}/views")
def get_actor_views(actor_id: int):
    return {"actor_id": actor_id, **_get_view_count("actor_views", "actor_id", actor_id)}


@app.post("/articles/{article_id}/view")
def track_article_view(article_id: int, data: ViewTrackData):
    result = _track_unique_view("article_views", "article_id", article_id, data.visitor_id)
    return {"article_id": article_id, **result}


@app.get("/articles/{article_id}/views")
def get_article_views(article_id: int):
    return {"article_id": article_id, **_get_view_count("article_views", "article_id", article_id)}


# ============================================================
# TRENDING FAN ACTIVITY
# ============================================================

@app.get("/fan-activity/trending")
def trending_fan_activity(limit: int = 8):
    limit = max(1, min(limit, 20))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                WITH activity AS (
                    SELECT
                        'movie'::text AS type,
                        m.id::text AS item_id,
                        m.title AS title,
                        COALESCE(m.poster, '') AS image,
                        ('movie.html?id=' || m.id::text) AS url,
                        COUNT(*)::bigint AS activity_count,
                        MAX(x.created_at) AS last_activity
                    FROM movies m
                    JOIN (
                        SELECT movie_id, created_at FROM movie_fans
                        UNION ALL SELECT movie_id, created_at FROM movie_hype
                        UNION ALL SELECT movie_id, created_at FROM movie_fan_votes
                        UNION ALL SELECT movie_id, created_at FROM movie_comments
                    ) x ON x.movie_id = m.id
                    WHERE x.created_at >= NOW() - INTERVAL '7 days'
                    GROUP BY m.id, m.title, m.poster

                    UNION ALL

                    SELECT
                        'article'::text,
                        a.id::text,
                        a.title,
                        COALESCE(a.hero_image, ''),
                        ('article/' || a.slug),
                        COUNT(*)::bigint,
                        MAX(x.created_at)
                    FROM articles a
                    JOIN (
                        SELECT article_id, created_at FROM article_likes
                        UNION ALL SELECT article_id, created_at FROM article_hype
                        UNION ALL SELECT article_id, created_at FROM article_comments
                    ) x ON x.article_id = a.id
                    WHERE x.created_at >= NOW() - INTERVAL '7 days'
                      AND a.status = 'published'
                    GROUP BY a.id, a.title, a.hero_image, a.slug

                    UNION ALL

                    SELECT
                        'hero_comparison'::text,
                        (p.actor1_id::text || '-' || p.actor2_id::text),
                        (a1.name || ' vs ' || a2.name),
                        '',
                        ('compare.html?a=' || p.actor1_id::text || '&b=' || p.actor2_id::text),
                        COUNT(*)::bigint,
                        MAX(p.created_at)
                    FROM (
                        SELECT actor1_id, actor2_id, created_at FROM hero_comparison_likes
                        UNION ALL SELECT actor1_id, actor2_id, created_at FROM hero_comparison_hype
                        UNION ALL SELECT actor1_id, actor2_id, created_at FROM hero_comparison_votes
                        UNION ALL SELECT actor1_id, actor2_id, created_at FROM hero_comparison_comments
                    ) p
                    JOIN actors a1 ON a1.id = p.actor1_id
                    JOIN actors a2 ON a2.id = p.actor2_id
                    WHERE p.created_at >= NOW() - INTERVAL '7 days'
                    GROUP BY p.actor1_id, p.actor2_id, a1.name, a2.name

                    UNION ALL

                    SELECT
                        'movie_comparison'::text,
                        (p.movie1_id::text || '-' || p.movie2_id::text),
                        (m1.title || ' vs ' || m2.title),
                        '',
                        ('movie-compare.html?a=' || p.movie1_id::text || '&b=' || p.movie2_id::text),
                        COUNT(*)::bigint,
                        MAX(p.created_at)
                    FROM (
                        SELECT movie1_id, movie2_id, created_at FROM movie_comparison_likes
                        UNION ALL SELECT movie1_id, movie2_id, created_at FROM movie_comparison_hype
                        UNION ALL SELECT movie1_id, movie2_id, created_at FROM movie_comparison_votes
                        UNION ALL SELECT movie1_id, movie2_id, created_at FROM movie_comparison_comments
                    ) p
                    JOIN movies m1 ON m1.id = p.movie1_id
                    JOIN movies m2 ON m2.id = p.movie2_id
                    WHERE p.created_at >= NOW() - INTERVAL '7 days'
                    GROUP BY p.movie1_id, p.movie2_id, m1.title, m2.title
                )
                SELECT type, item_id, title, image, url, activity_count, last_activity
                FROM activity
                ORDER BY activity_count DESC, last_activity DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()

    return {
        "period_days": 7,
        "items": [
            {
                "type": row[0],
                "id": row[1],
                "title": row[2],
                "image": row[3],
                "url": row[4],
                "activity_count": row[5],
                "last_activity": row[6].isoformat() if row[6] else None,
            }
            for row in rows
        ]
    }
