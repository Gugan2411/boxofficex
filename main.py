import html
from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Depends
from fastapi.responses import FileResponse, Response, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from datetime import date, datetime, timedelta
import os
import json
import cloudinary
import cloudinary.uploader
from urllib.parse import urlparse, quote
import textwrap
import unicodedata
import math
import time as time_module
import threading

# ============================================================
# CLOUDINARY CONFIGURATION
# Uses the single CLOUDINARY_URL value from Render.
# Example format:
# cloudinary://API_KEY:API_SECRET@CLOUD_NAME
# Never hard-code the real value in this file.
# ============================================================

CLOUDINARY_URL = (os.getenv("CLOUDINARY_URL") or "").strip()

if CLOUDINARY_URL:
    # Normalize the environment value before Cloudinary reads it.
    os.environ["CLOUDINARY_URL"] = CLOUDINARY_URL

# Cloudinary's Python SDK automatically reads CLOUDINARY_URL.
cloudinary.config(secure=True)
import secrets
import re
import psycopg
from pydantic import BaseModel
from xml.sax.saxutils import escape as xml_escape
from html import escape as html_escape


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


def _is_remote_image(value):
    if not value:
        return False

    value = str(value).strip().lower()

    return (
        value.startswith("https://")
        or value.startswith("http://")
    )


def safe_movie_poster(filename):
    """Support Cloudinary URLs and existing local posters."""
    if filename:
        filename = str(filename).strip()

        if _is_remote_image(filename):
            return filename

        if (POSTERS_DIR / filename).is_file():
            return filename

    return DEFAULT_MOVIE_POSTER


def safe_actor_photo(filename):
    """Support Cloudinary URLs and existing local actor photos."""
    if filename:
        filename = str(filename).strip()

        if _is_remote_image(filename):
            return filename

        if (ACTORS_DIR / filename).is_file():
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


# ============================================================
# ADVERTISEMENT MANAGEMENT MODELS
# Owner-only paid campaign management
# ============================================================

class AdvertisementCreateData(BaseModel):
    advertiser_name: str
    business_category: Optional[str] = None
    campaign_name: str

    ad_type: Literal[
        "full_screen",
        "top_banner",
        "top_sticky",
        "bottom_sticky",
        "in_content_video",
        "in_content",
        "homepage",
        "movie_page",
        "actor_page",
        "article",
        "small_video",
        "sponsored_movie",
        "sponsored_article",
        "sponsored_link",
        "search_result",
    ]

    media_type: Literal["image", "video"]
    media_url: str
    mobile_media_url: Optional[str] = None
    target_url: str

    # Comma-separated placement groups; supports one or many public page groups.
    placement: str

    page_target: Optional[str] = None
    ad_slot: Optional[int] = None
    movie_ranking_industry: Optional[str] = None
    actor_ranking_industry: Optional[str] = None
    duration_seconds: Optional[int] = None

    frequency: Literal[
        "always",
        "once_session",
        "once_12h",
        "once_24h",
    ] = "once_24h"

    start_date: date
    start_time: Optional[time] = None
    end_date: date
    end_time: Optional[time] = None
    is_active: bool = True

    # Private billing / traffic controls.
    total_amount: Optional[float] = None
    amount_paid: Optional[float] = None
    traffic_weight: float = 1.0
    client_email: Optional[str] = None
    client_phone: Optional[str] = None
    billing_address: Optional[str] = None
    invoice_number: Optional[str] = None
    invoice_date: Optional[date] = None
    payment_due_date: Optional[date] = None
    billing_notes: Optional[str] = None

    # V2 precise campaign targeting.
    # Empty lists mean "all" within the selected placement/page type.
    target_actor_ids: Optional[list[int]] = None
    target_movie_ids: Optional[list[int]] = None
    target_actor_movies: bool = False
    is_draft: bool = False


    ad_package: Optional[str] = 'standard'
    sponsored_package: Optional[str] = 'rotation'
    exclusive_inventory: bool = False
    suggested_rate: Optional[float] = 0
    final_rate: Optional[float] = 0

class AdvertisementUpdateData(BaseModel):
    advertiser_name: Optional[str] = None
    business_category: Optional[str] = None
    campaign_name: Optional[str] = None

    ad_type: Optional[
        Literal[
            "full_screen",
            "top_banner",
            "top_sticky",
            "bottom_sticky",
            "in_content_video",
            "in_content",
            "homepage",
            "movie_page",
            "actor_page",
            "article",
            "small_video",
            "sponsored_movie",
            "sponsored_article",
            "sponsored_link",
            "search_result",
        ]
    ] = None

    media_type: Optional[Literal["image", "video"]] = None
    media_url: Optional[str] = None
    mobile_media_url: Optional[str] = None
    target_url: Optional[str] = None

    # Comma-separated placement groups; supports one or many public page groups.
    placement: Optional[str] = None

    page_target: Optional[str] = None
    ad_slot: Optional[int] = None
    movie_ranking_industry: Optional[str] = None
    actor_ranking_industry: Optional[str] = None
    duration_seconds: Optional[int] = None

    frequency: Optional[
        Literal[
            "always",
            "once_session",
            "once_12h",
            "once_24h",
        ]
    ] = None

    start_date: Optional[date] = None
    start_time: Optional[time] = None
    end_date: Optional[date] = None
    end_time: Optional[time] = None
    is_active: Optional[bool] = None
    total_amount: Optional[float] = None
    amount_paid: Optional[float] = None
    traffic_weight: Optional[float] = None
    client_email: Optional[str] = None
    client_phone: Optional[str] = None
    billing_address: Optional[str] = None
    invoice_number: Optional[str] = None
    invoice_date: Optional[date] = None
    payment_due_date: Optional[date] = None
    billing_notes: Optional[str] = None
    target_actor_ids: Optional[list[int]] = None
    target_movie_ids: Optional[list[int]] = None
    target_actor_movies: Optional[bool] = None
    is_draft: Optional[bool] = None


    ad_package: Optional[str] = None
    sponsored_package: Optional[str] = None
    exclusive_inventory: Optional[bool] = None
    suggested_rate: Optional[float] = None
    final_rate: Optional[float] = None

class AdvertisementStatusData(BaseModel):
    is_active: bool


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





@app.on_event("startup")
def initialize_actor_view_tracking():
    """Ensure actor unique-view storage exists on every deployment/database."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS actor_views (
                    id BIGSERIAL PRIMARY KEY,
                    actor_id BIGINT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
                    visitor_id TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (actor_id, visitor_id)
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_actor_views_actor_id
                ON actor_views (actor_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_actor_views_created_at
                ON actor_views (created_at DESC)
            """)
        conn.commit()
    print("ACTOR VIEW TRACKING: READY", flush=True)


# ============================================================
# ADVERTISEMENT DATABASE
# ============================================================

@app.on_event("startup")
def initialize_advertisement_system():
    """
    Create the direct-advertising campaign table and indexes.

    Campaign state is intentionally derived from:
    - is_active
    - start_date
    - end_date

    This avoids stale manually-maintained scheduled/expired states.
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS advertisements (
                    id BIGSERIAL PRIMARY KEY,

                    advertiser_name TEXT NOT NULL,
                    business_category TEXT,
                    campaign_name TEXT NOT NULL,

                    ad_type TEXT NOT NULL CHECK (
                        ad_type IN (
                            'full_screen',
                            'top_banner',
                            'homepage',
                            'movie_page',
                            'actor_page',
                            'article',
                            'small_video',
                            'sponsored_movie',
                            'sponsored_article',
                            'sponsored_link',
                            'search_result'
                        )
                    ),

                    media_type TEXT NOT NULL CHECK (
                        media_type IN ('image', 'video')
                    ),

                    media_url TEXT NOT NULL,
                    mobile_media_url TEXT,
                    target_url TEXT NOT NULL,

                    placement TEXT NOT NULL CHECK (
                        placement IN (
                            'homepage',
                            'movie_pages',
                            'actor_pages',
                            'article_pages',
                            'rankings_compare',
                            'search',
                            'sponsors_page',
                            'selected_pages',
                            'sitewide'
                        )
                    ),

                    page_target TEXT,

                    duration_seconds INTEGER CHECK (
                        duration_seconds IS NULL
                        OR (
                            duration_seconds >= 1
                            AND duration_seconds <= 60
                        )
                    ),

                    frequency TEXT NOT NULL DEFAULT 'once_24h'
                        CHECK (
                            frequency IN (
                                'always',
                                'once_session',
                                'once_12h',
                                'once_24h'
                            )
                        ),

                    start_date DATE NOT NULL,
                    end_date DATE NOT NULL,

                    is_active BOOLEAN NOT NULL DEFAULT TRUE,

                    amount_paid NUMERIC(12, 2) CHECK (
                        amount_paid IS NULL OR amount_paid >= 0
                    ),

                    impressions BIGINT NOT NULL DEFAULT 0 CHECK (impressions >= 0),
                    clicks BIGINT NOT NULL DEFAULT 0 CHECK (clicks >= 0),
                    completed_views BIGINT NOT NULL DEFAULT 0 CHECK (completed_views >= 0),
                    skips BIGINT NOT NULL DEFAULT 0 CHECK (skips >= 0),

                    created_by BIGINT
                        REFERENCES admins(id)
                        ON DELETE SET NULL,

                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

                    CHECK (end_date >= start_date)
                )
            """)

            # V1.1 advertising upgrade: existing installs originally used CHECK
            # constraints for one placement and the first ad-type set. Placement is
            # now validated by the app and may contain comma-separated page groups.
            cur.execute("ALTER TABLE advertisements DROP CONSTRAINT IF EXISTS advertisements_placement_check")
            cur.execute("ALTER TABLE advertisements DROP CONSTRAINT IF EXISTS advertisements_ad_type_check")

            # V1.2 billing + weighted traffic upgrade. Safe for existing databases.
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS total_amount NUMERIC(12,2)")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS traffic_weight NUMERIC(10,2) NOT NULL DEFAULT 1")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS client_email TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS client_phone TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS billing_address TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS invoice_number TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS invoice_date DATE")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS payment_due_date DATE")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS billing_notes TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS ad_slot INTEGER")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS movie_ranking_industry VARCHAR(40)")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS actor_ranking_industry VARCHAR(40)")
            # V2 precise actor/movie targeting + draft workflow.
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS target_actor_ids TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS target_movie_ids TEXT")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS target_actor_movies BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS start_time TIME")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS end_time TIME")
            # V2.1 package + exclusive inventory fields used by Master Inventory.
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS ad_package TEXT NOT NULL DEFAULT 'standard'")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS sponsored_package TEXT NOT NULL DEFAULT 'rotation'")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS exclusive_inventory BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS suggested_rate NUMERIC(12,2) NOT NULL DEFAULT 0")
            cur.execute("ALTER TABLE advertisements ADD COLUMN IF NOT EXISTS final_rate NUMERIC(12,2) NOT NULL DEFAULT 0")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS advertisement_invoices (
                    id BIGSERIAL PRIMARY KEY,
                    advertisement_id BIGINT NOT NULL REFERENCES advertisements(id) ON DELETE CASCADE,
                    invoice_number TEXT NOT NULL UNIQUE,
                    invoice_date DATE NOT NULL,
                    advertiser_name TEXT NOT NULL,
                    client_email TEXT,
                    client_phone TEXT,
                    billing_address TEXT,
                    campaign_name TEXT NOT NULL,
                    ad_type TEXT NOT NULL,
                    placement TEXT NOT NULL,
                    start_date DATE NOT NULL,
                    end_date DATE NOT NULL,
                    traffic_weight NUMERIC(10,2) NOT NULL DEFAULT 1,
                    total_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
                    amount_paid NUMERIC(12,2) NOT NULL DEFAULT 0,
                    pending_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
                    payment_status TEXT NOT NULL,
                    payment_due_date DATE,
                    billing_notes TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            cur.execute("ALTER TABLE advertisement_invoices ADD COLUMN IF NOT EXISTS impressions BIGINT NOT NULL DEFAULT 0")
            cur.execute("ALTER TABLE advertisement_invoices ADD COLUMN IF NOT EXISTS clicks BIGINT NOT NULL DEFAULT 0")
            cur.execute("ALTER TABLE advertisement_invoices ADD COLUMN IF NOT EXISTS completed_views BIGINT NOT NULL DEFAULT 0")
            cur.execute("ALTER TABLE advertisement_invoices ADD COLUMN IF NOT EXISTS skips BIGINT NOT NULL DEFAULT 0")

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ad_invoices_advertisement
                ON advertisement_invoices (advertisement_id, created_at DESC)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS
                    idx_advertisements_active_dates
                ON advertisements (
                    is_active,
                    start_date,
                    end_date
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS
                    idx_advertisements_placement
                ON advertisements (placement)
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS
                    idx_advertisements_type
                ON advertisements (ad_type)
            """)

        conn.commit()

    print(
        "BOXOFFICEX ADVERTISEMENT SYSTEM: READY",
        flush=True
    )


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
            "https://boxofficex.in,"
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

    # Public performance caching. Never cache admin/auth/search responses here.
    path = request.url.path
    if request.method == "GET":
        if path.startswith(("/posters/", "/actor-images/", "/article-images/", "/images/")):
            response.headers["Cache-Control"] = "public, max-age=604800, stale-while-revalidate=86400"
        elif path.endswith((".css", ".js", ".woff", ".woff2")):
            response.headers["Cache-Control"] = "public, max-age=86400, stale-while-revalidate=604800"
        elif (
            not path.startswith(("/admin", "/api/admin", "/docs", "/redoc", "/openapi.json"))
            and path != "/search"
            and response.headers.get("content-type", "").startswith("application/json")
        ):
            response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"

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





# Temporary public-display switch.
# View tracking and stored article view totals remain active.
SHOW_PUBLIC_ARTICLE_VIEWS = False


BOXOFFICEX_GLOBAL_HEAD_ICONS = """
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" type="image/png" sizes="32x32" href="/images/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/images/favicon-16x16.png">
<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#031123">
""".strip()


def _inject_boxofficex_global_icons(document: str) -> str:
    """Add BoxOfficeX favicon/PWA discovery tags once, without touching page SEO."""
    if not document or "</head>" not in document.lower():
        return document

    # If this document has already been upgraded, do nothing.
    if 'href="/site.webmanifest"' in document:
        return document

    return re.sub(
        r"</head\s*>",
        BOXOFFICEX_GLOBAL_HEAD_ICONS + "\n</head>",
        document,
        count=1,
        flags=re.I,
    )


def _boxofficex_html_file(filename: str, *, headers=None):
    """Serve a static HTML file with the same global icon tags as SSR pages."""
    path = BASE_DIR / filename
    document = path.read_text(encoding="utf-8")
    return HTMLResponse(
        content=_inject_boxofficex_global_icons(document),
        headers=headers or {},
    )


# ============================================================
# BOXOFFICEX GLOBAL BRAND ICONS
# ============================================================

@app.get("/favicon.ico", include_in_schema=False)
def boxofficex_favicon():
    return FileResponse(
        IMAGES_DIR / "favicon.ico",
        media_type="image/x-icon",
        headers={"Cache-Control": "public, max-age=604800"}
    )


@app.get("/site.webmanifest", include_in_schema=False)
def boxofficex_webmanifest():
    return FileResponse(
        IMAGES_DIR / "site.webmanifest",
        media_type="application/manifest+json",
        headers={"Cache-Control": "public, max-age=86400"}
    )


# ============================================================
# ADMIN MOVIE / ACTOR IMAGE UPLOADS
# Cloudinary-backed permanent storage
# ============================================================

ALLOWED_IMAGE_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}

MAX_ADMIN_IMAGE_BYTES = 8 * 1024 * 1024


ALLOWED_AD_MEDIA_TYPES = {
    "image/jpeg": "image",
    "image/png": "image",
    "image/webp": "image",
    "video/mp4": "video",
    "video/webm": "video",
    "video/quicktime": "video",
}

MAX_ADMIN_AD_MEDIA_BYTES = 50 * 1024 * 1024


async def _upload_ad_media_to_cloudinary(
    file: UploadFile,
    folder: str = "boxofficex/advertisements"
):
    """
    Owner-only advertisement media uploader.

    Supports:
    - JPG
    - PNG
    - WEBP
    - MP4
    - WEBM
    - MOV

    Maximum file size: 50 MB.
    """

    if not _cloudinary_ready():
        config = cloudinary.config()

        raise HTTPException(
            status_code=500,
            detail={
                "message": "Cloudinary is not configured on the server",
                "url_present": bool(os.getenv("CLOUDINARY_URL")),
                "cloud_name_present": bool(getattr(config, "cloud_name", None)),
                "api_key_present": bool(getattr(config, "api_key", None)),
                "api_secret_present": bool(getattr(config, "api_secret", None)),
            }
        )

    content_type = (file.content_type or "").lower().strip()

    resource_type = ALLOWED_AD_MEDIA_TYPES.get(content_type)

    if not resource_type:
        raise HTTPException(
            status_code=400,
            detail=(
                "Advertisement media must be JPG, PNG, WEBP, "
                "MP4, WEBM or MOV"
            )
        )

    raw = await file.read()

    if not raw:
        raise HTTPException(
            status_code=400,
            detail="Uploaded advertisement media is empty"
        )

    if len(raw) > MAX_ADMIN_AD_MEDIA_BYTES:
        raise HTTPException(
            status_code=400,
            detail="Advertisement media must be 50 MB or smaller"
        )

    original_stem = Path(
        file.filename or "advertisement-media"
    ).stem

    safe_stem = re.sub(
        r"[^a-zA-Z0-9_-]+",
        "-",
        original_stem
    ).strip("-").lower()

    if not safe_stem:
        safe_stem = "advertisement-media"

    public_id = (
        f"{safe_stem}-"
        f"{secrets.token_hex(5)}"
    )

    try:
        result = cloudinary.uploader.upload(
            raw,
            folder=folder,
            public_id=public_id,
            resource_type=resource_type,
            overwrite=False,
            use_filename=False,
            unique_filename=False,
        )
    except Exception as exc:
        print(
            "ADVERTISEMENT CLOUDINARY UPLOAD ERROR:",
            exc,
            flush=True
        )

        raise HTTPException(
            status_code=502,
            detail="Advertisement media upload failed"
        )

    secure_url = result.get("secure_url")

    if not secure_url:
        raise HTTPException(
            status_code=502,
            detail="Cloudinary did not return an advertisement media URL"
        )

    return {
        "url": secure_url,
        "public_id": result.get("public_id"),
        "resource_type": result.get("resource_type") or resource_type,
        "format": result.get("format"),
        "width": result.get("width"),
        "height": result.get("height"),
        "duration": result.get("duration"),
        "bytes": result.get("bytes"),
    }


def _cloudinary_ready():
    """Check Cloudinary configuration without exposing credential values."""
    config = cloudinary.config()

    status = {
        "url_present": bool(os.getenv("CLOUDINARY_URL")),
        "cloud_name_present": bool(getattr(config, "cloud_name", None)),
        "api_key_present": bool(getattr(config, "api_key", None)),
        "api_secret_present": bool(getattr(config, "api_secret", None)),
    }

    print("CLOUDINARY STATUS:", status, flush=True)
    return all(status.values())


async def _upload_admin_image_to_cloudinary(
    file: UploadFile,
    folder: str,
    default_stem: str
):
    if not _cloudinary_ready():
        config = cloudinary.config()
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Cloudinary is not configured on the server",
                "url_present": bool(os.getenv("CLOUDINARY_URL")),
                "cloud_name_present": bool(getattr(config, "cloud_name", None)),
                "api_key_present": bool(getattr(config, "api_key", None)),
                "api_secret_present": bool(getattr(config, "api_secret", None)),
            }
        )

    if file.content_type not in ALLOWED_IMAGE_TYPES:
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

    if len(raw) > MAX_ADMIN_IMAGE_BYTES:
        raise HTTPException(
            status_code=400,
            detail="Image must be 8 MB or smaller"
        )

    original_stem = Path(file.filename or default_stem).stem
    safe_stem = re.sub(
        r"[^a-zA-Z0-9_-]+",
        "-",
        original_stem
    ).strip("-").lower()

    if not safe_stem:
        safe_stem = default_stem

    public_id = (
        f"{safe_stem}-"
        f"{secrets.token_hex(4)}"
    )

    try:
        result = cloudinary.uploader.upload(
            raw,
            folder=folder,
            public_id=public_id,
            resource_type="image",
            overwrite=False,
            use_filename=False,
            unique_filename=False,
        )
    except Exception as exc:
        print("CLOUDINARY UPLOAD ERROR:", exc)
        raise HTTPException(
            status_code=502,
            detail="Image upload failed"
        )

    secure_url = result.get("secure_url")
    returned_public_id = result.get("public_id")

    if not secure_url:
        raise HTTPException(
            status_code=502,
            detail="Cloudinary did not return an image URL"
        )

    return {
        "url": secure_url,
        "public_id": returned_public_id,
        "format": result.get("format"),
        "width": result.get("width"),
        "height": result.get("height"),
        "bytes": result.get("bytes"),
    }


@app.post(
    "/admin/upload/movie-poster",
    dependencies=[Depends(require_admin)]
)
async def admin_upload_movie_poster(
    file: UploadFile = File(...)
):
    uploaded = await _upload_admin_image_to_cloudinary(
        file=file,
        folder="boxofficex/movie-posters",
        default_stem="movie-poster"
    )

    return {
        "success": True,
        # Keep "filename" for compatibility with your current admin JS.
        # It now contains the permanent Cloudinary URL.
        "filename": uploaded["url"],
        "url": uploaded["url"],
        "public_id": uploaded["public_id"],
        "width": uploaded["width"],
        "height": uploaded["height"],
        "bytes": uploaded["bytes"],
    }


@app.post(
    "/admin/upload/actor-photo",
    dependencies=[Depends(require_admin)]
)
async def admin_upload_actor_photo(
    file: UploadFile = File(...)
):
    uploaded = await _upload_admin_image_to_cloudinary(
        file=file,
        folder="boxofficex/actor-photos",
        default_stem="actor-photo"
    )

    return {
        "success": True,
        # Keep "filename" for compatibility with your current admin JS.
        # It now contains the permanent Cloudinary URL.
        "filename": uploaded["url"],
        "url": uploaded["url"],
        "public_id": uploaded["public_id"],
        "width": uploaded["width"],
        "height": uploaded["height"],
        "bytes": uploaded["bytes"],
    }




# ============================================================
# OWNER: ADVERTISEMENT MEDIA UPLOAD
# Cloudinary-backed permanent image/video storage
# ============================================================

@app.post(
    "/admin/upload/advertisement-media",
    dependencies=[Depends(require_owner)]
)
async def admin_upload_advertisement_media(
    file: UploadFile = File(...)
):
    uploaded = await _upload_ad_media_to_cloudinary(
        file=file,
        folder="boxofficex/advertisements"
    )

    return {
        "success": True,
        "url": uploaded["url"],
        "filename": uploaded["url"],
        "public_id": uploaded["public_id"],
        "resource_type": uploaded["resource_type"],
        "format": uploaded["format"],
        "width": uploaded["width"],
        "height": uploaded["height"],
        "duration": uploaded["duration"],
        "bytes": uploaded["bytes"],
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
# PUBLIC SEO SLUG HELPERS
# Stage 1: no database schema migration required.
# Numeric IDs remain the internal API / relationship keys.
# ============================================================

def seo_slugify(value: str) -> str:
    """Create a stable, URL-safe lowercase slug from public text."""
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = value.encode("ascii", "ignore").decode("ascii")
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "item"


def movie_seo_slug(movie_id: int, title: str, release_date=None) -> str:
    """Movie slug: title + release year, with ID fallback when year is missing."""
    base = seo_slugify(title)
    year = None

    if release_date:
        try:
            year = getattr(release_date, "year", None) or int(str(release_date)[:4])
        except (TypeError, ValueError):
            year = None

    return f"{base}-{year}" if year else f"{base}-{movie_id}"


def actor_seo_slug(actor_id: int, name: str) -> str:
    """Actor slug: normalized public name. ID is only a fallback for blank names."""
    base = seo_slugify(name)
    return base if base != "item" else f"actor-{actor_id}"


def _movie_slug_rows():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, release_date
                FROM movies
                ORDER BY id
            """)
            return cur.fetchall()


def _actor_slug_rows():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name
                FROM actors
                ORDER BY id
            """)
            return cur.fetchall()


def _unique_movie_slug_map(rows=None):
    """Return {movie_id: unique_slug}; duplicate title/year slugs receive -ID."""
    rows = rows if rows is not None else _movie_slug_rows()
    bases = {row[0]: movie_seo_slug(row[0], row[1], row[2]) for row in rows}
    counts = {}
    for base in bases.values():
        counts[base] = counts.get(base, 0) + 1
    return {
        movie_id: (base if counts[base] == 1 else f"{base}-{movie_id}")
        for movie_id, base in bases.items()
    }


def _unique_actor_slug_map(rows=None):
    """Return {actor_id: unique_slug}; duplicate names receive -ID."""
    rows = rows if rows is not None else _actor_slug_rows()
    bases = {row[0]: actor_seo_slug(row[0], row[1]) for row in rows}
    counts = {}
    for base in bases.values():
        counts[base] = counts.get(base, 0) + 1
    return {
        actor_id: (base if counts[base] == 1 else f"{base}-{actor_id}")
        for actor_id, base in bases.items()
    }


def public_movie_url(movie_id: int) -> str:
    """Return the canonical clean public URL for a movie ID."""
    slug = _unique_movie_slug_map().get(int(movie_id))
    return f"/movie/{slug}" if slug else "/new-movies.html"


def public_actor_url(actor_id: int) -> str:
    """Return the canonical clean public URL for an actor ID."""
    slug = _unique_actor_slug_map().get(int(actor_id))
    return f"/actor/{slug}" if slug else "/actors.html"


def public_actor_comparison_url(actor1_id: int, actor2_id: int) -> str:
    """Return the single canonical clean Hero vs Hero URL."""
    try:
        ids = sorted([int(actor1_id), int(actor2_id)])
        if ids[0] == ids[1]:
            return "/compare-select.html"

        slug_map = _unique_actor_slug_map()
        first_slug = slug_map.get(ids[0])
        second_slug = slug_map.get(ids[1])

        if first_slug and second_slug:
            return f"/compare/{first_slug}-vs-{second_slug}"
    except Exception:
        pass

    return "/compare-select.html"


def public_movie_comparison_url(movie1_id: int, movie2_id: int) -> str:
    """Return the canonical clean Movie vs Movie URL using backend pair ordering."""
    try:
        first_id, second_id = _movie_comparison_pair(
            int(movie1_id),
            int(movie2_id)
        )
        slug_map = _unique_movie_slug_map()
        first_slug = slug_map.get(first_id)
        second_slug = slug_map.get(second_id)

        if first_slug and second_slug:
            return f"/compare/movies/{first_slug}-vs-{second_slug}"
    except Exception:
        pass

    return "/movie-compare-select.html"


def resolve_movie_slug(movie_slug: str):
    requested = (movie_slug or "").strip().lower()
    rows = _movie_slug_rows()
    slug_map = _unique_movie_slug_map(rows)
    for movie_id, title, release_date in rows:
        if slug_map.get(movie_id) == requested:
            return {
                "id": movie_id,
                "title": title,
                "release_date": release_date,
                "slug": requested,
                "url": f"/movie/{requested}",
            }
    return None


def resolve_actor_slug(actor_slug: str):
    requested = (actor_slug or "").strip().lower()
    rows = _actor_slug_rows()
    slug_map = _unique_actor_slug_map(rows)
    for actor_id, name in rows:
        if slug_map.get(actor_id) == requested:
            return {
                "id": actor_id,
                "name": name,
                "slug": requested,
                "url": f"/actor/{requested}",
            }
    return None


# ============================================================
# HOME - CACHED SERVER-RENDERED SEO CONTENT
# ============================================================

# Five minutes keeps the homepage fresh enough for box-office discovery while
# avoiding repeated database work for every visitor and crawler request.
HOME_HTML_CACHE_TTL = 300
_home_html_cache = {"html": None, "expires_at": 0.0}
_home_html_cache_lock = threading.Lock()
_home_html_refreshing = False


def _home_placeholder_hash(value):
    # Match the homepage JavaScript FNV-1a placeholder hash.
    result = 2166136261
    raw = str(value or "BOXOFFICEX").lower().encode("utf-16-le", errors="surrogatepass")
    for index in range(0, len(raw), 2):
        code_unit = raw[index] | (raw[index + 1] << 8)
        result ^= code_unit
        result = (result * 16777619) & 0xFFFFFFFF
    return result


def _home_placeholder_colors(name):
    h = _home_placeholder_hash(name)
    a = h % 360
    b = (a + 38 + ((h >> 8) % 83)) % 360
    c = (b + 42 + ((h >> 20) % 67)) % 360
    d = (a + 145 + ((h >> 17) % 71)) % 360
    return (
        f"hsl({a} {55 + ((h >> 4) % 26)}% 13%)",
        f"hsl({b} {58 + ((h >> 12) % 24)}% 34%)",
        f"hsl({c} 66% 20%)",
        f"hsl({d} 88% 68%)",
    )


def _home_svg_data_uri(svg):
    return "data:image/svg+xml;charset=UTF-8," + quote(
        svg, safe="-_.!~*'()", encoding="utf-8", errors="strict"
    )


def _home_movie_placeholder(movie):
    # Server-side equivalent of boxOfficeXMoviePlaceholder().
    title = str(movie.get("title") or "Movie").strip() or "Movie"
    parts = []
    for word in title.upper().split():
        if len(word) <= 10:
            parts.append(word)
        else:
            parts.extend(word[i:i + 10] for i in range(0, len(word), 10))
    lines, current = [], ""
    for part in parts:
        next_value = f"{current} {part}" if current else part
        if len(next_value) > 10 and current:
            lines.append(current)
            current = part
        else:
            current = next_value
    if current:
        lines.append(current)
    if not lines:
        lines = ["MOVIE"]
    if len(lines) > 4:
        lines = lines[:4]
        lines[3] = lines[3][:9] + "…"
    gap = 76
    start = 390 - ((len(lines) - 1) * gap / 2)
    title_svg = "".join(
        f'<text x="300" y="{start + index * gap:g}" text-anchor="middle" fill="#171717" font-family="Arial,Helvetica,sans-serif" font-size="64" font-weight="900" letter-spacing="1">{xml_escape(line)}</text>'
        for index, line in enumerate(lines)
    )
    release_value = str(movie.get("release_date") or movie.get("year") or "")
    match = re.search(r"\b(?:19|20)\d{2}\b", release_value)
    year = match.group(0) if match else ""
    language = str(movie.get("language") or "").strip().upper()
    meta = "  •  ".join(part for part in (year, language) if part)
    meta_svg = (
        f'<text x="300" y="575" text-anchor="middle" fill="#242424" font-family="Arial,Helvetica,sans-serif" font-size="25" font-weight="500" letter-spacing="7">{xml_escape(meta)}</text>'
        if meta else ""
    )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 900" role="img" aria-label="{xml_escape(title)} movie placeholder">
      <defs>
        <linearGradient id="paper" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#fbfaf7"/><stop offset=".52" stop-color="#f4f2ed"/><stop offset="1" stop-color="#ebe9e4"/></linearGradient>
        <filter id="grain"><feTurbulence type="fractalNoise" baseFrequency=".78" numOctaves="3" seed="9"/><feColorMatrix type="saturate" values="0"/><feComponentTransfer><feFuncA type="table" tableValues="0 .055"/></feComponentTransfer></filter>
        <linearGradient id="fade" x1="0" y1="0" x2="1" y2="0"><stop stop-color="#9b9b9b" stop-opacity=".25"/><stop offset="1" stop-color="#c8c8c8" stop-opacity=".06"/></linearGradient>
      </defs>
      <rect width="600" height="900" fill="url(#paper)"/><rect width="600" height="900" filter="url(#grain)" opacity=".72"/>
      <g opacity=".22" transform="rotate(24 45 230)"><rect x="-48" y="-55" width="90" height="520" rx="8" fill="url(#fade)"/><path d="M-32-35v480M26-35v480" stroke="#888" stroke-width="5" stroke-dasharray="18 13"/></g>
      <g opacity=".18" transform="rotate(-18 570 720)"><rect x="550" y="505" width="92" height="470" rx="8" fill="url(#fade)"/><path d="M566 520v430M624 520v430" stroke="#888" stroke-width="5" stroke-dasharray="18 13"/></g>
      <circle cx="64" cy="790" r="120" fill="none" stroke="#a8a8a8" stroke-width="24" opacity=".08"/>{title_svg}
      <line x1="115" y1="525" x2="485" y2="525" stroke="#ad1726" stroke-width="5"/>{meta_svg}
      <text x="300" y="846" text-anchor="middle" fill="#242424" font-family="Arial,Helvetica,sans-serif" font-size="13" font-weight="700" letter-spacing="5">BOXOFFICEX MOVIE PLACEHOLDER</text>
    </svg>'''
    return _home_svg_data_uri(svg)


def _home_actor_placeholder(name):
    # Server-side equivalent of boxOfficeXActorPlaceholder().
    actor_name = str(name or "Actor").strip() or "Actor"
    colors = _home_placeholder_colors(actor_name)
    words = actor_name.split()
    initials = "BX" if not words else (words[0][:2].upper() if len(words) == 1 else "".join(word[0] for word in words[:3]).upper())
    name_size = 50 if len(actor_name) <= 11 else 42 if len(actor_name) <= 17 else 34
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 760"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{colors[0]}"/><stop offset=".56" stop-color="{colors[1]}"/><stop offset="1" stop-color="{colors[2]}"/></linearGradient><radialGradient id="r" cx="78%" cy="12%" r="74%"><stop offset="0" stop-color="{colors[3]}" stop-opacity=".28"/><stop offset="1" stop-color="{colors[3]}" stop-opacity="0"/></radialGradient><linearGradient id="glass"><stop stop-color="#fff" stop-opacity=".3"/><stop offset="1" stop-color="#fff" stop-opacity=".03"/></linearGradient></defs><rect width="600" height="760" rx="28" fill="url(#g)"/><rect width="600" height="760" rx="28" fill="url(#r)"/><circle cx="500" cy="90" r="150" fill="{colors[3]}" fill-opacity=".13"/><rect x="92" y="104" width="416" height="414" rx="78" fill="url(#glass)" stroke="#fff" stroke-opacity=".38" stroke-width="4"/><circle cx="300" cy="300" r="164" fill="#fff" fill-opacity=".09" stroke="#fff" stroke-opacity=".24" stroke-width="3"/><text x="300" y="342" text-anchor="middle" fill="#fff" font-family="Arial,sans-serif" font-size="118" font-weight="800">{xml_escape(initials)}</text><line x1="155" y1="544" x2="445" y2="544" stroke="{colors[3]}" stroke-width="11" stroke-linecap="round"/><text x="300" y="608" text-anchor="middle" fill="#fff" font-family="Arial,sans-serif" font-size="{name_size}" font-weight="800">{xml_escape(actor_name)}</text><rect x="142" y="646" width="316" height="82" rx="24" fill="#fff" fill-opacity=".9"/><text x="300" y="691" text-anchor="middle" font-family="Arial,sans-serif" font-size="24" font-weight="900"><tspan fill="#101828">BOXOFFICE</tspan><tspan fill="#f4b400">X</tspan></text><text x="300" y="716" text-anchor="middle" fill="#344054" font-family="Arial,sans-serif" font-size="12" font-weight="700">ACTOR PROFILE</text></svg>'
    )
    return _home_svg_data_uri(svg)


def _home_article_placeholder(article):
    # Server-side equivalent of boxOfficeXArticlePlaceholder().
    title = str(article.get("title") or "BoxOfficeX Article").strip() or "BoxOfficeX Article"
    category = str(article.get("category") or "TRENDING ARTICLE").strip().upper()
    colors = _home_placeholder_colors(title)
    lines, current = [], ""
    for word in title.split():
        next_value = f"{current} {word}" if current else word
        if len(next_value) > 28 and current:
            lines.append(current)
            current = word
        else:
            current = next_value
    if current:
        lines.append(current)
    if len(lines) > 3:
        lines = lines[:3]
        lines[2] = lines[2][:25] + "…"
    start = 292 - ((len(lines) - 1) * 48 / 2)
    title_svg = "".join(
        f'<text x="600" y="{start + index * 48:g}" text-anchor="middle" fill="#fff" font-family="Arial,Helvetica,sans-serif" font-size="38" font-weight="900">{xml_escape(line)}</text>'
        for index, line in enumerate(lines)
    )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 675" role="img" aria-label="{xml_escape(title)} article placeholder"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="{colors[0]}"/><stop offset=".55" stop-color="{colors[1]}"/><stop offset="1" stop-color="{colors[2]}"/></linearGradient><radialGradient id="r" cx="82%" cy="10%" r="78%"><stop stop-color="{colors[3]}" stop-opacity=".34"/><stop offset="1" stop-color="{colors[3]}" stop-opacity="0"/></radialGradient></defs><rect width="1200" height="675" fill="url(#g)"/><rect width="1200" height="675" fill="url(#r)"/><circle cx="1060" cy="80" r="250" fill="#fff" opacity=".05"/><circle cx="130" cy="620" r="220" fill="#fff" opacity=".04"/><rect x="120" y="105" width="960" height="465" rx="34" fill="#fff" opacity=".08" stroke="#fff" stroke-opacity=".28" stroke-width="3"/><text x="600" y="190" text-anchor="middle" fill="{colors[3]}" font-family="Arial,Helvetica,sans-serif" font-size="18" font-weight="900" letter-spacing="6">{xml_escape(category)}</text>{title_svg}<line x1="385" y1="405" x2="815" y2="405" stroke="{colors[3]}" stroke-width="7" stroke-linecap="round"/><text x="600" y="485" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="27" font-weight="900"><tspan fill="#fff">BOXOFFICE</tspan><tspan fill="#ffd43b">X</tspan></text><text x="600" y="522" text-anchor="middle" fill="#fff" opacity=".72" font-family="Arial,Helvetica,sans-serif" font-size="13" font-weight="700" letter-spacing="5">ARTICLE</text></svg>'
    )
    return _home_svg_data_uri(svg)


def _home_movie_card(movie, slug_map, rank=None, running_day=None, upcoming_days=None):
    movie_id = int(movie["id"])
    title_raw = str(movie.get("title") or "Untitled")
    title = html_escape(title_raw)
    language = html_escape(str(movie.get("language") or "Cinema"))
    industry = html_escape(str(movie.get("industry") or ""))
    release_date = html_escape(str(movie.get("release_date") or ""))
    verdict = html_escape(str(movie.get("verdict") or "Box Office"))
    image = html_escape(_home_movie_placeholder(movie), quote=True)
    slug = slug_map.get(movie_id)
    url = html_escape(f"/movie/{slug}" if slug else "/new-movies.html", quote=True)
    collection = float(movie.get("worldwide_collection_crore") or 0)
    classes = "movie-card ranking-card" if rank else "movie-card"
    rank_html = f'<div class="ranking-number">#{int(rank)}</div>' if rank else ""
    badge_html = ""
    timing_html = ""
    if running_day is not None:
        badge_html = '<div class="home-release-badge running">RUNNING</div>'
        timing_html = f'<p class="home-release-timing">Running • Day {int(running_day)}</p>'
    elif upcoming_days is not None:
        days = int(upcoming_days)
        countdown = "Tomorrow" if days == 1 else f"{days} Days Left"
        timing_html = f'<span class="upcoming-countdown">{html_escape(countdown)}</span>'
    meta_parts = [part for part in (language, industry) if part]
    meta_html = f'<p>{" • ".join(meta_parts)}</p>' if meta_parts else ""
    date_html = f'<p>📅 {release_date}</p>' if release_date and not rank else ""
    collection_html = f'<p class="movie-collection">🌍 ₹{collection:.2f} Cr</p>' if collection > 0 else ""
    verdict_html = f'<p class="movie-verdict">{verdict}</p>' if rank else ""
    return (
        f'<article class="{classes}"><a href="{url}" aria-label="View {title}">{rank_html}{badge_html}'
        f'<img class="movie-poster" src="{image}" alt="{title}" loading="lazy" decoding="async" onerror="setMovieFallback(this)">'
        f'<div class="movie-info"><h3>{title}</h3>{timing_html}{date_html}{meta_html}{collection_html}{verdict_html}</div></a></article>'
    )


def _home_article_image_url(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if _is_remote_image(value):
        return value
    if value.startswith("/"):
        return value
    if value.startswith("article-images/"):
        return f"/{value}"
    return f"/article-images/{value}"


def _home_cloudinary_article_thumbnail(value, width=500):
    """Return a lighter Cloudinary URL for homepage article cards only.

    The stored/original URL is never changed. Non-Cloudinary URLs are returned
    untouched. c_limit preserves the original aspect ratio while f_auto/q_auto
    let Cloudinary choose an efficient browser format and quality.
    """
    original = _home_article_image_url(value)
    if not original:
        return "", ""

    try:
        parsed = urlparse(original)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.netloc.lower().endswith("res.cloudinary.com")
            and "/image/upload/" in parsed.path
        ):
            marker = "/image/upload/"
            transform = f"f_auto,q_auto,w_{int(width)},c_limit/"
            optimized = original.replace(marker, marker + transform, 1)
            return optimized, original
    except Exception:
        pass

    return original, original


def _home_article_card(article, rank):
    title_raw = str(article.get("title") or "Untitled Article")
    category_raw = str(article.get("category") or "BoxOfficeX Article")
    title = html_escape(title_raw)
    category = html_escape(category_raw)
    slug = html_escape(str(article.get("slug") or ""), quote=True)
    url = f"/article/{slug}" if slug else "/articles.html"
    image, original_image = _home_cloudinary_article_thumbnail(article.get("hero_image"), width=500)
    image = image or _home_article_placeholder(article)
    original_image = original_image or image
    views = int(article.get("view_count") or 0)
    likes = int(article.get("like_count") or 0)
    hype = int(article.get("hype_count") or 0)
    comments = int(article.get("comment_count") or 0)
    image_html = (
        f'<img class="article-trending-image" src="{html_escape(image, quote=True)}" alt="{title}" '
        f'data-original-src="{html_escape(original_image, quote=True)}" '
        f'data-article-title="{html_escape(title_raw, quote=True)}" data-article-category="{html_escape(category_raw, quote=True)}" '
        'loading="lazy" decoding="async" '
        'onerror="if(this.dataset.originalSrc&&this.src!==this.dataset.originalSrc){this.src=this.dataset.originalSrc;this.dataset.originalSrc='';}else{setArticleFallback(this)}">'
    )
    return (
        '<article class="article-trending-card">'
        f'<a href="{url}" aria-label="Read {title}"><div class="ranking-number">#{int(rank)}</div>{image_html}'
        f'<div class="article-trending-copy"><div class="article-trending-type">{category}</div>'
        f'<h3 class="article-trending-title">{title}</h3>'
        f'<div class="article-trending-stats">👁 {views:,} • ❤️ {likes:,} • 🔥 {hype:,} • 💬 {comments:,}</div></div></a></article>'
    )


def _home_actor_card(actor, actor_slug_map):
    actor_id = int(actor["id"])
    name_raw = str(actor.get("name") or "Actor")
    name = html_escape(name_raw)
    profession = html_escape(str(actor.get("profession") or "Actor"))
    image = html_escape(_home_actor_placeholder(name_raw), quote=True)
    slug = actor_slug_map.get(actor_id)
    url = html_escape(f"/actor/{slug}" if slug else "/actors.html", quote=True)
    return (
        '<article class="actor-card">'
        f'<a href="{url}" aria-label="View {name}"><div class="actor-image-wrap">'
        f'<img src="{image}" alt="{name}" loading="lazy" decoding="async" onerror="setActorFallback(this)"></div>'
        f'<h3>{name}</h3><p>{profession}</p></a></article>'
    )


def _build_homepage_ssr_sections():
    """Build SEO-critical homepage sections without letting one failed query kill SSR."""
    today = date.today()

    # Slugs are shared by all three sections. If this fails, cards still render
    # with the safe New Movies fallback rather than returning the raw template.
    try:
        slug_map = _unique_movie_slug_map()
    except Exception as exc:
        print(f"Homepage SSR slug-map warning: {exc}", flush=True)
        slug_map = {}

    def movie_from_row(row):
        return {
            "id": row[0],
            "title": row[1],
            "release_date": row[2].isoformat() if row[2] else None,
            "language": row[3],
            "industry": row[4],
            "worldwide_collection_crore": float(row[5]) if row[5] is not None else None,
            "verdict": row[6],
            "poster": row[7],
        }

    # Each section uses its own short DB transaction. A ranking/data problem can
    # no longer force the whole homepage to fall back to untouched index.html.
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, title, release_date, language, industry,
                           worldwide_collection_crore, verdict, poster
                    FROM movies
                    WHERE release_date IS NOT NULL
                      AND release_date BETWEEN CURRENT_DATE - 9 AND CURRENT_DATE
                    ORDER BY release_date DESC, id DESC
                    LIMIT 5
                """)
                running_rows = cur.fetchall()
        running_html = [
            _home_movie_card(
                movie_from_row(row), slug_map,
                running_day=(today - row[2]).days + 1,
            )
            for row in running_rows
        ]
        running = "\n".join(running_html) or '<div class="movie-empty">No running movies are inside the current 10-day release window.</div>'
    except Exception as exc:
        print(f"Homepage SSR running warning: {exc}", flush=True)
        running = '<div class="movie-empty">Running movies are being updated.</div>'

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, title, release_date, language, industry,
                           worldwide_collection_crore, verdict, poster,
                           (release_date - CURRENT_DATE) AS days_until_release
                    FROM movies
                    WHERE release_date IS NOT NULL
                      AND release_date > CURRENT_DATE
                    ORDER BY release_date ASC, id ASC
                    LIMIT 10
                """)
                upcoming_rows = cur.fetchall()
        upcoming_html = [
            _home_movie_card(
                movie_from_row(row[:8]), slug_map,
                upcoming_days=int(row[8] or 0),
            )
            for row in upcoming_rows
        ]
        upcoming = "\n".join(upcoming_html) or '<div class="movie-empty">No upcoming movies added yet.</div>'
    except Exception as exc:
        print(f"Homepage SSR upcoming warning: {exc}", flush=True)
        upcoming = '<div class="movie-empty">Upcoming movies are being updated.</div>'

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, title, release_date, language, industry,
                           worldwide_collection_crore, verdict, poster
                    FROM movies
                    WHERE worldwide_collection_crore IS NOT NULL
                      AND worldwide_collection_crore > 0
                    ORDER BY worldwide_collection_crore DESC NULLS LAST, id ASC
                    LIMIT 10
                """)
                ranking_rows = cur.fetchall()
        ranking_html = [
            _home_movie_card(movie_from_row(row), slug_map, rank=rank)
            for rank, row in enumerate(ranking_rows, start=1)
        ]
        rankings = "\n".join(ranking_html) or '<div class="movie-empty">No ranking data available.</div>'
    except Exception as exc:
        print(f"Homepage SSR rankings warning: {exc}", flush=True)
        rankings = '<div class="movie-empty">Rankings are being updated.</div>'

    # Trending articles: same 7-day activity formula as /articles/trending.
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    WITH article_activity AS (
                        SELECT a.id, a.title, a.slug, a.category, a.hero_image,
                               a.published_at, COALESCE(a.views, 0)::bigint AS view_count,
                               (SELECT COUNT(*) FROM article_likes l
                                WHERE l.article_id=a.id AND l.created_at >= NOW() - INTERVAL '7 days')::bigint AS like_count,
                               (SELECT COUNT(*) FROM article_hype h
                                WHERE h.article_id=a.id AND h.created_at >= NOW() - INTERVAL '7 days')::bigint AS hype_count,
                               (SELECT COUNT(*) FROM article_comments c
                                WHERE c.article_id=a.id AND c.created_at >= NOW() - INTERVAL '7 days'
                                  AND c.is_hidden=FALSE AND c.is_deleted=FALSE)::bigint AS comment_count
                        FROM articles a
                        WHERE a.status='published'
                    )
                    SELECT id, title, slug, category, hero_image, published_at,
                           view_count, like_count, hype_count, comment_count,
                           (view_count + like_count*2 + hype_count*3 + comment_count*3)::bigint AS trending_score
                    FROM article_activity
                    WHERE (view_count + like_count*2 + hype_count*3 + comment_count*3) > 0
                    ORDER BY trending_score DESC, hype_count DESC, view_count DESC,
                             published_at DESC NULLS LAST, id DESC
                    LIMIT 10
                """)
                article_rows = cur.fetchall()
        trending_articles_html = []
        for rank, row in enumerate(article_rows, start=1):
            article = {
                "id": row[0], "title": row[1], "slug": row[2], "category": row[3],
                "hero_image": row[4], "view_count": row[6], "like_count": row[7],
                "hype_count": row[8], "comment_count": row[9],
            }
            trending_articles_html.append(_home_article_card(article, rank))
        trending_articles = "\n".join(trending_articles_html) or '<div class="movie-empty">Trending articles will appear as readers interact with articles.</div>'
    except Exception as exc:
        print(f"Homepage SSR trending-articles warning: {exc}", flush=True)
        trending_articles = '<div class="movie-empty">Trending articles are being updated.</div>'

    # Popular actors: same interaction-weighted ranking as /actors/popular.
    try:
        actor_slug_map = _unique_actor_slug_map()
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.id, a.name, a.profession, a.photo,
                           (SELECT COUNT(*) FROM actor_views av WHERE av.actor_id=a.id) AS view_count,
                           (SELECT COUNT(*) FROM hero_comparison_likes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id) AS comparison_likes,
                           (SELECT COUNT(*) FROM hero_comparison_hype h WHERE h.actor1_id=a.id OR h.actor2_id=a.id) AS comparison_hype,
                           (SELECT COUNT(*) FROM hero_comparison_votes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id) AS comparison_votes,
                           (SELECT COUNT(*) FROM hero_comparison_comments h
                            WHERE (h.actor1_id=a.id OR h.actor2_id=a.id)
                              AND h.is_hidden=FALSE AND h.is_deleted=FALSE) AS comparison_comments
                    FROM actors a
                    ORDER BY (
                        5 * LN(1 + (SELECT COUNT(*) FROM actor_views av WHERE av.actor_id=a.id))
                        + 8 * (SELECT COUNT(*) FROM hero_comparison_likes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id)
                        + 14 * (SELECT COUNT(*) FROM hero_comparison_hype h WHERE h.actor1_id=a.id OR h.actor2_id=a.id)
                        + 10 * (SELECT COUNT(*) FROM hero_comparison_votes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id)
                        + 12 * (SELECT COUNT(*) FROM hero_comparison_comments h
                                WHERE (h.actor1_id=a.id OR h.actor2_id=a.id)
                                  AND h.is_hidden=FALSE AND h.is_deleted=FALSE)
                    ) DESC, a.id ASC
                    LIMIT 10
                """)
                actor_rows = cur.fetchall()
        popular_actors_html = [
            _home_actor_card({"id": r[0], "name": r[1], "profession": r[2], "photo": r[3]}, actor_slug_map)
            for r in actor_rows
        ]
        popular_actors = "\n".join(popular_actors_html) or '<div class="movie-empty">Popular actors are being updated.</div>'
    except Exception as exc:
        print(f"Homepage SSR popular-actors warning: {exc}", flush=True)
        popular_actors = '<div class="movie-empty">Popular actors are being updated.</div>'

    return {
        "running": running,
        "upcoming": upcoming,
        "rankings": rankings,
        "trending_articles": trending_articles,
        "popular_actors": popular_actors,
    }


def _render_homepage_html():
    template = _inject_boxofficex_global_icons((BASE_DIR / "index.html").read_text(encoding="utf-8"))
    sections = _build_homepage_ssr_sections()

    replacements = {
        "<!-- BOXOFFICEX_SSR_RUNNING -->": sections["running"],
        "<!-- BOXOFFICEX_SSR_UPCOMING -->": sections["upcoming"],
        "<!-- BOXOFFICEX_SSR_RANKINGS -->": sections["rankings"],
        "<!-- BOXOFFICEX_SSR_TRENDING_ARTICLES -->": sections["trending_articles"],
        "<!-- BOXOFFICEX_SSR_POPULAR_ACTORS -->": sections["popular_actors"],
    }

    for marker, content in replacements.items():
        if marker not in template:
            raise RuntimeError(f"Homepage SSR marker missing: {marker}")
        template = template.replace(marker, content, 1)

    # The browser loaders use this marker to avoid replacing the server-rendered copy.
    template = template.replace('id="latestMoviesGrid"', 'id="latestMoviesGrid" data-ssr="1"', 1)
    template = template.replace('id="upcomingMoviesGrid"', 'id="upcomingMoviesGrid" data-ssr="1"', 1)
    template = template.replace('id="rankingGrid"', 'id="rankingGrid" data-ssr="1"', 1)
    template = template.replace('id="trendingArticlesGrid"', 'id="trendingArticlesGrid" data-ssr="1"', 1)
    template = template.replace('id="actorsGrid"', 'id="actorsGrid" data-ssr="1"', 1)
    return template


def _refresh_homepage_cache():
    global _home_html_refreshing
    try:
        rendered = _render_homepage_html()
        with _home_html_cache_lock:
            _home_html_cache["html"] = rendered
            _home_html_cache["expires_at"] = time_module.monotonic() + HOME_HTML_CACHE_TTL
    except Exception as exc:
        print(f"Homepage SSR cache refresh failed: {exc}")
    finally:
        _home_html_refreshing = False


def _start_homepage_refresh():
    global _home_html_refreshing
    with _home_html_cache_lock:
        if _home_html_refreshing:
            return
        _home_html_refreshing = True
    threading.Thread(target=_refresh_homepage_cache, daemon=True).start()


def _get_cached_homepage_html():
    now = time_module.monotonic()
    cached_html = _home_html_cache.get("html")
    expires_at = float(_home_html_cache.get("expires_at") or 0)

    if cached_html and now < expires_at:
        return cached_html, "HIT"

    # Stale-while-revalidate: after the first successful render, never make a
    # visitor wait for a routine cache refresh.
    if cached_html:
        _start_homepage_refresh()
        return cached_html, "STALE"

    # True cold start fallback: build once synchronously if startup warm-up has
    # not completed yet. The result is cached for following requests.
    rendered = _render_homepage_html()
    with _home_html_cache_lock:
        _home_html_cache["html"] = rendered
        _home_html_cache["expires_at"] = time_module.monotonic() + HOME_HTML_CACHE_TTL
    return rendered, "MISS"


@app.on_event("startup")
def warm_homepage_ssr_cache():
    # Warm in the background so application startup itself is not blocked.
    _start_homepage_refresh()


@app.get("/")
def home():
    try:
        html, cache_status = _get_cached_homepage_html()
        return HTMLResponse(
            content=html,
            headers={
                "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                "X-BoxOfficeX-Homepage": "cached-ssr",
                "X-BoxOfficeX-Cache": cache_status,
            },
        )
    except Exception as exc:
        print(f"Homepage SSR fallback: {type(exc).__name__}: {exc}", flush=True)
        return FileResponse(
            BASE_DIR / "index.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Homepage": "ssr-fallback",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
            },
        )




# ============================================================
# SEO FILES
# ============================================================

SITEMAP_SITE_URL = "https://boxofficex.in"

_sitemap_cache = {}


def _xml_response(xml):
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=86400"}
    )


def _sitemap_url_entry(path, changefreq=None, priority=None, lastmod=None):
    loc = xml_escape(SITEMAP_SITE_URL + path)
    parts = ["  <url>", f"    <loc>{loc}</loc>"]

    if lastmod:
        # Google sitemap <lastmod>: use a stable W3C calendar date (YYYY-MM-DD).
        if isinstance(lastmod, datetime):
            lastmod_value = lastmod.date().isoformat()
        elif isinstance(lastmod, date):
            lastmod_value = lastmod.isoformat()
        else:
            raw_lastmod = str(lastmod).strip()
            lastmod_value = raw_lastmod.split("T", 1)[0].split(" ", 1)[0]

        parts.append(
            f"    <lastmod>{xml_escape(lastmod_value)}</lastmod>"
        )

    if changefreq:
        parts.append(f"    <changefreq>{changefreq}</changefreq>")

    if priority:
        parts.append(f"    <priority>{priority}</priority>")

    parts.append("  </url>")
    return "\n".join(parts)


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    """
    BoxOfficeX master sitemap index.

    Connects Google and other search engines to all specialized
    BoxOfficeX sitemaps through one stable sitemap.xml endpoint.
    """

    sitemap_paths = [
        "/sitemap-movies.xml",
        "/sitemap-actors.xml",
        "/sitemap-movie-compare.xml",
        "/sitemap-actor-compare.xml",
        "/sitemap-articles.xml",
        "/sitemap-movie-rankings.xml",
        "/sitemap-actor-rankings.xml",
        "/sitemap-pages.xml",
        "/news-sitemap.xml",
    ]

    sitemap_entries = []

    for path in sitemap_paths:
        loc = xml_escape(SITEMAP_SITE_URL + path)
        sitemap_entries.append(
            "  <sitemap>\n"
            f"    <loc>{loc}</loc>\n"
            "  </sitemap>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(sitemap_entries)
        + '\n</sitemapindex>\n'
    )

    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=300"}
    )


# ============================================================
# GOOGLE NEWS SITEMAP
# Latest published BoxOfficeX articles from the last 2 days
# ============================================================

@app.get("/news-sitemap.xml", include_in_schema=False)
def news_sitemap_xml():
    """
    Google News sitemap for BoxOfficeX.

    Google News sitemaps should contain recent news URLs only.
    This endpoint includes published articles from the last 2 days
    and is intentionally separate from the main sitemap.xml.
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    title,
                    slug,
                    COALESCE(published_at, created_at) AS publication_date
                FROM articles
                WHERE status = 'published'
                  AND slug IS NOT NULL
                  AND TRIM(slug) <> ''
                  AND COALESCE(published_at, created_at)
                      >= NOW() - INTERVAL '2 days'
                ORDER BY
                    COALESCE(published_at, created_at) DESC,
                    id DESC
                LIMIT 1000
            """)
            article_rows = cur.fetchall()

    urls = []

    india_tz = ZoneInfo("Asia/Kolkata")

    for title, slug, publication_date in article_rows:
        if not title or not publication_date:
            continue

        # Convert the stored publication timestamp to India Standard Time.
        # If PostgreSQL returns a naive datetime, treat it as UTC first.
        if publication_date.tzinfo is None:
            publication_date = publication_date.replace(
                tzinfo=timezone.utc
            )

        publication_date = publication_date.astimezone(india_tz)

        article_url = xml_escape(
            f"{SITEMAP_SITE_URL}/article/{str(slug).strip()}"
        )
        news_title = xml_escape(str(title).strip())
        published_iso = xml_escape(
            publication_date.isoformat(timespec="seconds")
        )

        urls.append(
            "  <url>\n"
            f"    <loc>{article_url}</loc>\n"
            "    <news:news>\n"
            "      <news:publication>\n"
            "        <news:name>BoxOfficeX</news:name>\n"
            "        <news:language>en</news:language>\n"
            "      </news:publication>\n"
            f"      <news:publication_date>{published_iso}</news:publication_date>\n"
            f"      <news:title>{news_title}</news:title>\n"
            "    </news:news>\n"
            "  </url>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
        'xmlns:news="http://www.google.com/schemas/sitemap-news/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    # Keep the News sitemap much fresher than the normal 24-hour sitemap.
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=300"}
    )


# ============================================================
# MOVIE SITEMAP
# Top 25 important BoxOfficeX movie pages
# ============================================================

@app.get("/sitemap-movies.xml", include_in_schema=False)
def sitemap_movies_xml():
    """
    BoxOfficeX movie sitemap.

    Contains the Top 25 movie detail pages ranked by
    worldwide box-office collection.
    """

    cached = _sitemap_cache.get("movies")
    if cached is not None:
        return _xml_response(cached)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    release_date,
                    worldwide_collection_crore
                FROM movies
                WHERE worldwide_collection_crore IS NOT NULL
                  AND worldwide_collection_crore > 0
                ORDER BY
                    worldwide_collection_crore DESC,
                    id ASC
                LIMIT 25
            """)

            movie_rows = cur.fetchall()

    movie_slug_map = _unique_movie_slug_map()

    urls = []

    for movie_id, release_date, worldwide_collection in movie_rows:
        movie_slug = movie_slug_map.get(movie_id)

        if not movie_slug:
            continue

        urls.append(
            _sitemap_url_entry(
                f"/movie/{movie_slug}",
                "weekly",
                "0.8",
                release_date
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    _sitemap_cache["movies"] = xml

    return _xml_response(xml)

# ============================================================
# ACTOR SITEMAP
# 25 important BoxOfficeX actor pages
# ============================================================

@app.get("/sitemap-actors.xml", include_in_schema=False)
def sitemap_actors_xml():
    """
    BoxOfficeX actor sitemap.

    Contains 25 selected major Indian actors across
    Tamil, Telugu, Hindi, Malayalam and Kannada cinema.
    """

    cached = _sitemap_cache.get("actors")
    if cached is not None:
        return _xml_response(cached)

    selected_actor_names = [
        # Tamil
        "Rajinikanth",
        "Vijay",
        "Ajith Kumar",
        "Kamal Haasan",
        "Suriya",

        # Telugu
        "Prabhas",
        "Allu Arjun",
        "Ram Charan",
        "N. T. Rama Rao Jr.",
        "Mahesh Babu",

        # Hindi
        "Shah Rukh Khan",
        "Salman Khan",
        "Aamir Khan",
        "Ranbir Kapoor",
        "Hrithik Roshan",

        # Malayalam
        "Mohanlal",
        "Mammootty",
        "Dulquer Salmaan",
        "Fahadh Faasil",
        "Prithviraj Sukumaran",

        # Kannada
        "Yash",
        "Kichcha Sudeep",
        "Darshan",
        "Shiva Rajkumar",
        "Rishab Shetty",
    ]

    selected_actor_names_lower = [
        name.strip().lower()
        for name in selected_actor_names
    ]

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    name
                FROM actors
                WHERE LOWER(TRIM(name)) = ANY(%s)
            """, (selected_actor_names_lower,))

            actor_rows = cur.fetchall()

    actor_slug_map = _unique_actor_slug_map()

    # Keep sitemap order identical to our selected actor list.
    actors_by_name = {
        str(actor_name).strip().lower(): actor_id
        for actor_id, actor_name in actor_rows
    }

    urls = []

    for actor_name in selected_actor_names:
        actor_id = actors_by_name.get(actor_name.lower())

        if not actor_id:
            continue

        actor_slug = actor_slug_map.get(actor_id)

        if not actor_slug:
            continue

        urls.append(
            _sitemap_url_entry(
                f"/actor/{actor_slug}",
                "weekly",
                "0.8"
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    _sitemap_cache["actors"] = xml

    return _xml_response(xml)


# ============================================================
# ACTOR COMPARISON SITEMAP
# 25 important BoxOfficeX actor comparison pages
# ============================================================

@app.get("/sitemap-actor-compare.xml", include_in_schema=False)
def sitemap_actor_compare_xml():
    """
    BoxOfficeX actor comparison sitemap.

    Contains 25 selected high-value actor comparison pages.
    """

    cached = _sitemap_cache.get("actor_compare")
    if cached is not None:
        return _xml_response(cached)

    comparison_pairs = [
        # Tamil
        ("Vijay", "Ajith Kumar"),
        ("Rajinikanth", "Kamal Haasan"),
        ("Vijay", "Rajinikanth"),
        ("Vijay", "Suriya"),
        ("Ajith Kumar", "Suriya"),

        # Telugu
        ("Prabhas", "Allu Arjun"),
        ("Prabhas", "Ram Charan"),
        ("Prabhas", "N. T. Rama Rao Jr."),
        ("Allu Arjun", "Ram Charan"),
        ("Mahesh Babu", "N. T. Rama Rao Jr."),

        # Hindi
        ("Shah Rukh Khan", "Salman Khan"),
        ("Shah Rukh Khan", "Aamir Khan"),
        ("Salman Khan", "Aamir Khan"),
        ("Ranbir Kapoor", "Hrithik Roshan"),
        ("Shah Rukh Khan", "Ranbir Kapoor"),

        # Malayalam
        ("Mohanlal", "Mammootty"),
        ("Dulquer Salmaan", "Fahadh Faasil"),
        ("Mohanlal", "Prithviraj Sukumaran"),
        ("Mammootty", "Dulquer Salmaan"),
        ("Fahadh Faasil", "Prithviraj Sukumaran"),

        # Kannada
        ("Yash", "Kichcha Sudeep"),
        ("Yash", "Darshan"),
        ("Yash", "Rishab Shetty"),
        ("Kichcha Sudeep", "Darshan"),
        ("Shiva Rajkumar", "Rishab Shetty"),
    ]

    # Get every actor needed for the selected comparisons.
    required_names = {
        name.strip().lower()
        for pair in comparison_pairs
        for name in pair
    }

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    name
                FROM actors
                WHERE LOWER(TRIM(name)) = ANY(%s)
            """, (list(required_names),))

            actor_rows = cur.fetchall()

    actor_slug_map = _unique_actor_slug_map()

    actors_by_name = {
        str(actor_name).strip().lower(): actor_id
        for actor_id, actor_name in actor_rows
    }

    urls = []
    seen_urls = set()

    for first_name, second_name in comparison_pairs:
        first_id = actors_by_name.get(first_name.lower())
        second_id = actors_by_name.get(second_name.lower())

        if not first_id or not second_id:
            continue

        first_slug = actor_slug_map.get(first_id)
        second_slug = actor_slug_map.get(second_id)

        if not first_slug or not second_slug:
            continue

        # Keep the canonical ordering used by the comparison system.
        if first_id > second_id:
            first_slug, second_slug = second_slug, first_slug

        path = f"/compare/{first_slug}-vs-{second_slug}"

        # Prevent accidental duplicate canonical URLs.
        if path in seen_urls:
            continue

        seen_urls.add(path)

        urls.append(
            _sitemap_url_entry(
                path,
                "weekly",
                "0.8"
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    _sitemap_cache["actor_compare"] = xml

    return _xml_response(xml)


# ============================================================
# MOVIE COMPARISON SITEMAP
# 25 curated high-value BoxOfficeX movie comparison pages
# ============================================================

@app.get("/sitemap-movie-compare.xml", include_in_schema=False)
def sitemap_movie_compare_xml():
    """
    BoxOfficeX movie comparison sitemap.

    Contains 25 manually selected high-value movie
    comparison pages.

    Uses BoxOfficeX's existing canonical movie slug map
    and canonical ID ordering.
    """

    cached = _sitemap_cache.get("movie_compare")
    if cached is not None:
        return _xml_response(cached)

    # --------------------------------------------------------
    # 25 curated high-value comparison pairs
    # --------------------------------------------------------

    comparison_pairs = [
        # Major all-time / pan-India comparisons
        ("dangal-2016", "baahubali-2-the-conclusion-2017"),
        ("dangal-2016", "pushpa-2-the-rule-2024"),
        ("baahubali-2-the-conclusion-2017", "pushpa-2-the-rule-2024"),

        # Telugu / pan-India
        ("rrr-2022", "kgf-chapter-2-2022"),
        ("rrr-2022", "baahubali-2-the-conclusion-2017"),
        ("pushpa-2-the-rule-2024", "rrr-2022"),
        ("kalki-2898-ad-2024", "rrr-2022"),
        ("kalki-2898-ad-2024", "pushpa-2-the-rule-2024"),

        # KGF / pan-India
        ("kgf-chapter-2-2022", "pushpa-2-the-rule-2024"),
        ("kgf-chapter-2-2022", "baahubali-2-the-conclusion-2017"),

        # Hindi
        ("jawan-2023", "pathaan-2023"),
        ("jawan-2023", "animal-2023"),
        ("pathaan-2023", "animal-2023"),
        ("stree-2-2024", "animal-2023"),
        ("stree-2-2024", "jawan-2023"),
        ("pk-2014", "dangal-2016"),
        ("bajrangi-bhaijaan-2015", "dangal-2016"),
        ("sultan-2016", "bajrangi-bhaijaan-2015"),

        # Baahubali franchise
        (
            "baahubali-the-beginning-2015",
            "baahubali-2-the-conclusion-2017"
        ),

        # Tamil
        ("jailer-2023", "leo-2023"),
        ("jailer-2023", "2-0-2018"),
        ("leo-2023", "2-0-2018"),

        # Salaar / KGF / RRR
        (
            "salaar-cease-fire-part-1-2023",
            "kgf-chapter-2-2022"
        ),
        (
            "salaar-cease-fire-part-1-2023",
            "rrr-2022"
        ),

        # Kannada
        (
            "kantara-chapter-1-2025",
            "kgf-chapter-2-2022"
        ),
    ]

    # --------------------------------------------------------
    # Get BoxOfficeX canonical movie slugs
    #
    # Existing helper format:
    # {
    #     movie_id: "movie-slug",
    #     ...
    # }
    # --------------------------------------------------------

    movie_slug_map = _unique_movie_slug_map()

    # Reverse it so we can find movie ID from canonical slug.
    slug_to_movie_id = {
        movie_slug: movie_id
        for movie_id, movie_slug in movie_slug_map.items()
    }

    urls = []
    seen_urls = set()

    # --------------------------------------------------------
    # Build comparison URLs
    # --------------------------------------------------------

    for requested_first_slug, requested_second_slug in comparison_pairs:

        first_id = slug_to_movie_id.get(requested_first_slug)
        second_id = slug_to_movie_id.get(requested_second_slug)

        # Movie not available in this database.
        if first_id is None or second_id is None:
            continue

        first_slug = movie_slug_map.get(first_id)
        second_slug = movie_slug_map.get(second_id)

        if not first_slug or not second_slug:
            continue

        # ----------------------------------------------------
        # IMPORTANT:
        # Follow the same canonical ordering used by
        # BoxOfficeX comparison URLs.
        # ----------------------------------------------------

        if first_id > second_id:
            first_id, second_id = second_id, first_id
            first_slug, second_slug = second_slug, first_slug

        path = (
            f"/compare/movies/"
            f"{first_slug}-vs-{second_slug}"
        )

        # Avoid duplicate comparison URLs.
        if path in seen_urls:
            continue

        seen_urls.add(path)

        urls.append(
            _sitemap_url_entry(
                path,
                "weekly",
                "0.8"
            )
        )

    # --------------------------------------------------------
    # Generate sitemap XML
    # --------------------------------------------------------

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    # Cache generated sitemap.
    _sitemap_cache["movie_compare"] = xml

    return _xml_response(xml)


# ============================================================
# ARTICLES SITEMAP
# All published BoxOfficeX articles
# ============================================================

# ============================================================
# ARTICLES SITEMAP
# All published BoxOfficeX articles
# Short cache for live box-office updates
# ============================================================

@app.get("/sitemap-articles.xml", include_in_schema=False)
def sitemap_articles_xml():
    """
    BoxOfficeX article sitemap.

    Contains ALL published articles.

    lastmod priority:
    1. updated_at
    2. published_at
    3. created_at

    No in-memory sitemap cache because live box-office
    articles may be updated frequently.
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    slug,
                    COALESCE(
                        updated_at,
                        published_at,
                        created_at
                    ) AS last_modified
                FROM articles
                WHERE status = 'published'
                  AND slug IS NOT NULL
                  AND TRIM(slug) <> ''
                ORDER BY id ASC
            """)

            article_rows = cur.fetchall()

    urls = []
    seen_slugs = set()

    for slug, last_modified in article_rows:

        slug = str(slug).strip()

        if not slug:
            continue

        # Prevent accidental duplicate article URLs.
        if slug in seen_slugs:
            continue

        seen_slugs.add(slug)

        urls.append(
            _sitemap_url_entry(
                f"/article/{slug}",
                "daily",
                "0.8",
                last_modified
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    return Response(
        content=xml,
        media_type="application/xml",
        headers={
            "Cache-Control": "public, max-age=300"
        }
    )


# ============================================================
# MOVIE RANKINGS SITEMAP
# BoxOfficeX movie ranking pages
# ============================================================

@app.get("/sitemap-movie-rankings.xml", include_in_schema=False)
def sitemap_movie_rankings_xml():
    """
    BoxOfficeX movie rankings sitemap.

    Contains the main movie rankings page and
    major Indian language/industry ranking pages.
    """

    cached = _sitemap_cache.get("movie_rankings")
    if cached is not None:
        return _xml_response(cached)

    ranking_pages = [
        "/movie-rankings.html",
        "/movie-rankings/tamil",
        "/movie-rankings/telugu",
        "/movie-rankings/hindi",
        "/movie-rankings/kannada",
        "/movie-rankings/malayalam",
    ]

    urls = []

    for path in ranking_pages:
        urls.append(
            _sitemap_url_entry(
                path,
                "daily",
                "0.9"
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    _sitemap_cache["movie_rankings"] = xml

    return _xml_response(xml)


# ============================================================
# ACTOR RANKINGS SITEMAP
# BoxOfficeX actor ranking pages
# ============================================================

@app.get("/sitemap-actor-rankings.xml", include_in_schema=False)
def sitemap_actor_rankings_xml():
    """
    BoxOfficeX actor rankings sitemap.

    Contains the main actor rankings page and
    major Indian language/industry ranking pages.
    """

    cached = _sitemap_cache.get("actor_rankings")
    if cached is not None:
        return _xml_response(cached)

    ranking_pages = [
        "/rankings.html",
        "/actor-rankings/tamil",
        "/actor-rankings/telugu",
        "/actor-rankings/hindi",
        "/actor-rankings/kannada",
        "/actor-rankings/malayalam",
    ]

    urls = []

    for path in ranking_pages:
        urls.append(
            _sitemap_url_entry(
                path,
                "daily",
                "0.9"
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    _sitemap_cache["actor_rankings"] = xml

    return _xml_response(xml)



# ============================================================
# PUBLIC PAGES SITEMAP
# Important BoxOfficeX general, trust and legal pages
# ============================================================

@app.get("/sitemap-pages.xml", include_in_schema=False)
def sitemap_pages_xml():
    """
    BoxOfficeX public pages sitemap.

    Contains important general/public pages that are not
    already covered by movie, actor, article, comparison
    or ranking sitemaps.
    """

    cached = _sitemap_cache.get("pages")
    if cached is not None:
        return _xml_response(cached)

    pages = [
        # ----------------------------------------------------
        # Homepage
        # ----------------------------------------------------
        ("/", "daily", "1.0"),

        # ----------------------------------------------------
        # Discovery pages
        # ----------------------------------------------------
        ("/new-movies.html", "daily", "0.9"),
        ("/actors.html", "weekly", "0.8"),
        ("/articles.html", "daily", "0.9"),

        # ----------------------------------------------------
        # Comparison discovery pages
        # ----------------------------------------------------
        ("/compare-select.html", "weekly", "0.7"),
        ("/movie-compare-select.html", "weekly", "0.7"),

        # ----------------------------------------------------
        # Company / trust pages
        # ----------------------------------------------------
        ("/about.html", "monthly", "0.5"),
        ("/contact.html", "monthly", "0.5"),

        # ----------------------------------------------------
        # Legal pages
        # ----------------------------------------------------
        ("/privacy.html", "monthly", "0.4"),
        ("/terms.html", "monthly", "0.4"),
        ("/disclaimer.html", "monthly", "0.4"),

        # ----------------------------------------------------
        # Advertising / business
        # ----------------------------------------------------
        ("/advertise.html", "monthly", "0.6"),
    ]

    urls = []

    for path, changefreq, priority in pages:
        urls.append(
            _sitemap_url_entry(
                path,
                changefreq,
                priority
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset '
        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + '\n</urlset>\n'
    )

    _sitemap_cache["pages"] = xml

    return _xml_response(xml)



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
    return _boxofficex_html_file("index.html")

@app.get("/boxofficex-placeholders.js", include_in_schema=False)
def boxofficex_placeholders_script():
    return FileResponse(
        BASE_DIR / "boxofficex-placeholders.js",
        media_type="application/javascript",
    )


@app.get("/movie.html", include_in_schema=False)
def movie_page(id: Optional[int] = None):
    # Legacy public URL -> one canonical clean URL.
    if id is None:
        return RedirectResponse(url="/new-movies.html", status_code=301)

    movie_url = public_movie_url(id)
    if movie_url == "/new-movies.html":
        raise HTTPException(status_code=404, detail="Movie not found")

    return RedirectResponse(url=movie_url, status_code=301)


# ============================================================
# MOVIE RANKINGS - CACHED SSR + INDEXABLE INDUSTRY URLS
# ============================================================

MOVIE_RANKINGS_HTML_CACHE_TTL = 3600
MOVIE_RANKINGS_HTML_STALE_TTL = 900
_movie_rankings_html_cache = {}
_movie_rankings_html_cache_lock = threading.Lock()
_movie_rankings_html_refreshing = set()

_MOVIE_RANKING_TARGETS = {
    "all": {"label": "Global", "industry": "All", "language": None, "path": "/movie-rankings.html"},
    "tamil": {"label": "Tamil", "industry": "Kollywood", "language": "Tamil", "path": "/movie-rankings/tamil"},
    "telugu": {"label": "Telugu", "industry": "Tollywood", "language": "Telugu", "path": "/movie-rankings/telugu"},
    "hindi": {"label": "Hindi", "industry": "Bollywood", "language": "Hindi", "path": "/movie-rankings/hindi"},
    "kannada": {"label": "Kannada", "industry": "Sandalwood", "language": "Kannada", "path": "/movie-rankings/kannada"},
    "malayalam": {"label": "Malayalam", "industry": "Mollywood", "language": "Malayalam", "path": "/movie-rankings/malayalam"},
}


def _movie_rankings_format_crore(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return ""
    if number <= 0:
        return ""
    return f"{number:,.2f}".rstrip("0").rstrip(".")


def _movie_rankings_fetch_rows():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, language, industry, release_date,
                       worldwide_collection_crore, budget_crore, verdict, poster
                FROM movies
                WHERE worldwide_collection_crore IS NOT NULL
                  AND worldwide_collection_crore > 0
                ORDER BY worldwide_collection_crore DESC
                LIMIT 300
            """)
            rows = cur.fetchall()
    return [{
        "id": row[0], "title": row[1], "language": row[2], "industry": row[3],
        "release_date": str(row[4]) if row[4] else None,
        "worldwide_collection": float(row[5]) if row[5] is not None else None,
        "budget_crore": float(row[6]) if row[6] is not None else None,
        "verdict": row[7], "poster": safe_movie_poster(row[8]),
    } for row in rows]


def _movie_rankings_matches(movie, industry, language):
    return (
        str(movie.get("industry") or "").strip().lower() == str(industry or "").lower()
        or str(movie.get("language") or "").strip().lower() == str(language or "").lower()
    )


def _movie_rankings_public_url(movie):
    # Ranking SSR precomputes canonical movie URLs once per render.
    # This avoids rebuilding the full movie slug map for every card,
    # Top 10 item and structured-data item.
    cached_url = str(movie.get("_public_url") or "").strip()
    if cached_url:
        return cached_url

    movie_id = movie.get("id")
    if movie_id is None:
        return "/new-movies.html"
    try:
        return public_movie_url(int(movie_id)) or "/new-movies.html"
    except Exception:
        return "/new-movies.html"


def _movie_rankings_card(movie, rank):
    title = str(movie.get("title") or "Movie").strip()
    gross = _movie_rankings_format_crore(movie.get("worldwide_collection"))
    budget = _movie_rankings_format_crore(movie.get("budget_crore"))
    release = str(movie.get("release_date") or "").strip()
    verdict = str(movie.get("verdict") or "Box Office").strip()
    poster = str(movie.get("poster") or DEFAULT_MOVIE_POSTER).strip()
    poster_url = poster if _is_remote_image(poster) else f"/posters/{poster}"
    url = _movie_rankings_public_url(movie)
    details = []
    if release:
        details.append(f"📅 {html_escape(release)}")
    if gross:
        details.append(f"🌍 ₹{html_escape(gross)} Cr Worldwide")
    if budget:
        details.append(f"💰 ₹{html_escape(budget)} Cr Budget")
    return (
        f'<a class="movie-card" href="{html_escape(url, quote=True)}" aria-label="{html_escape(title, quote=True)} box office details">'
        f'<div class="rank">#{rank}</div>'
        f'<img src="{html_escape(poster_url, quote=True)}" alt="{html_escape(title, quote=True)}" loading="lazy">'
        '<div class="movie-info">'
        f'<div class="movie-title">{html_escape(title)}</div>'
        f'<div class="details">{" &nbsp; | &nbsp; ".join(details)}</div>'
        f'<div class="verdict">🎬 {html_escape(verdict)}</div>'
        '</div></a>'
    )


def _movie_rankings_meta(target_key, ranked_movies):
    target = _MOVIE_RANKING_TARGETS[target_key]
    label = target["label"]
    canonical = f'https://boxofficex.in{target["path"]}'

    if target_key == "all":
        title = "Top 50 Highest-Grossing Movies of All Time | BoxOfficeX"
        fallback = (
            "Explore the Top 50 highest-grossing movies of all time by worldwide box office collection, "
            "with reported budgets and verdicts on BoxOfficeX."
        )
        subject = "the worldwide movie rankings"
    else:
        title = f"Highest-Grossing {label} Movies of All Time | BoxOfficeX"
        fallback = (
            f"Explore the highest-grossing {label} movies ranked by worldwide box office collection, "
            "with reported budgets and verdicts on BoxOfficeX."
        )
        subject = f"the highest-grossing {label} movies"

    leaders = []
    for movie in ranked_movies[:3]:
        name = str(movie.get("title") or "").strip()
        gross = _movie_rankings_format_crore(movie.get("worldwide_collection"))
        if name and gross:
            leaders.append((name, gross))

    if len(leaders) >= 3:
        leader_text = (
            f"{leaders[0][0]} ₹{leaders[0][1]} Cr, "
            f"{leaders[1][0]} ₹{leaders[1][1]} Cr and "
            f"{leaders[2][0]} ₹{leaders[2][1]} Cr"
        )
        description = (
            f"{leader_text} lead {subject}. "
            "Explore worldwide collections, reported budgets and verdicts on BoxOfficeX."
        )
    elif leaders:
        leader_text = ", ".join(f"{name} ₹{gross} Cr" for name, gross in leaders)
        description = (
            f"{leader_text} lead {subject}. "
            "Explore worldwide collections, reported budgets and verdicts on BoxOfficeX."
        )
    else:
        description = fallback

    # Keep the search snippet compact while preserving the strongest live numbers.
    if len(description) > 180:
        description = description[:177].rstrip(" ,.-") + "..."

    return title, description, canonical


def _movie_rankings_apply_meta(template, title, description, canonical):
    et = html_escape(title, quote=True); ed = html_escape(description, quote=True); ec = html_escape(canonical, quote=True)
    replacements = [
        (r"<title\b[^>]*>.*?</title>", f"<title>{html_escape(title)}</title>"),
        (r'<meta\b(?=[^>]*\bname=["\']description["\'])[^>]*>', f'<meta id="metaDescription" name="description" content="{ed}">'),
        (r'<link\b(?=[^>]*\brel=["\']canonical["\'])[^>]*>', f'<link id="canonicalUrl" rel="canonical" href="{ec}">'),
        (r'<meta\b(?=[^>]*\bproperty=["\']og:title["\'])[^>]*>', f'<meta id="ogTitle" property="og:title" content="{et}">'),
        (r'<meta\b(?=[^>]*\bproperty=["\']og:description["\'])[^>]*>', f'<meta id="ogDescription" property="og:description" content="{ed}">'),
        (r'<meta\b(?=[^>]*\bproperty=["\']og:url["\'])[^>]*>', f'<meta id="ogUrl" property="og:url" content="{ec}">'),
        (r'<meta\b(?=[^>]*\bname=["\']twitter:title["\'])[^>]*>', f'<meta id="twitterTitle" name="twitter:title" content="{et}">'),
        (r'<meta\b(?=[^>]*\bname=["\']twitter:description["\'])[^>]*>', f'<meta id="twitterDescription" name="twitter:description" content="{ed}">'),
    ]
    for pattern, replacement in replacements:
        template = re.sub(pattern, replacement, template, count=1, flags=re.I | re.S)
    return template



def _movie_rankings_top10_html(target_key, ranked):
    target = _MOVIE_RANKING_TARGETS[target_key]
    label = target["label"]
    heading = (
        "Top 10 Highest-Grossing Movies of All Time — Worldwide Gross & Budget"
        if target_key == "all"
        else f"Top 10 Highest-Grossing {label} Movies — Worldwide Gross & Budget"
    )
    items = []
    for rank, movie in enumerate(ranked[:10], 1):
        name = str(movie.get("title") or "Movie").strip()
        gross = _movie_rankings_format_crore(movie.get("worldwide_collection")) or "N/A"
        budget = _movie_rankings_format_crore(movie.get("budget_crore")) or "N/A"
        url = _movie_rankings_public_url(movie)
        items.append(
            '<li class="movie-top10-item">'
            f'<span class="movie-top10-rank">#{rank}</span>'
            f'<a class="movie-top10-title" href="{html_escape(url, quote=True)}">{html_escape(name)}</a>'
            '<span class="movie-top10-numbers">'
            f'<strong>₹{html_escape(gross)} Cr Worldwide</strong>'
            f'<span>Budget: {"₹" + html_escape(budget) + " Cr" if budget != "N/A" else "N/A"}</span>'
            '</span></li>'
        )
    return (
        '<section class="movie-top10-section" id="movieRankingsTop10" data-ssr="1" '
        'aria-labelledby="movieRankingsTop10Heading">'
        f'<h2 id="movieRankingsTop10Heading">{html_escape(heading)}</h2>'
        '<p class="movie-rankings-section-copy">The table-style summary below uses the same '
        'worldwide-gross ranking data shown above. Budget figures are the reported production '
        'budgets currently stored in the BoxOfficeX database.</p>'
        f'<ol class="movie-top10-list">{"".join(items)}</ol>'
        '</section>'
    )


def _movie_rankings_info_html(target_key):
    target = _MOVIE_RANKING_TARGETS[target_key]
    label = target["label"]
    scope = "all movies in the ranking database" if target_key == "all" else f"qualifying {label} movies"
    return (
        '<section class="movie-rankings-info" id="movieRankingsMethodology" data-ssr="1" '
        'aria-labelledby="movieRankingsMethodologyHeading">'
        '<h2 id="movieRankingsMethodologyHeading">How BoxOfficeX Movie Rankings Are Calculated</h2>'
        '<div class="movie-rankings-info-grid">'
        '<div><h3>Worldwide Box Office Gross</h3><p>Movies are ordered by their tracked '
        'worldwide box office collection, from highest to lowest.</p></div>'
        '<div><h3>Reported Movie Budget</h3><p>Budget is shown as supporting information '
        'when a reported production budget is available in the BoxOfficeX database.</p></div>'
        f'<div><h3>Movies Included</h3><p>This page uses {html_escape(scope)} with a positive '
        'worldwide collection value. Rankings can change when collection data is updated.</p></div>'
        '</div></section>'
    )


def _movie_rankings_faq_items(target_key, ranked):
    target = _MOVIE_RANKING_TARGETS[target_key]
    label = target["label"]
    first = ranked[0] if ranked else {}
    first_name = str(first.get("title") or "the current No. 1 movie").strip()
    first_gross = _movie_rankings_format_crore(first.get("worldwide_collection"))

    q1 = (
        "What is the highest-grossing movie of all time on BoxOfficeX?"
        if target_key == "all"
        else f"What is the highest-grossing {label} movie on BoxOfficeX?"
    )
    a1 = (
        f"Based on the collections currently tracked by BoxOfficeX, {first_name} is ranked No. 1"
        + (f" with ₹{first_gross} Cr worldwide." if first_gross else ".")
        + " Rankings can change when box office data is updated."
    )

    scope_answer = (
        "The Global ranking combines qualifying movies in the BoxOfficeX database and orders them by tracked worldwide gross."
        if target_key == "all"
        else f"This page filters qualifying {label} movies in the BoxOfficeX database and orders them by tracked worldwide gross."
    )

    return [
        (q1, a1),
        (
            "How are movies ranked on this page?",
            "Movies are ranked from highest to lowest by tracked worldwide box office gross. "
            "Budget, release date and verdict are supporting details and do not change the ranking order."
        ),
        (
            "Do the movie rankings include production budget?",
            "Yes. The Top 10 summary and movie cards show the reported production budget when it is available "
            "in the BoxOfficeX database. A missing budget is shown as unavailable rather than estimated."
        ),
        (
            "Why can box office collection figures differ between sources?",
            "Box office figures can vary because reporting schedules, territory coverage, currency conversion, "
            "re-release totals and trade estimates may differ. BoxOfficeX displays the figures currently tracked "
            "in its database and updates them when newer data is added."
        ),
        (
            "How often are the movie rankings updated?",
            "The ranking order can change whenever BoxOfficeX updates a movie's worldwide collection. "
            "New releases may therefore move through the list as additional box office data becomes available."
        ),
        (
            "Are re-release collections included in the rankings?",
            "A movie's ranking follows the worldwide collection value currently stored by BoxOfficeX. "
            "If an updated stored total includes reported re-release business, that updated total can affect its position."
        ),
        (
            "Why do some movies not show a budget?",
            "Budget is displayed only when a reported production-budget figure is available in the BoxOfficeX database. "
            "BoxOfficeX does not insert a made-up budget simply to fill a missing value."
        ),
        (
            f"Which movies are included in the {label} ranking?",
            scope_answer + " Movies without a positive tracked worldwide collection are not included in this ranking."
        ),
    ]


def _movie_rankings_faq_html(target_key, ranked):
    faq_items = _movie_rankings_faq_items(target_key, ranked)
    details = []
    for index, (question, answer) in enumerate(faq_items):
        open_attr = " open" if index == 0 else ""
        details.append(
            f'<details class="movie-faq-item"{open_attr}>'
            f'<summary><span>{html_escape(question)}</span>'
            '<span class="movie-faq-plus" aria-hidden="true">+</span></summary>'
            f'<div class="movie-faq-answer"><p>{html_escape(answer)}</p></div>'
            '</details>'
        )

    return (
        '<section class="movie-rankings-faq" id="movieRankingsFaq" data-ssr="1" '
        'aria-labelledby="movieRankingsFaqHeading">'
        '<div class="movie-rankings-section-kicker">QUESTIONS & ANSWERS</div>'
        '<h2 id="movieRankingsFaqHeading">Movie Box Office Rankings FAQ</h2>'
        '<p class="movie-rankings-section-copy">Quick answers about worldwide gross, budgets, '
        'ranking methodology and BoxOfficeX data updates.</p>'
        f'<div class="movie-faq-list">{"".join(details)}</div>'
        '</section>'
    )


def _movie_rankings_faq_schema(target_key, ranked):
    return {
        "@type": "FAQPage",
        "mainEntity": [
            {
                "@type": "Question",
                "name": question,
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": answer,
                },
            }
            for question, answer in _movie_rankings_faq_items(target_key, ranked)
        ],
    }


def _movie_rankings_breadcrumb_schema(target_key, canonical):
    target = _MOVIE_RANKING_TARGETS[target_key]
    items = [
        {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://boxofficex.in/index.html"},
        {"@type": "ListItem", "position": 2, "name": "Movie Rankings", "item": "https://boxofficex.in/movie-rankings.html"},
    ]
    if target_key != "all":
        items.append({"@type": "ListItem", "position": 3, "name": f"{target['label']} Movie Rankings", "item": canonical})
    return {"@type": "BreadcrumbList", "itemListElement": items}


def _render_movie_rankings_html(target_key="all"):
    target = _MOVIE_RANKING_TARGETS[target_key]
    template = _inject_boxofficex_global_icons((BASE_DIR / "movie-rankings.html").read_text(encoding="utf-8"))
    movies = _movie_rankings_fetch_rows()

    # Build the complete movie slug map ONCE for this SSR render.
    # Previously public_movie_url() rebuilt it for every movie URL, causing
    # dozens of repeated DB reads during a single cold ranking request.
    try:
        movie_slug_map = _unique_movie_slug_map()
    except Exception as exc:
        print("MOVIE RANKINGS SLUG MAP WARNING:", type(exc).__name__, exc, flush=True)
        movie_slug_map = {}

    for movie in movies:
        movie_id = movie.get("id")
        slug = movie_slug_map.get(movie_id)
        movie["_public_url"] = f"/movie/{slug}" if slug else "/new-movies.html"

    if target_key == "all":
        ranked = movies[:50]
    else:
        ranked = [m for m in movies if _movie_rankings_matches(m, target["industry"], target["language"])][:50]
    title, description, canonical = _movie_rankings_meta(target_key, ranked)
    template = _movie_rankings_apply_meta(template, title, description, canonical)

    label = target["label"]

    hero_leaders = []
    for movie in ranked[:3]:
        name = str(movie.get("title") or "").strip()
        gross = _movie_rankings_format_crore(movie.get("worldwide_collection"))
        if name and gross:
            hero_leaders.append((name, gross))

    if target_key == "all":
        hero_h1 = "Top 50 Highest-Grossing Movies of All Time"
        list_h2 = "Highest-Grossing Movies by Worldwide Box Office Collection"
        list_copy = (
            "Movies are ranked from highest to lowest by tracked worldwide gross. "
            "Reported budget is shown alongside each movie when available."
        )
        hero_scope = "the worldwide movie ranking"
    else:
        hero_h1 = f"Highest-Grossing {label} Movies of All Time"
        list_h2 = f"Highest-Grossing {label} Movies by Worldwide Box Office"
        list_copy = (
            f"These {label} movies are ranked from highest to lowest by tracked worldwide gross. "
            "Reported budget is shown when available."
        )
        hero_scope = f"the {label} movie ranking"

    if len(hero_leaders) >= 3:
        hero_intro = (
            f"{hero_leaders[0][0]} currently leads {hero_scope} with "
            f"₹{hero_leaders[0][1]} Cr worldwide, followed by "
            f"{hero_leaders[1][0]} at ₹{hero_leaders[1][1]} Cr and "
            f"{hero_leaders[2][0]} at ₹{hero_leaders[2][1]} Cr. "
            "Explore the ranking with reported budgets, release dates and box-office verdicts."
        )
    elif hero_leaders:
        hero_intro = (
            f"{hero_leaders[0][0]} currently leads {hero_scope} with "
            f"₹{hero_leaders[0][1]} Cr worldwide. "
            "Explore the ranking with reported budgets, release dates and box-office verdicts."
        )
    else:
        hero_intro = (
            f"Explore {hero_scope} by tracked worldwide box office collection, "
            "with reported budgets, release dates and verdicts from the BoxOfficeX database."
        )

    template = re.sub(
        r'(<section\s+class=["\']page-header["\'][^>]*>).*?(</section>)',
        lambda m: (
            m.group(1)
            + '<div class="page-badge">BOXOFFICEX MOVIE RANKINGS</div>'
            + f'<h1>{html_escape(hero_h1)}</h1>'
            + f'<p>{html_escape(hero_intro)}</p>'
            + m.group(2)
        ),
        template, count=1, flags=re.I | re.S,
    )
    template = re.sub(
        r'(<h2\b[^>]*\bid=["\']rankingTitle["\'][^>]*>).*?(</h2>)',
        lambda m: m.group(1) + html_escape(list_h2) + m.group(2),
        template, count=1, flags=re.I | re.S,
    )
    template = re.sub(
        r'(<p\b[^>]*\bid=["\']rankingSubtitle["\'][^>]*>).*?(</p>)',
        lambda m: m.group(1) + html_escape(list_copy) + m.group(2),
        template, count=1, flags=re.I | re.S,
    )

    cards = "".join(_movie_rankings_card(movie, rank) for rank, movie in enumerate(ranked, 1))
    if cards:
        template = re.sub(
            r'(<div\s+id=["\']movies["\'][^>]*>).*?(<!--\s*SSR_MOVIES_END\s*-->)',
            lambda m: m.group(1).replace('id="movies"', 'id="movies" data-ssr="1"') + cards + m.group(2),
            template, count=1, flags=re.I | re.S,
        )

    item_list = []
    for rank, movie in enumerate(ranked, 1):
        name = str(movie.get("title") or "").strip(); url = _movie_rankings_public_url(movie)
        if name and url != "/new-movies.html":
            item_list.append({"@type":"ListItem","position":rank,"name":name,"url":f"https://boxofficex.in{url}"})
    list_name = "BoxOfficeX Top 50 Highest-Grossing Movies" if target_key == "all" else f"BoxOfficeX Highest-Grossing {target['label']} Movies"
    structured = {
        "@context": "https://schema.org",
        "@graph": [
            {"@type":"CollectionPage","name":title.replace(" | BoxOfficeX", ""),"url":canonical,"description":description,
             "mainEntity":{"@type":"ItemList","name":list_name,"itemListElement":item_list}},
            _movie_rankings_faq_schema(target_key, ranked),
            _movie_rankings_breadcrumb_schema(target_key, canonical),
        ],
    }
    structured_json = json.dumps(structured, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    template = re.sub(r'<script\s+id=["\']rankingsStructuredData["\']\s+type=["\']application/ld\+json["\']\s*>.*?</script>', f'<script id="rankingsStructuredData" type="application/ld+json">{structured_json}</script>', template, count=1, flags=re.I | re.S)

    supporting_html = (
        _movie_rankings_top10_html(target_key, ranked)
        + _movie_rankings_info_html(target_key)
        + _movie_rankings_faq_html(target_key, ranked)
    )
    template = re.sub(
        r'(<!--\s*SSR_MOVIES_END\s*-->\s*</div>)',
        lambda m: m.group(1) + supporting_html,
        template, count=1, flags=re.I | re.S,
    )

    config = json.dumps({"targetKey":target_key,"industry":target["industry"],"label":target["label"],"canonical":canonical,"title":title,"description":description}, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    template = template.replace("</head>", f'<script>window.__BOXOFFICEX_MOVIE_RANKINGS_PAGE__={config};</script>\n</head>', 1)
    return template


def _refresh_movie_rankings_html_cache(target_key):
    try:
        rendered = _render_movie_rankings_html(target_key)
        with _movie_rankings_html_cache_lock:
            _movie_rankings_html_cache[target_key] = {"html": rendered, "generated_at": time_module.time()}
    except Exception as exc:
        print("MOVIE RANKINGS SSR REFRESH WARNING:", target_key, exc, flush=True)
    finally:
        with _movie_rankings_html_cache_lock:
            _movie_rankings_html_refreshing.discard(target_key)


def _start_movie_rankings_html_refresh(target_key):
    with _movie_rankings_html_cache_lock:
        if target_key in _movie_rankings_html_refreshing:
            return
        _movie_rankings_html_refreshing.add(target_key)
    threading.Thread(target=_refresh_movie_rankings_html_cache, args=(target_key,), daemon=True).start()


def _movie_rankings_response(target_key):
    now = time_module.time()

    with _movie_rankings_html_cache_lock:
        entry = _movie_rankings_html_cache.get(target_key) or {}
        cached = entry.get("html")
        generated_at = float(entry.get("generated_at") or 0)

    age = now - generated_at if generated_at else float("inf")

    headers = {
        "X-BoxOfficeX-Movie-Rankings-CTR": "v4-top10-budget-ssr",
        "Cache-Control": "public, max-age=900, stale-while-revalidate=21600",
    }

    if cached and age <= MOVIE_RANKINGS_HTML_CACHE_TTL:
        headers["X-BoxOfficeX-Movie-Rankings-SSR"] = "HIT"
        return HTMLResponse(content=cached, headers=headers)

    if cached:
        _start_movie_rankings_html_refresh(target_key)
        headers["X-BoxOfficeX-Movie-Rankings-SSR"] = "STALE"
        return HTMLResponse(content=cached, headers=headers)

    # First request after deploy: render the complete SSR page immediately.
    try:
        rendered = _render_movie_rankings_html(target_key)

        with _movie_rankings_html_cache_lock:
            _movie_rankings_html_cache[target_key] = {
                "html": rendered,
                "generated_at": time_module.time(),
            }

        headers["X-BoxOfficeX-Movie-Rankings-SSR"] = "MISS-RENDERED"
        return HTMLResponse(content=rendered, headers=headers)

    except Exception as exc:
        print(
            "MOVIE RANKINGS SSR ERROR:",
            target_key,
            type(exc).__name__,
            exc,
            flush=True,
        )

        target = _MOVIE_RANKING_TARGETS[target_key]
        template = _inject_boxofficex_global_icons((BASE_DIR / "movie-rankings.html").read_text(encoding="utf-8"))
        title, description, canonical = _movie_rankings_meta(target_key, [])
        template = _movie_rankings_apply_meta(
            template,
            title,
            description,
            canonical,
        )

        config = json.dumps(
            {
                "targetKey": target_key,
                "industry": target["industry"],
                "label": target["label"],
                "canonical": canonical,
                "title": title,
                "description": description,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).replace("</", "<\\/")

        template = template.replace(
            "</head>",
            f'<script>window.__BOXOFFICEX_MOVIE_RANKINGS_PAGE__={config};</script>\\n</head>',
            1,
        )

        headers["X-BoxOfficeX-Movie-Rankings-SSR"] = "FALLBACK"
        headers["X-BoxOfficeX-SSR-Error"] = type(exc).__name__
        return HTMLResponse(content=template, headers=headers)


def _warm_all_movie_rankings_html_cache():
    # Warm ranking pages sequentially in one background thread.
    # Startup stays non-blocking while the public pages become cache hits.
    for target_key in _MOVIE_RANKING_TARGETS:
        try:
            _refresh_movie_rankings_html_cache(target_key)
        except Exception as exc:
            print(
                "MOVIE RANKINGS STARTUP WARM WARNING:",
                target_key,
                type(exc).__name__,
                exc,
                flush=True,
            )


@app.on_event("startup")
def warm_movie_rankings_ssr_cache():
    threading.Thread(
        target=_warm_all_movie_rankings_html_cache,
        name="boxofficex-movie-rankings-warm",
        daemon=True,
    ).start()


@app.get("/movie-rankings.html")
def movie_rankings_page():
    return _movie_rankings_response("all")


@app.get("/movie-rankings/{industry_slug}")
def movie_rankings_industry_page(industry_slug: str):
    key = str(industry_slug or "").strip().lower()
    if key not in _MOVIE_RANKING_TARGETS or key == "all":
        raise HTTPException(status_code=404, detail="Movie ranking industry not found")
    return _movie_rankings_response(key)


# ============================================================
# MOVIE DETAIL - CACHED SERVER-RENDERED SEO CONTENT
# ============================================================

MOVIE_HTML_CACHE_TTL = 300
_movie_html_cache = {}
_movie_html_cache_lock = threading.Lock()


def _movie_ssr_format_crore(value):
    if value is None or value == "":
        return "N/A"
    try:
        number = float(value)
        rendered = f"{number:,.2f}".rstrip("0").rstrip(".")
        return f"₹{rendered} Cr"
    except (TypeError, ValueError):
        return f"₹{value} Cr"


def _movie_ssr_release_year(movie):
    value = str(movie.get("release_date") or "").strip()
    match = re.search(r"(\d{4})", value)
    return match.group(1) if match else ""


def _movie_ssr_has_number(value):
    if value is None or value == "":
        return False
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _movie_ssr_plain_crore(value):
    if not _movie_ssr_has_number(value):
        return None
    number = float(value)
    return f"{number:,.2f}".rstrip("0").rstrip(".")


def _movie_ssr_lead_cast(movie):
    raw = (
        movie.get("actors")
        or movie.get("cast")
        or movie.get("cast_names")
        or movie.get("starring")
    )

    if isinstance(raw, list):
        names = []
        for item in raw:
            if isinstance(item, dict):
                value = item.get("name") or item.get("actor_name") or ""
            else:
                value = item
            value = str(value or "").strip()
            if value:
                names.append(value)
        return names[:3]

    if isinstance(raw, str):
        return [x.strip() for x in raw.split(",") if x.strip()][:3]

    return []


def _movie_ssr_natural_list(items):
    clean = [str(x).strip() for x in items if str(x).strip()]
    if not clean:
        return ""
    if len(clean) == 1:
        return clean[0]
    if len(clean) == 2:
        return f"{clean[0]} and {clean[1]}"
    return ", ".join(clean[:-1]) + f" and {clean[-1]}"


def _movie_ssr_deck(movie):
    title_text = str(movie.get("title") or "This movie").strip()
    language = str(movie.get("language") or "").strip()
    genre = str(movie.get("genre") or "").strip()
    director = str(movie.get("director") or "").strip()
    cast = _movie_ssr_lead_cast(movie)

    budget = _movie_ssr_plain_crore(movie.get("budget_crore"))
    india = _movie_ssr_plain_crore(movie.get("india_collection_crore"))
    overseas = _movie_ssr_plain_crore(movie.get("overseas_collection_crore"))
    worldwide = _movie_ssr_plain_crore(movie.get("worldwide_collection_crore"))
    verdict = str(movie.get("verdict") or "").strip()

    intro = title_text
    intro += f" is a {language}" if language else " is an Indian"
    if genre:
        intro += f" {genre.lower()}"
    intro += " film"

    if director:
        intro += f" directed by {director}"
    if cast:
        intro += ", starring " + _movie_ssr_natural_list(cast)

    deck = intro + "."

    if budget:
        deck += f" Made on a reported ₹{budget} crore budget"
        if india and overseas and worldwide:
            deck += (
                f", the film grossed ₹{india} crore in India and ₹{overseas} crore "
                f"overseas for a worldwide total of ₹{worldwide} crore"
            )
        elif worldwide:
            deck += f", the film grossed ₹{worldwide} crore worldwide"
        else:
            partial = []
            if india:
                partial.append(f"₹{india} crore in India")
            if overseas:
                partial.append(f"₹{overseas} crore overseas")
            if partial:
                deck += ", with " + " and ".join(partial) + " in theatrical gross"
        deck += "."
    elif india or overseas or worldwide:
        if india and overseas and worldwide:
            deck += (
                f" The film grossed ₹{india} crore in India and ₹{overseas} crore "
                f"overseas for a worldwide total of ₹{worldwide} crore."
            )
        elif worldwide:
            deck += f" The film grossed ₹{worldwide} crore worldwide."
        else:
            partial = []
            if india:
                partial.append(f"₹{india} crore in India")
            if overseas:
                partial.append(f"₹{overseas} crore overseas")
            if partial:
                deck += " The film grossed " + " and ".join(partial) + "."

    if (
        _movie_ssr_has_number(movie.get("budget_crore"))
        and float(movie.get("budget_crore")) > 0
        and _movie_ssr_has_number(movie.get("worldwide_collection_crore"))
    ):
        multiple = (
            float(movie.get("worldwide_collection_crore"))
            / float(movie.get("budget_crore"))
        )
        deck += (
            f" Its worldwide gross reached approximately {multiple:.1f}× "
            "its reported production budget"
        )
        if verdict:
            deck += f", with a BoxOfficeX verdict of {verdict}"
        deck += "."
    elif verdict:
        deck += f" BoxOfficeX records its theatrical verdict as {verdict}."

    return deck



def _movie_ssr_ctr_description(movie):
    """Build search-result copy from known movie data only. No visible-page changes."""
    title_text = str(movie.get("title") or "Movie").strip()

    budget = _movie_ssr_plain_crore(movie.get("budget_crore"))
    india = _movie_ssr_plain_crore(movie.get("india_collection_crore"))
    overseas = _movie_ssr_plain_crore(movie.get("overseas_collection_crore"))
    worldwide = _movie_ssr_plain_crore(movie.get("worldwide_collection_crore"))
    verdict = str(movie.get("verdict") or "").strip()

    parts = []

    if budget:
        parts.append(f"₹{budget} Cr reported budget")
    if india:
        parts.append(f"₹{india} Cr India gross")
    if overseas:
        parts.append(f"₹{overseas} Cr overseas")
    if worldwide:
        parts.append(f"₹{worldwide} Cr worldwide")

    description = f"{title_text} Box Office"
    if parts:
        description += ": " + ", ".join(parts) + "."

    # Theatrical-performance signal: use a budget multiple only when both
    # budget and worldwide gross are genuinely available and budget > 0.
    multiple = None
    if (
        _movie_ssr_has_number(movie.get("budget_crore"))
        and float(movie.get("budget_crore")) > 0
        and _movie_ssr_has_number(movie.get("worldwide_collection_crore"))
    ):
        multiple = (
            float(movie.get("worldwide_collection_crore"))
            / float(movie.get("budget_crore"))
        )

    if multiple is not None and verdict:
        description += (
            f" Theatrical performance: {multiple:.1f}× its reported budget; "
            f"BoxOfficeX verdict: {verdict}."
        )
    elif multiple is not None:
        description += (
            f" Theatrical performance: {multiple:.1f}× its reported budget."
        )
    elif verdict:
        description += f" BoxOfficeX theatrical verdict: {verdict}."

    description += " See complete theatrical performance."

    return description


def _movie_ssr_build(movie_slug: str):
    identity = resolve_movie_slug(movie_slug)
    if not identity:
        return None

    movie_id = int(identity["id"])
    movie = get_movie(movie_id)
    if not movie or movie.get("error"):
        return None

    canonical_slug = str(movie.get("slug") or movie_slug)
    canonical_path = f"/movie/{canonical_slug}"
    canonical = "https://boxofficex.in" + canonical_path
    title_text = str(movie.get("title") or "Movie").strip()
    year = _movie_ssr_release_year(movie)

    # CTR metadata only. The visible movie H1/deck/layout remain unchanged.
    title = (
        f"{title_text} Box Office Collection, Budget & Verdict | BoxOfficeX"
    )
    description = _movie_ssr_ctr_description(movie)

    h1 = f"{title_text} Box Office Collection, Budget & Verdict"
    deck = _movie_ssr_deck(movie)

    # movie.html intentionally uses the generated BoxOfficeX placeholder on-page.
    poster = _home_movie_placeholder(movie)
    share_image = "https://boxofficex.in/images/boxofficex-share.jpg"

    template = _inject_boxofficex_global_icons((BASE_DIR / "movie.html").read_text(encoding="utf-8"))
    template = re.sub(
        r"<title>.*?</title>",
        f"<title>{html_escape(title)}</title>",
        template,
        count=1,
        flags=re.S,
    )
    template = re.sub(
        r'(<meta id="metaDescription" name="description" content=")[^"]*(")',
        lambda m: m.group(1) + html_escape(description, quote=True) + m.group(2),
        template,
        count=1,
    )
    template = re.sub(
        r'(<link id="canonicalUrl" rel="canonical" href=")[^"]*(")',
        lambda m: m.group(1) + canonical + m.group(2),
        template,
        count=1,
    )
    for element_id, value in (
        ("ogTitle", title),
        ("ogDescription", description),
        ("ogUrl", canonical),
        ("ogImage", share_image),
        ("twitterTitle", title),
        ("twitterDescription", description),
        ("twitterImage", share_image),
    ):
        template = re.sub(
            r'(<meta id="' + re.escape(element_id) + r'"[^>]*content=")[^"]*(")',
            lambda m, v=value: m.group(1) + html_escape(v, quote=True) + m.group(2),
            template,
            count=1,
        )

    structured = {
        "@context": "https://schema.org",
        "@type": "Movie",
        "name": title_text,
        "url": canonical,
        "image": share_image,
        "dateCreated": movie.get("release_date") or None,
        "genre": [
            x.strip()
            for x in str(movie.get("genre") or "").split(",")
            if x.strip()
        ] or None,
        "inLanguage": movie.get("language") or None,
        "director": (
            {"@type": "Person", "name": movie.get("director")}
            if movie.get("director")
            else None
        ),
    }
    structured = {k: v for k, v in structured.items() if v is not None}
    template = re.sub(
        r'<script id="movieStructuredData" type="application/ld\+json">.*?</script>',
        '<script id="movieStructuredData" type="application/ld+json">'
        + json.dumps(structured, ensure_ascii=False).replace("</", "<\\/")
        + "</script>",
        template,
        count=1,
        flags=re.S,
    )

    # Mark this exact movie in the initial document. JS uses the ID and skips the slug resolver call.
    template = template.replace(
        '<div class="movie-card" data-ssr="0">',
        (
            f'<div class="movie-card" data-ssr="1" data-movie-id="{movie_id}" '
            f'data-movie-slug="{html_escape(canonical_slug, quote=True)}">'
        ),
        1,
    )

    # Preserve the existing design; replace loading content with crawlable initial values.
    template = re.sub(
        r'(<img\s+id="moviePoster"\s+src=")[^"]*("\s+alt=")[^"]*("\s+class="movie-poster")',
        lambda m: (
            m.group(1)
            + html_escape(poster, quote=True)
            + m.group(2)
            + html_escape(title_text + " poster", quote=True)
            + m.group(3)
        ),
        template,
        count=1,
        flags=re.S,
    )
    template = re.sub(
        r'<h1\s+id="movieTitle"\s+class="movie-title"\s*>.*?</h1>',
        f'<h1 id="movieTitle" class="movie-title">{html_escape(h1)}</h1>',
        template,
        count=1,
        flags=re.S,
    )

    # Works with both the old movie.html and the new V1 movie.html.
    deck_pattern = (
        r'<p(?:\s+id="movieDeck")?\s+class="hero-subtitle"\s*>.*?</p>'
    )
    template = re.sub(
        deck_pattern,
        f'<p id="movieDeck" class="hero-subtitle">{html_escape(deck)}</p>',
        template,
        count=1,
        flags=re.S,
    )

    values = {
        "language": movie.get("language") or "Indian Cinema",
        "genre": movie.get("genre") or "Genre unavailable",
        "release_date": movie.get("release_date") or "Release date unavailable",
        "worldwide": _movie_ssr_format_crore(movie.get("worldwide_collection_crore")),
        "worldwideBoxOffice": _movie_ssr_format_crore(movie.get("worldwide_collection_crore")),
        "budget": _movie_ssr_format_crore(movie.get("budget_crore")),
        "india": _movie_ssr_format_crore(movie.get("india_collection_crore")),
        "overseas": _movie_ssr_format_crore(movie.get("overseas_collection_crore")),
        "director": movie.get("director") or "Not available",
        "verdict": movie.get("verdict") or "Box Office",
    }
    for element_id, value in values.items():
        pattern = (
            r'(<(?:span|div)\b[^>]*\bid="'
            + re.escape(element_id)
            + r'"[^>]*>).*?(</(?:span|div)>)'
        )
        template = re.sub(
            pattern,
            lambda m, v=str(value): m.group(1) + html_escape(v) + m.group(2),
            template,
            count=1,
            flags=re.S,
        )

    # Semantic movie section headings use the movie title in the initial HTML.
    heading_values = {
        "movieBoxOfficeHeading": f"{title_text} Box Office Collection & Budget",
        "movieBudgetVerdictHeading": f"{title_text} Budget, Recovery & Verdict",
        "movieDailyHeading": f"{title_text} Day-Wise & State Box Office Collection",
        "movieCastHeading": f"{title_text} Cast & Movie Details",
        "movieFaqHeading": f"{title_text} Box Office FAQ",
    }
    for element_id, value in heading_values.items():
        template = re.sub(
            r'(<h2\b[^>]*\bid="' + re.escape(element_id) + r'"[^>]*>).*?(</h2>)',
            lambda mt, v=value: mt.group(1) + html_escape(v) + mt.group(2),
            template,
            count=1,
            flags=re.S,
        )


    # Linked cast is real BoxOfficeX actor/movie relationship data.
    try:
        cast_payload = get_movie_actors(movie_id)
        cast_rows = cast_payload.get("actors", []) if isinstance(cast_payload, dict) else []
    except Exception:
        cast_rows = []

    cast_names = [str(a.get("name") or "").strip() for a in cast_rows if str(a.get("name") or "").strip()]
    if cast_names:
        cast_links = []
        for actor in cast_rows:
            actor_name = str(actor.get("name") or "").strip()
            if not actor_name:
                continue
            actor_url = public_actor_url(actor.get("id"))
            cast_links.append(
                f'<a href="{html_escape(actor_url, quote=True)}">{html_escape(actor_name)}</a>'
            )
        cast_html = ", ".join(cast_links) if cast_links else html_escape(", ".join(cast_names))
    else:
        cast_html = "N/A"

    details_html = (
        '<div><span>Language</span><strong>' + html_escape(str(movie.get("language") or "N/A")) + '</strong></div>'
        '<div><span>Release Date</span><strong>' + html_escape(str(movie.get("release_date") or "N/A")) + '</strong></div>'
        '<div><span>Director</span><strong>' + html_escape(str(movie.get("director") or "N/A")) + '</strong></div>'
        '<div><span>Cast</span><strong class="movie-seo-cast-links">' + cast_html + '</strong></div>'
    )
    template = re.sub(
        r'(<div class="movie-seo-details-grid" id="movieSeoDetailsGrid">).*?(</div>\s*</section>)',
        lambda mt: mt.group(1) + details_html + mt.group(2),
        template,
        count=1,
        flags=re.S,
    )
    template = template.replace('id="movieCastDetails" data-ssr="0"', 'id="movieCastDetails" data-ssr="1"', 1)

    # SSR FAQ: answers are based only on values stored for this movie.
    budget_text = _movie_ssr_format_crore(movie.get("budget_crore"))
    india_text = _movie_ssr_format_crore(movie.get("india_collection_crore"))
    overseas_text = _movie_ssr_format_crore(movie.get("overseas_collection_crore"))
    worldwide_text = _movie_ssr_format_crore(movie.get("worldwide_collection_crore"))
    verdict_text = str(movie.get("verdict") or "N/A")
    faq_items = [
        (f"What is {title_text}'s worldwide box office collection?", f"BoxOfficeX currently records {worldwide_text} as the worldwide box office collection for {title_text}."),
        (f"What is {title_text}'s budget?", f"The reported budget currently stored on BoxOfficeX for {title_text} is {budget_text}."),
        (f"What is {title_text}'s India and overseas box office collection?", f"BoxOfficeX currently records {india_text} in India and {overseas_text} overseas for {title_text}."),
        (f"What is {title_text}'s box office verdict?", f"The current BoxOfficeX verdict for {title_text} is {verdict_text}."),
    ]
    faq_html = ''.join(
        '<details><summary>' + html_escape(q) + '</summary><p>' + html_escape(a) + '</p></details>'
        for q, a in faq_items
    )
    template = re.sub(
        r'(<div class="movie-faq-items">).*?(</div>\s*</section>)',
        lambda mt: mt.group(1) + faq_html + mt.group(2),
        template,
        count=1,
        flags=re.S,
    )
    template = template.replace('id="movieFaq" data-ssr="0"', 'id="movieFaq" data-ssr="1"', 1)

    # Add FAQPage + BreadcrumbList while keeping Movie schema in one @graph.
    movie_schema = structured
    structured_graph = {
        "@context": "https://schema.org",
        "@graph": [
            movie_schema,
            {
                "@type": "BreadcrumbList",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://boxofficex.in/"},
                    {"@type": "ListItem", "position": 2, "name": "Movies", "item": "https://boxofficex.in/new-movies.html"},
                    {"@type": "ListItem", "position": 3, "name": title_text, "item": canonical},
                ],
            },
            {
                "@type": "FAQPage",
                "mainEntity": [
                    {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}}
                    for q, a in faq_items
                ],
            },
        ],
    }
    template = re.sub(
        r'<script id="movieStructuredData" type="application/ld\+json">.*?</script>',
        '<script id="movieStructuredData" type="application/ld+json">'
        + json.dumps(structured_graph, ensure_ascii=False).replace("</", "<\\/")
        + '</script>',
        template,
        count=1,
        flags=re.S,
    )

    # Render existing day/state table in source when collection records exist.
    try:
        breakdown = get_movie_collection_breakdown(movie_id)
        records = breakdown.get("records", []) if isinstance(breakdown, dict) else []
    except Exception:
        records = []

    if records:
        by_date = {}
        for rec in records:
            d = str(rec.get("date") or "")
            if not d:
                continue
            by_date.setdefault(d, {})[rec.get("state")] = float(rec.get("collection_crore") or 0)

        release_value = movie.get("release_date")
        try:
            release_day = date.fromisoformat(str(release_value)) if release_value else None
        except Exception:
            release_day = None

        rows_html = []
        for d in sorted(by_date):
            values_by_state = by_date[d]
            try:
                current_day = date.fromisoformat(d)
                day_number = (current_day - release_day).days + 1 if release_day else None
            except Exception:
                day_number = None
            if day_number is not None and day_number < 1:
                continue
            tn = values_by_state.get("Tamil Nadu", 0)
            kerala = values_by_state.get("Kerala", 0)
            karnataka = values_by_state.get("Karnataka", 0)
            telugu = values_by_state.get("Andhra Pradesh", 0) + values_by_state.get("Telangana", 0) + values_by_state.get("Telugu States", 0)
            roi = values_by_state.get("Rest of India", 0) + values_by_state.get("Maharashtra", 0) + values_by_state.get("West Bengal", 0) + values_by_state.get("Delhi", 0)
            india_total = values_by_state.get(None)
            if india_total is None:
                india_total = tn + kerala + karnataka + telugu + roi
            overseas_val = values_by_state.get("Overseas", 0)
            worldwide_val = india_total + overseas_val
            def td_money(v):
                return _movie_ssr_format_crore(v) if v else "N/A"
            rows_html.append(
                '<tr data-ssr="1">'
                f'<td class="day-label">Day {day_number if day_number is not None else "N/A"}</td>'
                f'<td>{html_escape(d)}</td>'
                f'<td>{td_money(tn)}</td><td>{td_money(kerala)}</td><td>{td_money(karnataka)}</td>'
                f'<td>{td_money(telugu)}</td><td>{td_money(roi)}</td><td>{td_money(india_total)}</td>'
                f'<td>{td_money(overseas_val)}</td><td>{td_money(worldwide_val)}</td></tr>'
            )
        if rows_html:
            template = re.sub(
                r'(<tbody id="dayStateMatrixBody">).*?(</tbody>)',
                lambda mt: mt.group(1) + ''.join(rows_html) + mt.group(2),
                template,
                count=1,
                flags=re.S,
            )

    template = re.sub(
        r'(id="worldwide"\s+class=")worldwide-value\s+loading("\s*)',
        r'\1worldwide-value\2',
        template,
        count=1,
    )

    # Movie-profile SSR validation: never silently serve a thin shell.
    required_movie_ssr = (
        'data-ssr="1" data-movie-id=',
        'id="movieTitle"',
        'id="movieBoxOfficeHeading"',
        'id="movieCastDetails" data-ssr="1"',
        'id="movieFaq" data-ssr="1"',
        '"@type": "BreadcrumbList"',
        '"@type": "FAQPage"',
    )
    missing = [marker for marker in required_movie_ssr if marker not in template]
    if missing:
        raise RuntimeError("Movie SSR validation failed: " + ", ".join(missing))

    return template


def _movie_ssr_cached(movie_slug: str):
    now = time_module.monotonic()
    with _movie_html_cache_lock:
        cached = _movie_html_cache.get(movie_slug)
        if cached and cached["expires_at"] > now:
            return cached["html"], "HIT"

    rendered = _movie_ssr_build(movie_slug)
    if rendered is None:
        return None, "MISS"

    with _movie_html_cache_lock:
        _movie_html_cache[movie_slug] = {
            "html": rendered,
            "expires_at": time_module.monotonic() + MOVIE_HTML_CACHE_TTL,
        }
    return rendered, "MISS"


# ============================================================
# ACTOR DETAIL - CACHED SERVER-RENDERED SEO CONTENT
# ============================================================

ACTOR_HTML_CACHE_TTL = 300
_actor_html_cache = {}
_actor_html_cache_lock = threading.Lock()


def _actor_ssr_money(value):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0.0
    if number.is_integer():
        return str(int(number))
    return f"{number:.2f}".rstrip("0").rstrip(".")


def _actor_ssr_money_known(value):
    if value is None or value == "":
        return "N/A"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "N/A"
    if number.is_integer():
        return str(int(number))
    return f"{number:.2f}".rstrip("0").rstrip(".")


def _actor_ssr_pronoun(profession):
    value = str(profession or "").strip().lower()
    if "actress" in value:
        return "her"
    if value == "actor" or value.startswith("actor ") or " actor" in value:
        return "his"
    return "their"


def _actor_ssr_movie_image(movie):
    # actor.html intentionally uses the generated BoxOfficeX movie placeholder.
    return _home_movie_placeholder(movie)


def _actor_ssr_profile_image(actor):
    # actor.html intentionally uses the generated BoxOfficeX actor placeholder.
    return _home_actor_placeholder(actor.get("name") or "Actor")


def _actor_ssr_build(actor_slug: str):
    actor_identity = resolve_actor_slug(actor_slug)
    if not actor_identity:
        return None

    actor_id = int(actor_identity["id"])
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, profession, photo, bio
                FROM actors
                WHERE id = %s
            """, (actor_id,))
            row = cur.fetchone()

    if not row:
        return None

    actor = {
        "id": row[0], "name": row[1] or "Actor", "profession": row[2] or "Actor",
        "photo": row[3], "bio": row[4] or "No biography available.",
        "slug": actor_slug, "url": f"/actor/{actor_slug}",
    }
    movies = get_actor_movies(actor_id).get("movies", [])
    overview = get_actor_overview(actor_id)
    top_movies = get_actor_top_movies(actor_id).get("movies", [])

    movie_by_id = {movie.get("id"): movie for movie in movies}
    movie_slug_map = _unique_movie_slug_map()
    for movie in top_movies:
        full_movie = movie_by_id.get(movie.get("id"), {})
        for key in ("budget_crore", "india_collection_crore", "overseas_collection_crore"):
            movie[key] = full_movie.get(key)
        movie["slug"] = movie_slug_map.get(movie.get("id"), movie_seo_slug(movie.get("id"), movie.get("title"), movie.get("release_date")))
        movie["url"] = f'/movie/{movie["slug"]}'

    template = _inject_boxofficex_global_icons((BASE_DIR / "actor.html").read_text(encoding="utf-8"))
    name, profession, bio = str(actor["name"]), str(actor["profession"]), str(actor["bio"])
    canonical = f"https://boxofficex.in/actor/{actor_slug}"
    title = f"{name} Movies, Box Office Collection & Career Statistics | BoxOfficeX"

    # CTR-focused Google description: career scale + recent five-film performance.
    # get_actor_movies() is already ordered newest release first. Future/unreleased
    # titles are excluded, and missing worldwide values are never treated as zero.
    today = date.today()
    released_movies = []
    for movie in movies:
        try:
            release_day = date.fromisoformat(str(movie.get("release_date") or "")[:10])
        except (TypeError, ValueError):
            continue
        if release_day <= today:
            released_movies.append(movie)

    last_five = released_movies[:5]
    last_five_worldwide = [
        float(movie["worldwide_collection_crore"])
        for movie in last_five
        if movie.get("worldwide_collection_crore") is not None
    ]
    recent_avg = (
        sum(last_five_worldwide) / len(last_five_worldwide)
        if last_five_worldwide else None
    )

    movie_count = int(overview.get("total_movies") or len(movies) or 0)
    blockbuster_count = int(overview.get("blockbusters") or 0)
    hit_count = int(overview.get("hits") or 0)
    known_worldwide_for_meta = [m for m in movies if m.get("worldwide_collection_crore") is not None]
    career_worldwide = sum(float(m["worldwide_collection_crore"]) for m in known_worldwide_for_meta)

    meta_parts = [f"{name} Box Office: {movie_count} movies tracked"]
    if blockbuster_count:
        meta_parts.append(f"{blockbuster_count} blockbusters")
    elif hit_count:
        meta_parts.append(f"{hit_count} hits")
    if career_worldwide > 0:
        meta_parts.append(f"₹{_actor_ssr_money(career_worldwide)} Cr worldwide gross")

    description = ", ".join(meta_parts) + "."
    if recent_avg is not None:
        if len(last_five_worldwide) == 5:
            description += f" Last 5 films averaged ₹{_actor_ssr_money(recent_avg)} Cr worldwide."
        else:
            possessive = _actor_ssr_pronoun(profession).capitalize()
            description += f" {possessive} last {len(last_five_worldwide)} films averaged ₹{_actor_ssr_money(recent_avg)} Cr worldwide."
    description += " See budgets & verdicts."

    profile_image = _actor_ssr_profile_image(actor)

    template = re.sub(r"<title>.*?</title>", f"<title>{html_escape(title)}</title>", template, count=1, flags=re.S)
    template = re.sub(r'(<meta\s+name="description"\s+content=")[^"]*(")', lambda m: m.group(1)+html_escape(description, quote=True)+m.group(2), template, count=1, flags=re.S)
    template = re.sub(r'(<link\s+id="canonicalUrl"\s+rel="canonical"\s+href=")[^"]*(")', lambda m: m.group(1)+canonical+m.group(2), template, count=1)
    for element_id, value in (("ogTitle", title), ("ogDescription", description), ("ogUrl", canonical), ("ogImage", profile_image), ("twitterTitle", title), ("twitterDescription", description), ("twitterImage", profile_image)):
        template = re.sub(r'(<meta id="'+re.escape(element_id)+r'"[^>]*content=")[^"]*(")', lambda m, v=value: m.group(1)+html_escape(v, quote=True)+m.group(2), template, count=1)

    structured = {"@context":"https://schema.org", "@graph":[
        {"@type":"Person", "name":name, "url":canonical, "image":profile_image, "jobTitle":profession, "description":bio},
        {"@type":"BreadcrumbList", "itemListElement":[
            {"@type":"ListItem", "position":1, "name":"Home", "item":"https://boxofficex.in/"},
            {"@type":"ListItem", "position":2, "name":"Actors", "item":"https://boxofficex.in/actors.html"},
            {"@type":"ListItem", "position":3, "name":name, "item":canonical}
        ]}
    ]}
    template = re.sub(r'<script id="actorStructuredData" type="application/ld\+json">.*?</script>', '<script id="actorStructuredData" type="application/ld+json">'+json.dumps(structured, ensure_ascii=False).replace("</", "<\\/")+"</script>", template, count=1, flags=re.S)

    known_budget=[m for m in movies if m.get("budget_crore") is not None]
    known_india=[m for m in movies if m.get("india_collection_crore") is not None]
    known_overseas=[m for m in movies if m.get("overseas_collection_crore") is not None]
    known_worldwide=[m for m in movies if m.get("worldwide_collection_crore") is not None]
    total_budget=sum(float(m["budget_crore"]) for m in known_budget)
    total_india=sum(float(m["india_collection_crore"]) for m in known_india)
    total_overseas=sum(float(m["overseas_collection_crore"]) for m in known_overseas)
    total_worldwide=sum(float(m["worldwide_collection_crore"]) for m in known_worldwide)
    avg_budget=total_budget/len(known_budget) if known_budget else None
    avg_worldwide=total_worldwide/len(known_worldwide) if known_worldwide else None
    highest_budget_movie=max(known_budget,key=lambda m:float(m["budget_crore"])) if known_budget else None
    highest_worldwide_movie=max(known_worldwide,key=lambda m:float(m["worldwide_collection_crore"])) if known_worldwide else None

    # Keep the visible actor hero profile-first (IMDb/Wikipedia-style).
    # SEO targeting lives in metadata, descriptive section headings and crawlable data below.
    hero=f'''<div class="actor" data-ssr="1" data-actor-id="{actor_id}">
        <h1 id="actorName">{html_escape(name)} Movies, Box Office Collection &amp; Career Statistics</h1>
        <img id="actorPhoto" src="{html_escape(profile_image, quote=True)}" alt="{html_escape(name, quote=True)} profile">
        <div id="profession">{html_escape(profession)}</div>
        <div id="actorViewCount" class="actor-view-count">👁 0 Views</div>
        <p id="bio">{html_escape(bio)}</p>
    </div>'''
    top_movie = highest_worldwide_movie or (top_movies[0] if top_movies else None)
    top_movie_name = str((top_movie or {}).get("title") or "not available")
    top_movie_gross = (top_movie or {}).get("worldwide_collection_crore")
    intro_parts = [f"<strong>{html_escape(name)}</strong> has {movie_count} movies tracked on BoxOfficeX."]
    if total_worldwide > 0:
        intro_parts.append(f"The tracked films have a combined worldwide gross of <strong>₹{_actor_ssr_money_known(total_worldwide)} Cr</strong>.")
    if top_movie and top_movie_gross is not None:
        intro_parts.append(f"The highest-grossing tracked film is <strong>{html_escape(top_movie_name)}</strong> at <strong>₹{_actor_ssr_money_known(top_movie_gross)} Cr</strong> worldwide.")
    intro_parts.append(f"The current verdict record includes <strong>{blockbuster_count} blockbusters</strong>, <strong>{hit_count} hits</strong> and <strong>{int(overview.get('flops') or 0)} flops</strong>.")
    actor_intro = '<section id="bxActorSeoIntro" class="bx-actor-seo-intro" data-ssr="1"><p>' + ' '.join(intro_parts) + '</p></section>'

    # actor.html may itself contain a previously SSR-rendered actor.
    # Match the actor hero regardless of data-ssr/data-actor-id attributes so
    # every /actor/{slug} request receives the actor resolved from that slug.
    actor_shell_pattern = re.compile(
        r'<div\b(?=[^>]*\bclass=["\'][^"\']*\bactor\b[^"\']*["\'])[^>]*>'
        r'.*?</div>\s*'
        r'<section\b(?=[^>]*\bid=["\']bxActorSeoIntro["\'])[^>]*>.*?</section>\s*'
        r'<section\b(?=[^>]*\bid=["\']bxActorPageAd["\'])',
        re.S | re.I,
    )
    template, actor_shell_count = actor_shell_pattern.subn(
        hero + '\n\n    ' + actor_intro + '\n\n    <section id="bxActorPageAd"',
        template,
        count=1,
    )
    if actor_shell_count != 1:
        raise RuntimeError(
            f"Actor SSR hero injection failed for {actor_slug}: "
            f"expected 1 actor shell, found {actor_shell_count}"
        )

    # Descriptive headings must also be regenerated on every actor request.
    # This is intentionally regex-based so a previously SSR-rendered actor.html
    # cannot leak Vijay (or any other actor) into another actor page.
    template = re.sub(
        r'<h2>[^<]*📊.*?Box Office Career Overview</h2>|'
        r'<h2>\s*📊\s*Career Overview\s*</h2>',
        f'<h2>📊 {html_escape(name)} Box Office Career Overview</h2>',
        template, count=1, flags=re.S | re.I
    )
    template = re.sub(
        r'<h2>[^<]*💰.*?Career Box Office Statistics</h2>|'
        r'<h2>\s*💰\s*Budget\s*&(?:amp;)?\s*Box Office Overview\s*</h2>',
        f'<h2>💰 {html_escape(name)} Career Box Office Statistics</h2>',
        template, count=1, flags=re.S | re.I
    )
    template = re.sub(
        r'<h2>[^<]*🏆.*?Highest-Grossing Movies</h2>|'
        r'<h2>\s*🏆\s*Top 5 Highest-Grossing Movies\s*</h2>',
        f'<h2>🏆 {html_escape(name)} Highest-Grossing Movies</h2>',
        template, count=1, flags=re.S | re.I
    )
    template = re.sub(
        r'<h3\s+class=["\']career-record-heading["\']>.*?</h3>',
        f'<h3 class="career-record-heading">{html_escape(name)} Hit, Flop &amp; Verdict Record</h3>',
        template, count=1, flags=re.S | re.I
    )
    template = re.sub(
        r'<h2>[^<]*🎬.*?(?:Movies\s*&(?:amp;)?\s*Complete Filmography|Complete Filmography)</h2>',
        f'<h2>🎬 {html_escape(name)} Movies &amp; Complete Filmography</h2>',
        template, count=1, flags=re.S | re.I
    )

    overview_html=f'''<div id="overviewGrid" data-ssr="1">
        <div class="overview-card overview-highlight-card" role="button" tabindex="0" onclick="openAllMoviesSection()" onkeydown="handleAllMoviesKey(event)"><div class="overview-label">🎬 Movies Tracked</div><div class="overview-value">{len(movies)}</div></div>
        <div class="overview-card overview-verdict-card" role="button" tabindex="0" data-verdict="Blockbuster" onclick="openCareerVerdict('Blockbuster', this)" onkeydown="handleCareerVerdictKey(event, 'Blockbuster', this)"><div class="overview-label">🔥 Blockbusters</div><div class="overview-value">{int(overview.get("blockbusters") or 0)}</div></div>
        <div class="overview-card overview-verdict-card" role="button" tabindex="0" data-verdict="Hit" onclick="openCareerVerdict('Hit', this)" onkeydown="handleCareerVerdictKey(event, 'Hit', this)"><div class="overview-label">⭐ Hits</div><div class="overview-value">{int(overview.get("hits") or 0)}</div></div>
        <div class="overview-card overview-verdict-card" role="button" tabindex="0" data-verdict="Average" onclick="openCareerVerdict('Average', this)" onkeydown="handleCareerVerdictKey(event, 'Average', this)"><div class="overview-label">📊 Average</div><div class="overview-value">{int(overview.get("average_movies") or 0)}</div></div>
        <div class="overview-card overview-verdict-card" role="button" tabindex="0" data-verdict="Flop" onclick="openCareerVerdict('Flop', this)" onkeydown="handleCareerVerdictKey(event, 'Flop', this)"><div class="overview-label">❌ Flops</div><div class="overview-value">{int(overview.get("flops") or 0)}</div></div>
    </div>'''
    template, overview_count = re.subn(
        r'<div\b(?=[^>]*\bid=["\']overviewGrid["\'])[^>]*>.*?</div>\s*</section>',
        overview_html + '\n\n    </section>',
        template, count=1, flags=re.S | re.I
    )
    if overview_count != 1:
        raise RuntimeError(f"Actor overview SSR injection failed for {actor_slug}")

    def stat_card(label,value):
        return f'<div class="overview-card"><div class="overview-label">{label}</div><div class="overview-value">{value}</div></div>'
    budget_grid="".join([
        stat_card("Movies With Budget Data",str(len(known_budget))),
        stat_card("Combined Reported Budget",f"₹{_actor_ssr_money_known(total_budget)} Cr" if known_budget else "N/A"),
        stat_card("Average Reported Budget",f"₹{_actor_ssr_money_known(avg_budget)} Cr" if avg_budget is not None else "N/A"),
        stat_card("Movies With Worldwide Data",str(len(known_worldwide))),
        stat_card("Total India Gross",f"₹{_actor_ssr_money_known(total_india)} Cr" if known_india else "N/A"),
        stat_card("Total Overseas Gross",f"₹{_actor_ssr_money_known(total_overseas)} Cr" if known_overseas else "N/A"),
        stat_card("Total Worldwide Gross",f"₹{_actor_ssr_money_known(total_worldwide)} Cr" if known_worldwide else "N/A"),
        stat_card("Average Worldwide Gross",f"₹{_actor_ssr_money_known(avg_worldwide)} Cr" if avg_worldwide is not None else "N/A"),
        stat_card("Highest-Grossing Movie",html_escape(str((highest_worldwide_movie or {}).get("title") or "N/A"))),
        stat_card("Highest-Budget Movie",(html_escape(str(highest_budget_movie.get("title")))+f" · ₹{_actor_ssr_money_known(highest_budget_movie.get('budget_crore'))} Cr") if highest_budget_movie else "N/A")
    ])
    budget_note=f"Averages use only movies with the relevant data available. Worldwide average is based on {len(known_worldwide)} tracked movies; budget average is based on {len(known_budget)} tracked movies. Missing values are not treated as zero."
    template, budget_count = re.subn(
        r'<div\b(?=[^>]*\bid=["\']boxOfficeOverviewGrid["\'])[^>]*>.*?</div>\s*'
        r'<p\b(?=[^>]*\bid=["\']boxOfficeOverviewNote["\'])[^>]*>.*?</p>',
        f'<div id="boxOfficeOverviewGrid" data-ssr="1">{budget_grid}</div>'
        f'<p class="actor-data-note" id="boxOfficeOverviewNote">{html_escape(budget_note)}</p>',
        template, count=1, flags=re.S | re.I
    )
    if budget_count != 1:
        raise RuntimeError(f"Actor box-office overview SSR injection failed for {actor_slug}")

    top_cards=[]
    for index,movie in enumerate(top_movies):
        url=movie.get("url") or "#"; image=_actor_ssr_movie_image(movie); movie_title=str(movie.get("title") or "Movie")
        budget=_actor_ssr_money_known(movie.get("budget_crore")); india=_actor_ssr_money_known(movie.get("india_collection_crore")); overseas=_actor_ssr_money_known(movie.get("overseas_collection_crore")); worldwide=_actor_ssr_money_known(movie.get("worldwide_collection_crore"))
        top_cards.append(f'<a class="top-movie-card" href="{html_escape(url, quote=True)}"><img src="{html_escape(image, quote=True)}" alt="{html_escape(movie_title, quote=True)}" loading="lazy" decoding="async"><div class="top-movie-title">#{index+1} {html_escape(movie_title)}</div><div class="top-movie-collection">🌍 {"₹"+worldwide+" Cr" if worldwide != "N/A" else "N/A"}</div><div class="top-movie-financials">Budget: {"₹"+budget+" Cr" if budget != "N/A" else "N/A"}<br>India: {"₹"+india+" Cr" if india != "N/A" else "N/A"} · Overseas: {"₹"+overseas+" Cr" if overseas != "N/A" else "N/A"}<br>Verdict: {html_escape(str(movie.get("verdict") or "N/A"))}</div></a>')
    highest_url=top_movies[0].get("url") if top_movies else ""
    top_html=f'<div id="topMovies" data-ssr="1" data-ssr-highest-url="{html_escape(highest_url or "", quote=True)}">'+("".join(top_cards) if top_cards else "<p>No top movies found.</p>")+"</div>"
    template, top_movies_count = re.subn(
        r'<div\b(?=[^>]*\bid=["\']topMovies["\'])[^>]*>.*?</div>\s*</section>',
        top_html + '\n\n    </section>',
        template, count=1, flags=re.S | re.I
    )
    if top_movies_count != 1:
        raise RuntimeError(f"Actor top-movies SSR injection failed for {actor_slug}")

    movie_cards=[]
    for index,movie in enumerate(movies):
        url=movie.get("url") or "#"; image=_actor_ssr_movie_image(movie); movie_title=str(movie.get("title") or "Movie")
        budget=_actor_ssr_money_known(movie.get("budget_crore")); india=_actor_ssr_money_known(movie.get("india_collection_crore")); overseas=_actor_ssr_money_known(movie.get("overseas_collection_crore")); worldwide=_actor_ssr_money_known(movie.get("worldwide_collection_crore"))
        financials=f'<div class="movie-financials"><span>Budget: {"₹"+budget+" Cr" if budget != "N/A" else "N/A"}</span><span>India: {"₹"+india+" Cr" if india != "N/A" else "N/A"}</span><span>Overseas: {"₹"+overseas+" Cr" if overseas != "N/A" else "N/A"}</span><span>Worldwide: {"₹"+worldwide+" Cr" if worldwide != "N/A" else "N/A"}</span></div>'
        movie_cards.append(f'<a class="movie-item" href="{html_escape(url, quote=True)}"><img src="{html_escape(image, quote=True)}" alt="{html_escape(movie_title, quote=True)}" loading="lazy" decoding="async"><div class="movie-details"><div class="movie-title">{html_escape(movie_title)}</div><div class="movie-info">📅 Release: {html_escape(str(movie.get("release_date") or "N/A"))}</div>{financials}<div class="movie-verdict">🎬 Verdict: {html_escape(str(movie.get("verdict") or "N/A"))}</div></div></a>')
        if index==7 and len(movies)>=12:
            movie_cards.append('<section id="bxSmartAdSlot3" class="bx-smart-ad-slot" aria-label="Advertisement slot 3"></section>')
    movie_html='<div id="movieList" data-ssr="1">'+("".join(movie_cards) if movie_cards else "<p>No movies found.</p>")+"</div>"
    template, movie_list_count = re.subn(
        r'<div\b(?=[^>]*\bid=["\']movieList["\'])[^>]*>.*?</div>\s*</section>',
        movie_html + '\n\n    </section>',
        template, count=1, flags=re.S | re.I
    )
    if movie_list_count != 1:
        raise RuntimeError(f"Actor filmography SSR injection failed for {actor_slug}")

    flop_count = int(overview.get("flops") or 0)
    highest_answer = (
        f"{name}'s highest-grossing tracked movie is {top_movie_name} with ₹{_actor_ssr_money_known(top_movie_gross)} Cr worldwide."
        if top_movie and top_movie_gross is not None
        else f"A highest-grossing movie is not currently available for {name} in the tracked data."
    )
    worldwide_answer = (
        f"The movies currently tracked for {name} have a combined worldwide gross of ₹{_actor_ssr_money_known(total_worldwide)} Cr."
        if known_worldwide
        else f"Worldwide collection data is not currently available for {name}'s tracked movies."
    )
    faq_items = [
        (f"How many movies does {name} have on BoxOfficeX?", f"BoxOfficeX currently tracks {movie_count} movies for {name}."),
        (f"What is {name}'s total worldwide box office collection?", worldwide_answer),
        (f"What is {name}'s highest-grossing movie?", highest_answer),
        (f"How many blockbusters, hits and flops does {name} have?", f"The current BoxOfficeX verdict data lists {blockbuster_count} blockbusters, {hit_count} hits and {flop_count} flops for {name}."),
    ]
    faq_html = '<section id="bxActorFaq" class="bx-actor-faq" data-ssr="1"><h2>'+html_escape(name)+' Box Office FAQ</h2>' + ''.join(
        '<details><summary>'+html_escape(q)+'</summary><p>'+html_escape(a)+'</p></details>' for q,a in faq_items
    ) + '</section>'
    template = re.sub(r'<section id="bxActorFaq".*?</section>', faq_html, template, count=1, flags=re.S)

    # Add FAQPage to the same SSR JSON-LD graph already used for Person + breadcrumbs.
    structured["@graph"].append({
        "@type": "FAQPage",
        "mainEntity": [
            {"@type":"Question", "name":q, "acceptedAnswer":{"@type":"Answer", "text":a}}
            for q,a in faq_items
        ],
    })
    template = re.sub(r'<script id="actorStructuredData" type="application/ld\+json">.*?</script>', '<script id="actorStructuredData" type="application/ld+json">'+json.dumps(structured, ensure_ascii=False).replace("</", "<\\/")+"</script>", template, count=1, flags=re.S)
    return template


def _actor_ssr_cached(actor_slug: str):
    now=time_module.monotonic()
    with _actor_html_cache_lock:
        cached=_actor_html_cache.get(actor_slug)
        if cached and cached["expires_at"] > now:
            return cached["html"], "HIT"
    rendered=_actor_ssr_build(actor_slug)
    if rendered is None:
        return None, "MISS"
    with _actor_html_cache_lock:
        _actor_html_cache[actor_slug]={"html":rendered, "expires_at":time_module.monotonic()+ACTOR_HTML_CACHE_TTL}
    return rendered, "MISS"


@app.get("/actor-movies.html", include_in_schema=False)
def actor_movies_page(id: Optional[int] = None):
    if id is None:
        return RedirectResponse(url="/actors.html", status_code=301)

    actor_url = public_actor_url(id)
    if actor_url == "/actors.html":
        raise HTTPException(status_code=404, detail="Actor not found")

    return RedirectResponse(url=f"{actor_url}/movies", status_code=301)


@app.get("/actor.html", include_in_schema=False)
def actor_page(id: Optional[int] = None):
    # Legacy public URL -> one canonical clean URL.
    if id is None:
        return RedirectResponse(url="/actors.html", status_code=301)

    actor_url = public_actor_url(id)
    if actor_url == "/actors.html":
        raise HTTPException(status_code=404, detail="Actor not found")

    return RedirectResponse(url=actor_url, status_code=301)


# Clean public SEO routes.
# movie.html / actor.html remain available during the migration stage.
@app.get("/movie/{movie_slug}", include_in_schema=False)
def movie_slug_page(movie_slug: str):
    movie = resolve_movie_slug(movie_slug)
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")

    try:
        rendered, cache_state = _movie_ssr_cached(movie_slug)
        if rendered is None:
            raise HTTPException(status_code=404, detail="Movie not found")
        return HTMLResponse(
            content=rendered,
            headers={
                "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                "X-BoxOfficeX-Movie": "cached-ssr",
                "X-BoxOfficeX-Cache": cache_state,
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        print("Movie SSR fallback:", type(exc).__name__, exc, flush=True)
        return FileResponse(
            BASE_DIR / "movie.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Movie": "ssr-fallback",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
            },
        )


@app.get("/actor/{actor_slug}/movies", include_in_schema=False)
def actor_movies_slug_page(actor_slug: str):
    actor = resolve_actor_slug(actor_slug)

    if not actor:
        raise HTTPException(
            status_code=404,
            detail="Actor not found"
        )

    return FileResponse(BASE_DIR / "actor-movies.html")


@app.get("/actor/{actor_slug}", include_in_schema=False)
def actor_slug_page(actor_slug: str):
    actor = resolve_actor_slug(actor_slug)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    try:
        rendered, cache_state = _actor_ssr_cached(actor_slug)
        if rendered is None:
            raise HTTPException(status_code=404, detail="Actor not found")
        return HTMLResponse(
            content=rendered,
            headers={
                "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                "X-BoxOfficeX-Actor": "cached-ssr",
                "X-BoxOfficeX-Cache": cache_state,
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        print("Actor SSR fallback:", type(exc).__name__, exc, flush=True)
        return FileResponse(
            BASE_DIR / "actor.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Actor": "ssr-fallback",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
            },
        )


@app.get("/seo/resolve/movie/{movie_slug}", include_in_schema=False)
def seo_resolve_movie(movie_slug: str):
    movie = resolve_movie_slug(movie_slug)
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    return movie


@app.get("/seo/resolve/actor/{actor_slug}", include_in_schema=False)
def seo_resolve_actor(actor_slug: str):
    actor = resolve_actor_slug(actor_slug)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


# ============================================================
# ACTORS LIST - NON-BLOCKING CACHED SSR
# ============================================================

ACTORS_LIST_HTML_CACHE_TTL = 300
_actors_list_html_cache = {"html": None, "expires_at": 0.0}
_actors_list_html_cache_lock = threading.Lock()
_actors_list_html_refreshing = False

_ACTORS_LIST_FEATURED_GROUPS = [
    ("Tamil", [7, 8, 9, 10, 11]),
    ("Telugu", [27, 28, 29, 30, 31]),
    ("Hindi", [37, 38, 39, 40, 41]),
    ("Malayalam", [47, 48, 49, 50, 51]),
    ("Kannada", [54, 55, 56, 57, 58]),
]


def _actors_list_ssr_card(actor):
    name = str(actor.get("name") or "Actor").strip() or "Actor"
    profession = str(actor.get("profession") or "Actor").strip() or "Actor"
    url = str(actor.get("url") or "/actors.html")
    # actors.html intentionally uses branded placeholders for copyright-safe parity.
    photo = _home_actor_placeholder(name)
    return (
        f'<a class="actor-card" href="{html_escape(url, quote=True)}" '
        f'aria-label="View {html_escape(name, quote=True)} actor profile">'
        f'<img src="{html_escape(photo, quote=True)}" data-actor-name="{html_escape(name, quote=True)}" '
        f'alt="{html_escape(name, quote=True)}" loading="lazy">'
        f'<div class="actor-name">{html_escape(name)}</div>'
        f'<div class="actor-profession">{html_escape(profession)}</div>'
        f'</a>'
    )


def _render_actors_list_html():
    template = _inject_boxofficex_global_icons((BASE_DIR / "actors.html").read_text(encoding="utf-8"))
    data = get_actors()
    actors = list(data.get("actors") or [])
    by_id = {int(actor["id"]): actor for actor in actors if actor.get("id") is not None}

    sections = []
    visible = []
    for language, ids in _ACTORS_LIST_FEATURED_GROUPS:
        group = [by_id[actor_id] for actor_id in ids if actor_id in by_id]
        if not group:
            continue
        visible.extend(group)
        cards = "".join(_actors_list_ssr_card(actor) for actor in group)
        sections.append(
            '<section class="language-section">'
            f'<h2 class="language-heading">🎬 {html_escape(language)}</h2>'
            '<div class="swipe-hint">↔ Swipe to explore more</div>'
            f'<div class="language-grid">{cards}</div>'
            '</section>'
        )

    ssr_grid = f'<div id="actorsGrid" class="actor-grid" data-ssr="1">{"".join(sections)}</div>'
    grid_pattern = re.compile(r'<div\s+id="actorsGrid"\s+class="actor-grid"\s*>.*?</div>\s*(?=<section\s+class="bx-popular-comparisons")', re.S | re.I)
    template, count = grid_pattern.subn(ssr_grid + "\n\n    ", template, count=1)
    if count != 1:
        raise RuntimeError("Actors list SSR body injection failed")

    item_list = []
    for position, actor in enumerate(visible, 1):
        item_list.append({
            "@type": "ListItem",
            "position": position,
            "name": actor.get("name") or "Actor",
            "url": "https://boxofficex.in" + str(actor.get("url") or "/actors.html"),
        })
    faq_entities = [
        {
            "@type": "Question",
            "name": "Which Indian film industries are covered on BoxOfficeX?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "BoxOfficeX currently highlights actors from Tamil, Telugu, Hindi, Malayalam and Kannada cinema."
            },
        },
        {
            "@type": "Question",
            "name": "What information is available on an actor profile?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "Actor profiles can include filmography, worldwide box office collections, career statistics, movie verdicts and highest-grossing films based on the data tracked by BoxOfficeX."
            },
        },
        {
            "@type": "Question",
            "name": "Can I compare two actors on BoxOfficeX?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "Yes. Use Actor Comparison to compare tracked career and box office data for supported actors."
            },
        },
    ]
    structured = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "CollectionPage",
                "@id": "https://boxofficex.in/actors.html#webpage",
                "name": "Indian Actors, Movies & Box Office Careers | BoxOfficeX",
                "url": "https://boxofficex.in/actors.html",
                "description": "Explore popular Indian actors across Tamil, Telugu, Hindi, Malayalam and Kannada cinema, with movies, box office collections, career highlights and verdicts on BoxOfficeX.",
                "mainEntity": {
                    "@type": "ItemList",
                    "name": "Popular Indian Actors",
                    "numberOfItems": len(item_list),
                    "itemListElement": item_list,
                },
            },
            {
                "@type": "BreadcrumbList",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://boxofficex.in/"},
                    {"@type": "ListItem", "position": 2, "name": "Actors", "item": "https://boxofficex.in/actors.html"},
                ],
            },
            {
                "@type": "FAQPage",
                "mainEntity": faq_entities,
            },
        ],
    }
    json_ld = json.dumps(structured, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    template, count = re.subn(
        r'<script\s+id="actorsStructuredData"\s+type="application/ld\+json"\s*>.*?</script>',
        f'<script id="actorsStructuredData" type="application/ld+json">{json_ld}</script>',
        template,
        count=1,
        flags=re.S | re.I,
    )
    if count != 1:
        raise RuntimeError("Actors list structured-data injection failed")

    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    marker = "</head>"
    if marker not in template:
        raise RuntimeError("Actors list </head> marker missing")
    template = template.replace(
        marker,
        f'<script>window.__BOXOFFICEX_ACTORS_SSR_DATA__={payload};</script>\n{marker}',
        1,
    )

    if 'id="actorsGrid" class="actor-grid" data-ssr="1"' not in template:
        raise RuntimeError("Actors list SSR validation failed")
    if 'href="/actor/' not in template:
        raise RuntimeError("Actors list crawlable href validation failed")
    if 'id="bxActorsExploreTitle"' not in template:
        raise RuntimeError("Actors list explore section validation failed")
    if '<h3>Career Statistics</h3>' not in template:
        raise RuntimeError("Actors list H3 content validation failed")
    if 'id="bxActorsFaq"' not in template:
        raise RuntimeError("Actors list FAQ validation failed")
    if '"@type":"FAQPage"' not in template:
        raise RuntimeError("Actors list FAQ schema validation failed")
    return template


def _refresh_actors_list_cache():
    global _actors_list_html_refreshing
    try:
        rendered = _render_actors_list_html()
        with _actors_list_html_cache_lock:
            _actors_list_html_cache["html"] = rendered
            _actors_list_html_cache["expires_at"] = time_module.monotonic() + ACTORS_LIST_HTML_CACHE_TTL
    except Exception as exc:
        print("Actors list SSR cache refresh failed:", type(exc).__name__, exc, flush=True)
    finally:
        with _actors_list_html_cache_lock:
            _actors_list_html_refreshing = False


def _start_actors_list_refresh():
    global _actors_list_html_refreshing
    with _actors_list_html_cache_lock:
        if _actors_list_html_refreshing:
            return
        _actors_list_html_refreshing = True
    threading.Thread(target=_refresh_actors_list_cache, name="actors-list-ssr", daemon=True).start()


@app.on_event("startup")
def warm_actors_list_ssr_cache():
    _start_actors_list_refresh()


@app.get("/actors.html")
def actors_page():
    now = time_module.monotonic()
    with _actors_list_html_cache_lock:
        cached_html = _actors_list_html_cache.get("html")
        expires_at = float(_actors_list_html_cache.get("expires_at") or 0.0)

    if cached_html and expires_at > now:
        return HTMLResponse(content=cached_html, headers={
            "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
            "X-BoxOfficeX-Actors-List": "cached-ssr",
            "X-BoxOfficeX-Cache": "HIT",
        })

    if cached_html:
        _start_actors_list_refresh()
        return HTMLResponse(content=cached_html, headers={
            "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
            "X-BoxOfficeX-Actors-List": "cached-ssr",
            "X-BoxOfficeX-Cache": "STALE",
        })

    # Cold cache: render synchronously so crawlers and first-time visitors
    # receive the complete actor directory instead of the raw JS shell.
    rendered = _render_actors_list_html()
    with _actors_list_html_cache_lock:
        _actors_list_html_cache["html"] = rendered
        _actors_list_html_cache["expires_at"] = time_module.monotonic() + ACTORS_LIST_HTML_CACHE_TTL

    return HTMLResponse(content=rendered, headers={
        "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
        "X-BoxOfficeX-Actors-List": "cached-ssr",
        "X-BoxOfficeX-Cache": "MISS",
    })


def resolve_actor_comparison_slug(comparison_slug: str):
    slug_map = _unique_actor_slug_map()
    by_slug = {slug: actor_id for actor_id, slug in slug_map.items()}

    # Match only the canonical ID-ordered pair. This guarantees that
    # A-vs-B and B-vs-A have one public SEO URL.
    actor_ids = sorted(slug_map.keys())

    for index, first_id in enumerate(actor_ids):
        first_slug = slug_map[first_id]
        prefix = first_slug + "-vs-"

        if not comparison_slug.startswith(prefix):
            continue

        second_slug = comparison_slug[len(prefix):]
        second_id = by_slug.get(second_slug)

        if second_id is None or second_id == first_id:
            continue

        canonical_ids = sorted([first_id, second_id])
        canonical_first_id, canonical_second_id = canonical_ids
        canonical_slug = (
            f"{slug_map[canonical_first_id]}-vs-{slug_map[canonical_second_id]}"
        )

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name FROM actors WHERE id IN (%s, %s)",
                    (first_id, second_id)
                )
                rows = cur.fetchall()

        actors = {row[0]: {"id": row[0], "name": row[1], "slug": slug_map[row[0]]}
                  for row in rows}

        if len(actors) != 2:
            return None

        return {
            "actor1": actors[canonical_first_id],
            "actor2": actors[canonical_second_id],
            "canonical_slug": canonical_slug,
            "canonical_url": f"/compare/{canonical_slug}",
            "is_canonical": comparison_slug == canonical_slug
        }

    return None


# ============================================================
# ACTOR COMPARISON - NON-BLOCKING CACHED SSR
# ============================================================

ACTOR_COMPARISON_HTML_CACHE_TTL = 300
_actor_comparison_html_cache = {}
_actor_comparison_cache_lock = threading.Lock()
_actor_comparison_refreshing = set()


def _actor_comparison_ssr_number(value, digits=2):
    try:
        return f"{float(value):,.{digits}f}"
    except (TypeError, ValueError):
        return "0.00"


def _actor_comparison_ssr_movie_url(movie):
    movie_id = movie.get("id")
    if movie_id is None:
        return "/new-movies.html"
    try:
        return public_movie_url(int(movie_id))
    except Exception:
        return "/new-movies.html"


def _render_actor_comparison_html(comparison):
    template = _inject_boxofficex_global_icons((BASE_DIR / "compare.html").read_text(encoding="utf-8"))
    actor1 = comparison["actor1"]
    actor2 = comparison["actor2"]
    payload = compare_actors(int(actor1["id"]), int(actor2["id"]))
    actors_by_id = {int(a["id"]): a for a in (payload.get("comparison") or [])}
    left = actors_by_id.get(int(actor1["id"]), actor1)
    right = actors_by_id.get(int(actor2["id"]), actor2)
    stats = payload.get("stats") or {}
    s1 = stats.get(str(actor1["id"]), {})
    s2 = stats.get(str(actor2["id"]), {})
    highest = payload.get("highest_grossing") or {}
    h1 = (highest.get(str(actor1["id"])) or {}).get("movie")
    h2 = (highest.get(str(actor2["id"])) or {}).get("movie")
    actors_catalog = payload.get("actors_catalog") or []

    name1 = str(left.get("name") or actor1.get("name") or "Actor").strip()
    name2 = str(right.get("name") or actor2.get("name") or "Actor").strip()
    actor1_url = f"/actor/{actor1['slug']}"
    actor2_url = f"/actor/{actor2['slug']}"
    canonical_url = f"https://boxofficex.in{comparison['canonical_url']}"
    # CTR metadata only. Keep the visible actor-comparison UI unchanged.
    title = f"{name1} vs {name2}: Box Office, Movies & Verdicts | BoxOfficeX"

    def ctr_money(value):
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(number):
            return None
        if abs(number - round(number)) < 0.05:
            return f"{int(round(number)):,}"
        return f"{number:,.1f}".rstrip("0").rstrip(".")

    def recent_theatrical_average(actor_id):
        # Filmographies are already newest-first. Exclude future/unreleased titles
        # and missing/non-positive worldwide values; never convert missing data to zero.
        today = date.today()
        usable = []
        for movie in (payload.get("movies") or {}).get(str(actor_id), []):
            release_raw = movie.get("release_date")
            gross = movie.get("worldwide_collection_crore")
            if not release_raw or gross is None:
                continue
            try:
                release_day = date.fromisoformat(str(release_raw)[:10])
                gross_value = float(gross)
            except (TypeError, ValueError):
                continue
            if release_day > today or gross_value <= 0 or not math.isfinite(gross_value):
                continue
            usable.append(gross_value)
            if len(usable) == 5:
                break

        if not usable:
            return None, 0
        return sum(usable) / len(usable), len(usable)

    total1 = ctr_money(s1.get("total_worldwide"))
    total2 = ctr_money(s2.get("total_worldwide"))
    recent1, recent_count1 = recent_theatrical_average(actor1["id"])
    recent2, recent_count2 = recent_theatrical_average(actor2["id"])
    recent1_text = ctr_money(recent1)
    recent2_text = ctr_money(recent2)

    description_parts = [f"{name1} vs {name2} Box Office:"]

    if total1 is not None and total2 is not None:
        description_parts.append(
            f"₹{total1} Cr vs ₹{total2} Cr worldwide."
        )

    if recent1_text is not None and recent2_text is not None:
        if recent_count1 == 5 and recent_count2 == 5:
            recent_label = "Last 5 films averaged"
        elif recent_count1 == recent_count2:
            recent_label = f"Last {recent_count1} films with data averaged"
        else:
            recent_label = (
                f"Recent theatrical averages ({recent_count1} vs {recent_count2} films)"
            )
        description_parts.append(
            f"{recent_label} ₹{recent1_text} Cr vs ₹{recent2_text} Cr worldwide."
        )

    description_parts.append("Compare biggest grossers & verdicts.")
    description = " ".join(description_parts)

    def _int_stat(stats_obj, key):
        try:
            return max(0, int(stats_obj.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    movie_count1 = _int_stat(s1, "movie_count")
    movie_count2 = _int_stat(s2, "movie_count")
    blockbusters1 = _int_stat(s1, "blockbusters")
    blockbusters2 = _int_stat(s2, "blockbusters")
    hits1 = _int_stat(s1, "hits")
    hits2 = _int_stat(s2, "hits")
    flops1 = _int_stat(s1, "flops")
    flops2 = _int_stat(s2, "flops")
    total1_display = f"₹{total1} Cr" if total1 is not None else "N/A"
    total2_display = f"₹{total2} Cr" if total2 is not None else "N/A"
    recent1_display = f"₹{recent1_text} Cr" if recent1_text is not None else "N/A"
    recent2_display = f"₹{recent2_text} Cr" if recent2_text is not None else "N/A"
    high1_title = str((h1 or {}).get("title") or "N/A")
    high2_title = str((h2 or {}).get("title") or "N/A")
    high1_gross = ctr_money((h1 or {}).get("worldwide_collection_crore"))
    high2_gross = ctr_money((h2 or {}).get("worldwide_collection_crore"))
    high1_text = f"{high1_title} (₹{high1_gross} Cr)" if high1_gross is not None else high1_title
    high2_text = f"{high2_title} (₹{high2_gross} Cr)" if high2_gross is not None else high2_title

    faq_items = [
        (
            f"How many movies have {name1} and {name2} acted in?",
            f"BoxOfficeX currently tracks {movie_count1} movies for {name1} and {movie_count2} movies for {name2} in this comparison."
        ),
        (
            f"What are {name1} and {name2}'s total worldwide box office collections?",
            f"The currently recorded worldwide totals are {total1_display} for {name1} and {total2_display} for {name2}."
        ),
        (
            f"What are the highest-grossing movies of {name1} and {name2}?",
            f"The highest-grossing movies currently recorded by BoxOfficeX are {high1_text} for {name1} and {high2_text} for {name2}."
        ),
        (
            f"How many blockbusters and hits do {name1} and {name2} have?",
            f"BoxOfficeX currently records {blockbusters1} blockbusters and {hits1} hits for {name1}, compared with {blockbusters2} blockbusters and {hits2} hits for {name2}."
        ),
    ]

    seo_intro = (
        f'<section class="bx-compare-seo" aria-label="{html_escape(name1, quote=True)} vs {html_escape(name2, quote=True)} career box office comparison">'
        f'<h2>{html_escape(name1)} vs {html_escape(name2)} Career Box Office Comparison</h2>'
        f'<p><strong>{html_escape(name1)} vs {html_escape(name2)} Box Office Comparison:</strong> '
        f'{html_escape(name1)} has <strong>{movie_count1} tracked movies</strong> with <strong>{html_escape(total1_display)}</strong> worldwide, while '
        f'{html_escape(name2)} has <strong>{movie_count2} tracked movies</strong> with <strong>{html_escape(total2_display)}</strong> worldwide. '
        f'Their recent theatrical averages are <strong>{html_escape(recent1_display)}</strong> and <strong>{html_escape(recent2_display)}</strong> respectively, based only on recent released movies with recorded worldwide collection data.</p>'
        f'<h3>{html_escape(name1)} vs {html_escape(name2)} Hits, Blockbusters &amp; Career Record</h3>'
        f'<p>{html_escape(name1)} currently has <strong>{blockbusters1} blockbusters</strong>, <strong>{hits1} hits</strong> and <strong>{flops1} flops</strong> in the BoxOfficeX database. '
        f'{html_escape(name2)} currently has <strong>{blockbusters2} blockbusters</strong>, <strong>{hits2} hits</strong> and <strong>{flops2} flops</strong>. Missing verdict data is excluded rather than treated as a flop.</p>'
        '</section>'
    )

    faq_html = (
        f'<section class="bx-compare-seo bx-compare-faq-section" aria-label="{html_escape(name1, quote=True)} vs {html_escape(name2, quote=True)} box office frequently asked questions">'
        f'<h2>{html_escape(name1)} vs {html_escape(name2)} Box Office FAQ</h2>'
        '<div class="bx-compare-faq">'
        + ''.join(
            f'<details><summary>{html_escape(q)}</summary><p>{html_escape(a)}</p></details>'
            for q, a in faq_items
        )
        + '</div></section>'
    )

    def actor_card(actor, name, url):
        image = _home_actor_placeholder(name)
        return (
            '<div class="hero-card">'
            f'<a href="{html_escape(url, quote=True)}" aria-label="{html_escape(name, quote=True)} profile">'
            f'<img src="{html_escape(image, quote=True)}" alt="{html_escape(name, quote=True)}" class="comparison-photo">'
            f'<h3>{html_escape(name)}</h3></a><p>Actor</p></div>'
        )

    def stat_row(v1, label, v2):
        return (
            '<div class="stat-row">'
            f'<div class="stat-value">{html_escape(str(v1))}</div>'
            f'<div class="stat-label">{html_escape(label)}</div>'
            f'<div class="stat-value">{html_escape(str(v2))}</div></div>'
        )

    def clickable_stat_row(v1, label, v2, verdict=None):
        def actor_movies_url(actor_slug):
            url = f"/actor/{quote(str(actor_slug), safe='')}/movies"
            if verdict:
                url += f"?verdict={quote(str(verdict), safe='')}"
            return url

        left_url = actor_movies_url(actor1["slug"])
        right_url = actor_movies_url(actor2["slug"])
        return (
            '<div class="stat-row">'
            f'<a class="stat-value clickable-stat" href="{html_escape(left_url, quote=True)}" '
            'style="color:inherit;text-decoration:none">'
            f'{html_escape(str(v1))}</a>'
            f'<div class="stat-label">{html_escape(label)}</div>'
            f'<a class="stat-value clickable-stat" href="{html_escape(right_url, quote=True)}" '
            'style="color:inherit;text-decoration:none">'
            f'{html_escape(str(v2))}</a></div>'
        )

    def related_comparisons_html():
        current_ids = {str(actor1.get("id", "")), str(actor2.get("id", ""))}
        current_names = {name1.lower(), name2.lower()}
        candidates = []
        for item in actors_catalog:
            item_name = str(item.get("name") or "").strip()
            if not item_name:
                continue
            if str(item.get("id", "")) in current_ids or item_name.lower() in current_names:
                continue
            candidates.append(item)

        languages = {
            str(v or "").strip().lower()
            for v in (left.get("language"), right.get("language"))
            if str(v or "").strip()
        }
        ranked = sorted(
            enumerate(candidates),
            key=lambda pair: (
                -int(bool(languages) and str(pair[1].get("language") or "").strip().lower() in languages),
                pair[0],
            ),
        )
        picked = [item for _, item in ranked[:6]]
        if not picked:
            return ""

        def related_slug(item):
            actor_id = item.get("id")
            try:
                actor_id = int(actor_id)
            except (TypeError, ValueError):
                actor_id = None
            # Use the canonical slug map whenever possible; fall back to the same
            # public slug normalization used by the client for catalogue entries.
            if actor_id is not None:
                try:
                    slug_map = _unique_actor_slug_map()
                    if actor_id in slug_map:
                        return slug_map[actor_id]
                except Exception:
                    pass
            raw = str(item.get("slug") or item.get("name") or "").strip().lower()
            raw = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode("ascii")
            return re.sub(r"^-+|-+$", "", re.sub(r"[^a-z0-9]+", "-", raw))

        # Resolve once for the two current actors; these are already canonical.
        current_slug_by_id = {int(actor1["id"]): actor1["slug"], int(actor2["id"]): actor2["slug"]}
        links = []
        for index, other in enumerate(picked):
            base = left if index % 2 == 0 else right
            base_id = int(base.get("id"))
            other_id = int(other.get("id"))
            other_slug = related_slug(other)
            base_slug = current_slug_by_id.get(base_id) or related_slug(base)
            ordered = sorted([(base_id, base_slug), (other_id, other_slug)], key=lambda x: x[0])
            if not ordered[0][1] or not ordered[1][1]:
                continue
            href = f"/compare/{quote(ordered[0][1], safe='')}-vs-{quote(ordered[1][1], safe='')}"
            base_name = str(base.get("name") or "Actor").strip()
            other_name = str(other.get("name") or "Actor").strip()
            base_img = _home_actor_placeholder(base_name)
            other_img = _home_actor_placeholder(other_name)
            links.append(
                f'<a class="bx-related-comparison-link" href="{html_escape(href, quote=True)}" '
                f'aria-label="{html_escape(base_name, quote=True)} vs {html_escape(other_name, quote=True)} actor comparison">'
                f'<span class="bx-related-person"><img src="{html_escape(base_img, quote=True)}" alt="{html_escape(base_name, quote=True)}" loading="lazy"><strong>{html_escape(base_name)}</strong></span>'
                f'<span class="bx-related-vs-badge">VS</span>'
                f'<span class="bx-related-person"><img src="{html_escape(other_img, quote=True)}" alt="{html_escape(other_name, quote=True)}" loading="lazy"><strong>{html_escape(other_name)}</strong></span>'
                f'<span class="bx-related-open">View Comparison →</span></a>'
            )
        if not links:
            return ""
        return (
            '<section class="bx-related-comparisons" aria-labelledby="bxRelatedComparisonsTitle">'
            '<div class="bx-related-comparisons-head"><h2 id="bxRelatedComparisonsTitle">🔥 More Related Actor Comparisons</h2>'
            f'<p>Keep exploring {html_escape(name1)} and {html_escape(name2)} against other actors.</p></div>'
            f'<div class="bx-related-comparisons-grid">{"".join(links)}</div></section>'
        )

    def highest_card(actor_name, movie):
        if not movie:
            return (
                '<div class="highest-card">'
                f'<h3>🏆 {html_escape(actor_name)}\'s Highest Grosser</h3>'
                '<p>No movie data available.</p></div>'
            )
        movie_title = str(movie.get("title") or "Movie")
        movie_url = _actor_comparison_ssr_movie_url(movie)
        gross = movie.get("worldwide_collection_crore")
        verdict = movie.get("verdict") or "N/A"
        poster = movie.get("poster")
        poster_src = (
            poster if _is_remote_image(poster)
            else (f"/posters/{quote(str(poster))}" if poster and poster != DEFAULT_MOVIE_POSTER else "")
        )
        image_html = (
            f'<img src="{html_escape(poster_src, quote=True)}" alt="{html_escape(movie_title, quote=True)}" loading="lazy">'
            if poster_src else ""
        )
        return (
            f'<a class="highest-card" href="{html_escape(movie_url, quote=True)}">'
            f'<h3>🏆 {html_escape(actor_name)}\'s Highest Grosser</h3>{image_html}'
            f'<h2>{html_escape(movie_title)}</h2>'
            f'<p>🌍 ₹{_actor_comparison_ssr_number(gross)} Cr</p>'
            f'<p>🎬 {html_escape(str(verdict))}</p><p>👆 Click to view movie</p></a>'
        )

    content = (
        '<div id="comparisonContent" data-ssr="1">'
        + seo_intro
        + '<div class="heroes">'
        + actor_card(left, name1, actor1_url)
        + '<div class="vs">VS</div>'
        + actor_card(right, name2, actor2_url)
        + '</div>'
        + '<div class="compare-click-hint"><span>👆</span> Tap Total Movies, Blockbusters, Hits, Average or Flops counts to view the movies</div>'
        + '<div class="stats">'
        + clickable_stat_row(s1.get("movie_count", 0), "🎬 Total Movies", s2.get("movie_count", 0))
        + stat_row(f"₹{_actor_comparison_ssr_number(s1.get('total_worldwide'))} Cr", "🌍 Total Worldwide", f"₹{_actor_comparison_ssr_number(s2.get('total_worldwide'))} Cr")
        + clickable_stat_row(s1.get("blockbusters", 0), "🔥 Blockbusters", s2.get("blockbusters", 0), "Blockbuster")
        + clickable_stat_row(s1.get("hits", 0), "⭐ Hits", s2.get("hits", 0), "Hit")
        + clickable_stat_row(s1.get("average_movies", 0), "➖ Average", s2.get("average_movies", 0), "Average")
        + clickable_stat_row(s1.get("flops", 0), "❌ Flops", s2.get("flops", 0), "Flop")
        + '</div>'
        + '<section id="bxSmartAdSlot1" class="bx-smart-ad-slot" aria-label="Advertisement slot 1"></section>'
        + f'<div class="highest-section"><h2 class="highest-section-title">🏆 {html_escape(name1)} vs {html_escape(name2)} Highest-Grossing Movies</h2><p class="bx-section-intro">Compare the highest-grossing movie currently recorded for {html_escape(name1)} and {html_escape(name2)}, including worldwide collection and verdict data.</p><div class="highest-grid">'
        + highest_card(name1, h1) + highest_card(name2, h2)
        + '</div></div>'
        + related_comparisons_html()
        + faq_html
        + '<div class="bx-ssr-comparison-note">'
        + f'<p><strong>{html_escape(name1)} vs {html_escape(name2)}</strong> comparison includes career movie counts, worldwide collections, verdict records and highest-grossing films. Interactive scoring, ROI, Fan Zone and live engagement load in the browser.</p>'
        + '</div></div>'
    )

    template = re.sub(
        r'<div id="comparisonContent"(?:\s+data-ssr="[01]")?\s*>\s*<div class="loading">.*?</div>\s*</div>',
        content,
        template,
        count=1,
        flags=re.S,
    )

    visible_h1 = f"{name1} vs {name2} Box Office Comparison"
    visible_subtitle = f"Compare movies, worldwide collections, recent box-office performance, blockbusters, hits, flops and highest-grossing films for {name1} and {name2}."
    template = re.sub(
        r'(<div class="comparison-header">\s*<h1>).*?(</h1>\s*<p>).*?(</p>)',
        lambda m: m.group(1) + html_escape(visible_h1) + m.group(2) + html_escape(visible_subtitle) + m.group(3),
        template, count=1, flags=re.S,
    )

    safe_title = html_escape(title, quote=True)
    safe_description = html_escape(description, quote=True)
    safe_canonical = html_escape(canonical_url, quote=True)
    template = re.sub(r'<title>.*?</title>', f'<title>{safe_title}</title>', template, count=1, flags=re.S)
    template = re.sub(r'<meta\s+name="description"\s+content="[^"]*"\s*/?>', f'<meta name="description" content="{safe_description}">', template, count=1, flags=re.S)
    template = re.sub(r'<link id="canonicalUrl" rel="canonical" href="[^"]*">', f'<link id="canonicalUrl" rel="canonical" href="{safe_canonical}">', template, count=1)
    template = re.sub(r'<meta id="ogTitle" property="og:title" content="[^"]*">', f'<meta id="ogTitle" property="og:title" content="{safe_title}">', template, count=1)
    template = re.sub(r'<meta id="ogDescription" property="og:description" content="[^"]*">', f'<meta id="ogDescription" property="og:description" content="{safe_description}">', template, count=1)
    template = re.sub(r'<meta id="ogUrl" property="og:url" content="[^"]*">', f'<meta id="ogUrl" property="og:url" content="{safe_canonical}">', template, count=1)
    template = re.sub(r'<meta id="twitterTitle" name="twitter:title" content="[^"]*">', f'<meta id="twitterTitle" name="twitter:title" content="{safe_title}">', template, count=1)
    template = re.sub(r'<meta id="twitterDescription" name="twitter:description" content="[^"]*">', f'<meta id="twitterDescription" name="twitter:description" content="{safe_description}">', template, count=1)

    structured = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebPage",
                "name": f"{name1} vs {name2} Box Office Comparison",
                "url": canonical_url,
                "description": description,
                "about": [
                    {"@type": "Person", "name": name1, "url": f"https://boxofficex.in{actor1_url}"},
                    {"@type": "Person", "name": name2, "url": f"https://boxofficex.in{actor2_url}"},
                ],
            },
            {
                "@type": "FAQPage",
                "mainEntity": [
                    {
                        "@type": "Question",
                        "name": question,
                        "acceptedAnswer": {"@type": "Answer", "text": answer},
                    }
                    for question, answer in faq_items
                ],
            },
        ],
    }
    json_ld = json.dumps(structured, ensure_ascii=False).replace("</", "<\\/")
    template = re.sub(
        r'<script\s+id="compareStructuredData"\s+type="application/ld\+json"\s*>.*?</script>',
        f'<script id="compareStructuredData" type="application/ld+json">{json_ld}</script>',
        template,
        count=1,
        flags=re.S,
    )
    return template


def _refresh_actor_comparison_cache(comparison_slug, comparison):
    try:
        rendered = _render_actor_comparison_html(comparison)
        with _actor_comparison_cache_lock:
            _actor_comparison_html_cache[comparison_slug] = {
                "html": rendered,
                "expires_at": time_module.monotonic() + ACTOR_COMPARISON_HTML_CACHE_TTL,
            }
    except Exception as exc:
        print("Actor Comparison SSR refresh failed:", comparison_slug, type(exc).__name__, exc, flush=True)
    finally:
        with _actor_comparison_cache_lock:
            _actor_comparison_refreshing.discard(comparison_slug)


def _start_actor_comparison_refresh(comparison_slug, comparison):
    with _actor_comparison_cache_lock:
        if comparison_slug in _actor_comparison_refreshing:
            return False
        _actor_comparison_refreshing.add(comparison_slug)
    threading.Thread(
        target=_refresh_actor_comparison_cache,
        args=(comparison_slug, comparison),
        daemon=True,
        name=f"actor-compare-ssr-{comparison_slug[:40]}",
    ).start()
    return True


def _get_actor_comparison_cached_html(comparison_slug, comparison):
    now = time_module.monotonic()
    with _actor_comparison_cache_lock:
        cached = _actor_comparison_html_cache.get(comparison_slug)
        if cached and cached.get("html"):
            if float(cached.get("expires_at") or 0) > now:
                return cached["html"], "HIT"
            stale_html = cached["html"]
        else:
            stale_html = None

    _start_actor_comparison_refresh(comparison_slug, comparison)
    if stale_html is not None:
        return stale_html, "STALE"
    return None, "WARMING"


@app.get("/compare/{comparison_slug}", include_in_schema=False)
def actor_comparison_slug_page(comparison_slug: str):
    comparison = resolve_actor_comparison_slug(comparison_slug)
    if not comparison:
        raise HTTPException(status_code=404, detail="Actor comparison not found")

    if not comparison.get("is_canonical", True):
        return RedirectResponse(url=comparison["canonical_url"], status_code=301)

    try:
        rendered, cache_state = _get_actor_comparison_cached_html(comparison_slug, comparison)
        if rendered is not None:
            return HTMLResponse(
                content=rendered,
                headers={
                    "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                    "X-BoxOfficeX-Actor-Comparison": "cached-ssr",
                    "X-BoxOfficeX-Cache": cache_state,
                },
            )

        # Cold cache must never block on the expensive comparison payload.
        # Serve the existing page immediately; its current JS remains the fallback.
        return FileResponse(
            BASE_DIR / "compare.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Actor-Comparison": "warming",
                "X-BoxOfficeX-Cache": "WARMING",
            },
        )
    except Exception as exc:
        print("Actor Comparison SSR fallback:", comparison_slug, type(exc).__name__, exc, flush=True)
        _start_actor_comparison_refresh(comparison_slug, comparison)
        return FileResponse(
            BASE_DIR / "compare.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Actor-Comparison": "ssr-fallback",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
            },
        )


@app.get("/seo/resolve/actor-comparison/{comparison_slug}", include_in_schema=False)
def seo_resolve_actor_comparison(comparison_slug: str):
    comparison = resolve_actor_comparison_slug(comparison_slug)
    if not comparison:
        raise HTTPException(status_code=404, detail="Actor comparison not found")
    return comparison


@app.get("/compare-select.html", response_class=HTMLResponse)
def actor_compare_select_page():
    try:
        rendered = _get_actor_compare_select_html()
        return HTMLResponse(
            content=rendered,
            headers={"Cache-Control": "public, max-age=300, stale-while-revalidate=3600"},
        )
    except Exception as exc:
        print("Actor Compare Select SSR failed:", type(exc).__name__, exc, flush=True)
        return FileResponse(os.path.join(BASE_DIR, "compare-select.html"))


@app.get("/compare.html", include_in_schema=False)
def compare_page(
    actor1: Optional[int] = None,
    actor2: Optional[int] = None
):
    if actor1 is None or actor2 is None:
        return RedirectResponse(url="/compare-select.html", status_code=301)

    if actor1 == actor2:
        raise HTTPException(status_code=400, detail="Choose two different actors")

    canonical_url = public_actor_comparison_url(actor1, actor2)
    if canonical_url == "/compare-select.html":
        raise HTTPException(status_code=404, detail="Actor comparison not found")

    return RedirectResponse(url=canonical_url, status_code=301)




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


@app.get(
    "/admin-advertisements.html",
    dependencies=[Depends(require_owner)]
)
def admin_advertisements_page():
    return FileResponse(
        BASE_DIR / "admin-advertisements.html"
    )

# ============================================================
# NEW MOVIES - NON-BLOCKING CACHED SSR
# ============================================================

NEW_MOVIES_HTML_CACHE_TTL = 300
_new_movies_html_cache = {"html": None, "expires_at": 0.0}
_new_movies_html_cache_lock = threading.Lock()
_new_movies_html_refreshing = False


def _new_movies_ssr_money(value):
    if value is None or value == "":
        return '<span class="collection-na">N/A</span>'
    try:
        formatted = f"{float(value):,.2f}".rstrip("0").rstrip(".")
        return f"₹{formatted} Cr"
    except (TypeError, ValueError):
        return '<span class="collection-na">N/A</span>'


def _new_movies_ssr_date(value):
    if not value:
        return "N/A"
    try:
        parsed = datetime.strptime(str(value)[:10], "%Y-%m-%d")
        return f"{parsed.day} {parsed.strftime('%b %Y')}"
    except Exception:
        return html_escape(str(value))


def _new_movies_ssr_card(movie, status, slug_map):
    movie_id = int(movie.get("id"))
    title = html_escape(str(movie.get("title") or "Untitled Movie"))
    slug = str(movie.get("slug") or slug_map.get(movie_id) or "").strip()
    movie_url = html_escape(f"/movie/{slug}" if slug else "/new-movies.html", quote=True)
    poster = html_escape(_home_movie_placeholder(movie), quote=True)
    release_date = _new_movies_ssr_date(movie.get("release_date"))
    language = html_escape(str(movie.get("language") or "N/A"))
    genre = html_escape(str(movie.get("genre") or "N/A"))
    director = html_escape(str(movie.get("director") or "N/A"))
    worldwide = (
        '<span class="collection-na">Not released</span>'
        if status == "upcoming"
        else _new_movies_ssr_money(movie.get("worldwide_collection_crore"))
    )
    status_label = {
        "running": "● NOW RUNNING",
        "upcoming": "COMING SOON",
        "final": "FINAL",
    }.get(status, "FINAL")
    verdict_html = ""
    if status != "upcoming":
        verdict = html_escape(str(movie.get("verdict") or "Not Rated"))
        verdict_html = f'<div class="verdict">🎯 {verdict}</div>'

    return (
        f'<a class="movie-card" href="{movie_url}" aria-label="View {title}">'
        f'<img class="poster" src="{poster}" alt="{title}" loading="lazy">'
        '<div class="movie-content">'
        f'<span class="status-badge status-{html_escape(status)}">{status_label}</span>'
        f'<div class="movie-title">{title}</div>'
        f'<div class="movie-info">📅 Release: {release_date}</div>'
        f'<div class="movie-info">🎭 Language: {language}</div>'
        f'<div class="movie-info">🎬 Genre: {genre}</div>'
        f'<div class="movie-info">🌍 Worldwide: {worldwide}</div>'
        f'<div class="movie-info">🎥 Director: {director}</div>'
        f'{verdict_html}</div></a>'
    )


def _new_movies_ssr_grid(movies, status, slug_map):
    if movies:
        return "".join(_new_movies_ssr_card(movie, status, slug_map) for movie in movies)
    messages = {
        "running": "No movies are currently marked as running.",
        "upcoming": "No upcoming movies are currently listed.",
        "final": "No recently released movies found.",
    }
    return '<div class="empty-section">' + html_escape(messages[status]) + '</div>'


def _render_new_movies_html():
    template = _inject_boxofficex_global_icons((BASE_DIR / "new-movies.html").read_text(encoding="utf-8"))
    payload = get_new_movie_system()
    running = list(payload.get("running") or [])
    upcoming = list(payload.get("upcoming") or [])
    recent = list(payload.get("recent") or [])
    slug_map = _unique_movie_slug_map()

    grids = {
        "runningGrid": (running, "running", "Loading running movies..."),
        "upcomingGrid": (upcoming, "upcoming", "Loading upcoming movies..."),
        "recentGrid": (recent, "final", "Loading recent movies..."),
    }
    for grid_id, (movies, status, loading_text) in grids.items():
        rendered = _new_movies_ssr_grid(movies, status, slug_map)

        # Attribute-tolerant replacement: works with the raw shell and also
        # with a template that already contains data-ssr or other attributes.
        pattern = (
            rf'<div(?P<attrs>[^>]*\bid="{re.escape(grid_id)}"[^>]*)>'
            rf'.*?</div>\s*(?=</section>)'
        )

        def replace_grid(match):
            attrs = match.group("attrs")
            attrs = re.sub(r'\sdata-ssr=(["\']).*?\1', '', attrs, flags=re.I)
            return (
                f'<div{attrs} data-ssr="1">'
                f'{rendered}</div>'
            )

        template, replaced = re.subn(
            pattern,
            replace_grid,
            template,
            count=1,
            flags=re.S | re.I,
        )
        if replaced != 1:
            raise RuntimeError(f"New Movies SSR grid injection failed: {grid_id}")

    counts = {
        "runningCount": len(running),
        "upcomingCount": len(upcoming),
        "recentCount": len(recent),
    }
    for count_id, count in counts.items():
        label = f'{count} {"movie" if count == 1 else "movies"}'
        template = re.sub(
            rf'(<span class="section-count" id="{count_id}">).*?(</span>)',
            rf'\g<1>{label}\g<2>',
            template,
            count=1,
            flags=re.S,
        )

    initial_json = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), default=str
    ).replace("</", "<\\/")
    initial_script = (
        '<script id="boxofficexNewMoviesSSRData">'
        f'window.__BOXOFFICEX_NEW_MOVIES_SSR_DATA__={initial_json};'
        '</script>'
    )
    template = template.replace("</head>", initial_script + "\n</head>", 1)

    item_movies = running + upcoming + recent
    seen = set()
    items = []
    for movie in item_movies:
        movie_id = int(movie.get("id"))
        if movie_id in seen:
            continue
        seen.add(movie_id)
        slug = slug_map.get(movie_id)
        if not slug:
            continue
        items.append({
            "@type": "ListItem",
            "position": len(items) + 1,
            "url": f"https://boxofficex.in/movie/{slug}",
            "name": str(movie.get("title") or "Movie"),
        })

    page_url = "https://boxofficex.in/new-movies.html"
    description = (
        "Explore new and recently released movies with box office collections, "
        "verdicts, language, genre, director and complete movie details on BoxOfficeX."
    )

    structured = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "CollectionPage",
                "@id": page_url + "#webpage",
                "name": "New Movies - Latest Releases & Box Office Collections",
                "url": page_url,
                "description": description,
                "mainEntity": {"@id": page_url + "#movies"},
            },
            {
                "@type": "ItemList",
                "@id": page_url + "#movies",
                "name": "New and Recently Released Movies",
                "itemListElement": items,
            },
            {
                "@type": "BreadcrumbList",
                "@id": page_url + "#breadcrumb",
                "itemListElement": [
                    {
                        "@type": "ListItem",
                        "position": 1,
                        "name": "Home",
                        "item": "https://boxofficex.in/",
                    },
                    {
                        "@type": "ListItem",
                        "position": 2,
                        "name": "New Movies",
                        "item": page_url,
                    },
                ],
            },
        ],
    }
    structured_json = json.dumps(
        structured, ensure_ascii=False, separators=(",", ":")
    ).replace("</", "<\\/")
    template = re.sub(
        r'<script\s+id="newMoviesStructuredData"\s+type="application/ld\+json"\s*>.*?</script>',
        f'<script id="newMoviesStructuredData" type="application/ld+json">{structured_json}</script>',
        template,
        count=1,
        flags=re.S | re.I,
    )

    if template.count('data-ssr="1"') < 3:
        raise RuntimeError("New Movies SSR body injection failed")
    return template


def _refresh_new_movies_cache():
    global _new_movies_html_refreshing
    try:
        rendered = _render_new_movies_html()
        now = time_module.monotonic()
        with _new_movies_html_cache_lock:
            _new_movies_html_cache["html"] = rendered
            _new_movies_html_cache["expires_at"] = now + NEW_MOVIES_HTML_CACHE_TTL
    except Exception as exc:
        print("New Movies SSR cache refresh failed:", exc, flush=True)
    finally:
        with _new_movies_html_cache_lock:
            _new_movies_html_refreshing = False


def _start_new_movies_refresh():
    global _new_movies_html_refreshing
    with _new_movies_html_cache_lock:
        if _new_movies_html_refreshing:
            return
        _new_movies_html_refreshing = True
    threading.Thread(
        target=_refresh_new_movies_cache,
        name="boxofficex-new-movies-ssr",
        daemon=True,
    ).start()


@app.on_event("startup")
def warm_new_movies_ssr_cache():
    _start_new_movies_refresh()


@app.get("/new-movies.html")
def new_movies_page():
    now = time_module.monotonic()
    with _new_movies_html_cache_lock:
        cached_html = _new_movies_html_cache.get("html")
        expires_at = float(_new_movies_html_cache.get("expires_at") or 0)

    if cached_html:
        state = "HIT" if expires_at > now else "STALE"
        if state == "STALE":
            _start_new_movies_refresh()
        return HTMLResponse(
            cached_html,
            headers={
                "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                "X-BoxOfficeX-New-Movies": "cached-ssr",
                "X-BoxOfficeX-Cache": state,
            },
        )

    # Cold cache must still return crawlable SSR on the first request.
    # Build once synchronously, cache it, then use background refreshes later.
    try:
        rendered = _render_new_movies_html()
        now = time_module.monotonic()
        with _new_movies_html_cache_lock:
            _new_movies_html_cache["html"] = rendered
            _new_movies_html_cache["expires_at"] = now + NEW_MOVIES_HTML_CACHE_TTL

        return HTMLResponse(
            rendered,
            headers={
                "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                "X-BoxOfficeX-New-Movies": "cold-ssr",
                "X-BoxOfficeX-Cache": "MISS",
            },
        )
    except Exception as exc:
        print("New Movies cold SSR fallback:", type(exc).__name__, exc, flush=True)
        _start_new_movies_refresh()
        return FileResponse(
            BASE_DIR / "new-movies.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-New-Movies": "ssr-fallback",
                "X-BoxOfficeX-Cache": "FALLBACK",
            },
        )


# ============================================================
# ACTOR RANKINGS - CACHED SSR + LANGUAGE SEO URLS
# ============================================================

ACTOR_RANKINGS_HTML_CACHE_TTL = 3600

_ACTOR_RANKING_TARGETS = {
    "all": {
        "label": "Indian",
        "language": "All",
        "path": "/rankings.html",
    },
    "tamil": {
        "label": "Tamil",
        "language": "Tamil",
        "path": "/actor-rankings/tamil",
    },
    "telugu": {
        "label": "Telugu",
        "language": "Telugu",
        "path": "/actor-rankings/telugu",
    },
    "hindi": {
        "label": "Hindi",
        "language": "Hindi",
        "path": "/actor-rankings/hindi",
    },
    "kannada": {
        "label": "Kannada",
        "language": "Kannada",
        "path": "/actor-rankings/kannada",
    },
    "malayalam": {
        "label": "Malayalam",
        "language": "Malayalam",
        "path": "/actor-rankings/malayalam",
    },
}

_actor_rankings_html_cache = {}
_actor_rankings_html_cache_lock = threading.Lock()
_actor_rankings_html_refreshing = set()


def _actor_rankings_number(value):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0.0
    return f"{number:,.2f}".rstrip("0").rstrip(".")


def _actor_rankings_meta(target_key, rankings):
    target = _ACTOR_RANKING_TARGETS[target_key]
    label = target["label"]
    canonical = "https://boxofficex.in" + target["path"]
    shown_count = min(len(rankings), 50)
    count_prefix = f"Top {shown_count}" if shown_count else "Top"

    if target_key == "all":
        page_title = f"{count_prefix} Highest Grossing Indian Actors & Actresses | BoxOfficeX"
        fallback = (
            "Discover the highest grossing Indian actors and actresses by tracked worldwide box office collection, "
            "including Top 10 stars, total gross, average collection and blockbuster movies."
        )
    else:
        page_title = f"{count_prefix} Highest Grossing {label} Actors & Actresses | BoxOfficeX"
        fallback = (
            f"Discover the highest grossing {label} actors and actresses by tracked worldwide box office collection, "
            f"including the Top 10 {label} stars, total gross, average collection and blockbuster movies."
        )

    leaders = []
    for actor in rankings[:2]:
        name = str(actor.get("name") or "").strip()
        total = actor.get("total_worldwide")
        if name and total is not None:
            leaders.append(f"{name} ₹{_actor_rankings_number(total)} Cr")

    if len(leaders) >= 2:
        scope = "Indian cinema" if target_key == "all" else f"{label} cinema"
        description = (
            f"{leaders[0]} and {leaders[1]} lead the tracked {scope} list. "
            f"See the {count_prefix.lower()} highest grossing actors and actresses, Top 10 stars, worldwide totals and blockbusters."
        )
    else:
        description = fallback

    return {"title": page_title, "description": description, "canonical": canonical}


def _render_actor_rankings_html(target_key="all"):
    target = _ACTOR_RANKING_TARGETS[target_key]
    template = _inject_boxofficex_global_icons((BASE_DIR / "rankings.html").read_text(encoding="utf-8"))

    # The site shell uses a global `header` selector for the fixed mobile navbar
    # (including a fixed height). The rankings hero used a semantic <header> tag,
    # so those global mobile rules also fixed the hero and caused its H1/intro,
    # language buttons and ranking heading to overlap. Render the hero as a
    # neutral <section> instead; its class/id and all SEO content stay unchanged.
    template = re.sub(
        r'<header(?P<attrs>\s+class=["\']rankings-hero["\'][^>]*)>(?P<body>.*?)</header>',
        lambda m: '<section' + m.group('attrs') + '>' + m.group('body') + '</section>',
        template,
        count=1,
        flags=re.I | re.S,
    )

    data = actor_rankings(target["language"])
    rankings = list(data.get("rankings") or [])
    cards = []
    total_rows = len(rankings)
    slot1_after = max(0, math.ceil(total_rows / 3) - 1)
    slot2_after = max(slot1_after + 1, math.ceil((total_rows * 2) / 3) - 1)

    for index, actor in enumerate(rankings):
        name = str(actor.get("name") or "Actor")
        url = str(actor.get("url") or "/actors.html")
        image = _home_actor_placeholder(name)
        rank = actor.get("rank") or index + 1
        movie_count = actor.get("movie_count") or 0
        total_worldwide = actor.get("total_worldwide") or 0
        average_worldwide = actor.get("average_worldwide") or 0
        blockbusters = actor.get("blockbusters") or 0
        total_text = _actor_rankings_number(total_worldwide)
        average_text = _actor_rankings_number(average_worldwide)

        cards.append(
            f'<a class="rank" href="{html_escape(url, quote=True)}" '
            f'aria-label="{html_escape(name, quote=True)} profile">'
            f'<div class="rank-number">#{html_escape(str(rank))}</div>'
            f'<img src="{html_escape(image, quote=True)}" alt="{html_escape(name, quote=True)}">'
            f'<div><div class="name">{html_escape(name)}</div>'
            f'<div class="stats">{html_escape(str(movie_count))} movies | '
            f'₹{html_escape(total_text)} Cr | '
            f'₹{html_escape(average_text)} Cr Avg | '
            f'{html_escape(str(blockbusters))} Blockbusters</div></div></a>'
        )

        if index == slot1_after and total_rows > 1:
            cards.append(
                '<section id="bxSmartAdSlot1" class="bx-smart-ad-slot" '
                'aria-label="Advertisement slot 1"></section>'
            )
        if index == slot2_after and total_rows > 2:
            cards.append(
                '<section id="bxSmartAdSlot2" class="bx-smart-ad-slot" '
                'aria-label="Advertisement slot 2"></section>'
            )

    empty_label = target["label"] if target_key != "all" else "Indian"
    ranking_html = (
        '<div id="rankings" data-ssr="1">'
        + ("".join(cards) if cards else f"No actors found for {html_escape(empty_label)}")
        + "</div>"
    )
    template = re.sub(
        r'<div id="rankings"(?:\s+data-ssr="[01]")?\s*>.*?</div>',
        ranking_html,
        template,
        count=1,
        flags=re.S,
    )

    meta = _actor_rankings_meta(target_key, rankings)
    page_title = meta["title"]
    description = meta["description"]
    canonical = meta["canonical"]

    label = target["label"]
    shown_count = min(len(rankings), 50)
    count_prefix = f"Top {shown_count}" if shown_count else "Top"

    if target_key == "all":
        h1_text = f"{count_prefix} Highest Grossing Indian Actors & Actresses"
        list_heading = "Indian Cinema’s Highest Grossing Stars"
        intro_text = (
            f"Explore {count_prefix.lower()} of the highest grossing Indian actors and actresses using worldwide box office "
            "collections from movies tracked by BoxOfficeX across Tamil, Telugu, Hindi, Kannada and Malayalam cinema. "
            "Compare total worldwide gross, movie count, average collection and blockbuster movies, then use the language "
            "filters to see how stars perform within individual Indian film languages."
        )
        list_copy = (
            "The complete list is ordered by combined tracked worldwide gross across the supported Indian languages. "
            "The Top 10 summary below highlights the first ten positions from the same ranking."
        )
        top10_heading = "Top 10 Indian Actors & Actresses by Worldwide Box Office Collection"
        top10_copy = "A quick view of the first 10 positions from the complete All India ranking, using the same tracked worldwide gross data."
        methodology_heading = "How These Indian Star Rankings Are Calculated"
        language_text = (
            "The All India page combines qualifying tracked movies across supported languages. Language pages recalculate "
            "each star using only movies recorded in the selected language."
        )
        faq_heading = "Indian Actors & Actresses Box Office FAQ"
    else:
        h1_text = f"{count_prefix} Highest Grossing {label} Actors & Actresses"
        list_heading = f"{label} Cinema’s Highest Grossing Stars"
        intro_text = (
            f"Explore {count_prefix.lower()} of the highest grossing {label} actors and actresses using worldwide box office "
            f"collections from {label}-language movies tracked by BoxOfficeX. Compare total worldwide gross, movie count, "
            f"average collection and blockbuster movies, and see the Top 10 {label} stars before browsing the complete list. "
            f"Movies in other languages do not contribute to the figures on this {label} page."
        )
        list_copy = (
            f"The complete list uses only tracked {label}-language movies and is ordered by combined worldwide gross. "
            "The Top 10 summary below uses the first ten positions from this same ranking."
        )
        top10_heading = f"Top 10 {label} Actors & Actresses by Worldwide Box Office Collection"
        top10_copy = f"A quick view of the first 10 positions from the complete {label} ranking, calculated from tracked {label}-language movies."
        methodology_heading = f"How These {label} Star Rankings Are Calculated"
        language_text = (
            f"Only movies whose language is recorded as {label} contribute to this page. Movies by the same actor or actress "
            "in other languages are excluded from these totals."
        )
        faq_heading = f"{label} Actors & Actresses Box Office FAQ"

    leader_text = ""
    if rankings:
        leader = rankings[0]
        leader_name = str(leader.get("name") or "").strip()
        leader_total = _actor_rankings_number(leader.get("total_worldwide") or 0)
        if leader_name:
            leader_text = f" The current tracked leader is {leader_name} with ₹{leader_total} Cr in worldwide gross."
    intro_text += leader_text

    top10 = rankings[:10]
    top10_names = [str(a.get("name") or "").strip() for a in top10 if str(a.get("name") or "").strip()]
    if target_key == "all":
        scope_word = "Indian"
    else:
        scope_word = label
    leader_name = top10_names[0] if top10_names else "the current No. 1 star"
    faq_items = [
        (f"Who is the highest grossing {scope_word} actor or actress?", f"Based on the worldwide collections currently tracked by BoxOfficeX, {leader_name} is ranked No. 1 on this page. Rankings can change when movie data is updated."),
        (f"Who are the Top 10 {scope_word} actors and actresses by worldwide collection?", ("The current Top 10 are " + ", ".join(top10_names) + ".") if top10_names else "The Top 10 is generated from the first ten positions in the current BoxOfficeX ranking."),
        (f"Are actresses included in the {scope_word} box office ranking?", "Yes. The ranking can include both actors and actresses when they have qualifying tracked movies and worldwide collection data."),
        (f"Which {scope_word} stars have the most blockbuster movies?", "Each ranking card shows the number of tracked movies marked Blockbuster. The main ranking order is still based on combined worldwide gross, not blockbuster count."),
        ("How are multilingual actors ranked?", "A multilingual performer can appear on multiple language pages. Each language page calculates only qualifying movies recorded in that language, while the All India page combines supported languages."),
    ]

    def _replace_rankings_text(element_id, value):
        nonlocal template
        pattern = rf'(<(?P<tag>h1|h2|h3|p)\b[^>]*\bid=["\']{re.escape(element_id)}["\'][^>]*>).*?(</(?P=tag)>)'
        template = re.sub(
            pattern,
            lambda match: match.group(1) + html_escape(value) + match.group(3),
            template,
            count=1,
            flags=re.I | re.S,
        )

    _replace_rankings_text("actorRankingsH1", h1_text)
    _replace_rankings_text("actorRankingsIntro", intro_text)
    _replace_rankings_text("actorRankingsListHeading", list_heading)
    _replace_rankings_text("actorRankingsListCopy", list_copy)
    _replace_rankings_text("actorRankingsTop10Heading", top10_heading)
    _replace_rankings_text("actorRankingsTop10Copy", top10_copy)
    _replace_rankings_text("actorRankingsMetricHeading", "Total Worldwide Gross")
    _replace_rankings_text("actorRankingsLanguageHeading", "Movies Included in the Ranking")
    _replace_rankings_text("actorRankingsMultilingualHeading", "Actors Working Across Multiple Languages")
    _replace_rankings_text("actorRankingsMethodologyHeading", methodology_heading)
    _replace_rankings_text("actorRankingsMetricText", "Actors are ordered by combined tracked worldwide gross. Movie count, average worldwide gross and blockbuster count are supporting statistics, not separate ranking scores.")
    _replace_rankings_text("actorRankingsLanguageText", language_text)
    _replace_rankings_text("actorRankingsMultilingualText", "Actors are not locked to one industry. A multilingual actor can qualify for multiple language pages, and each page calculates that actor only from the movies that match the selected language.")
    _replace_rankings_text("actorRankingsNote", "BoxOfficeX rankings use the movie, collection, verdict and actor-movie relationship data currently stored in the site database. Figures may change when tracked data is added or updated.")
    _replace_rankings_text("actorRankingsFaqHeading", faq_heading)

    top10_html = '<ol class="rankings-top10-list" id="actorRankingsTop10List">' + ''.join(
        '<li><span class="top10-pos">#' + html_escape(str(actor.get("rank") or index + 1)) + '</span>'
        '<a href="' + html_escape(str(actor.get("url") or "/actors.html"), quote=True) + '">' + html_escape(str(actor.get("name") or "Actor")) + '</a>'
        '<span class="top10-gross">₹' + html_escape(_actor_rankings_number(actor.get("total_worldwide") or 0)) + ' Cr</span></li>'
        for index, actor in enumerate(top10)
    ) + '</ol>'
    template = re.sub(
        r'<ol class="rankings-top10-list" id="actorRankingsTop10List">.*?</ol>',
        top10_html, template, count=1, flags=re.I | re.S,
    )
    template = template.replace('id="actorRankingsTop10" data-ssr="0"', 'id="actorRankingsTop10" data-ssr="1"', 1)

    faq_html = '<div class="rankings-faq-items">' + ''.join(
        '<details><summary>' + html_escape(question) + '</summary><p>' + html_escape(answer) + '</p></details>'
        for question, answer in faq_items
    ) + '</div>'
    template = re.sub(
        r'<div class="rankings-faq-items">.*?</div>',
        faq_html,
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = template.replace('id="actorRankingsHero" data-ssr="0"', 'id="actorRankingsHero" data-ssr="1"', 1)
    template = template.replace('id="actorRankingsMethodology" data-ssr="0"', 'id="actorRankingsMethodology" data-ssr="1"', 1)
    template = template.replace('id="actorRankingsFaq" data-ssr="0"', 'id="actorRankingsFaq" data-ssr="1"', 1)
    template = re.sub(
        rf'(class="ranking-filter)("[^>]*data-ranking-key="{re.escape(target_key)}")',
        r'\1 active\2',
        template,
        count=1,
    )

    escaped_title = html_escape(page_title)
    escaped_description = html_escape(description, quote=True)

    template = re.sub(
        r"<title\b[^>]*>.*?</title>",
        f"<title>{escaped_title}</title>",
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bname=["\']description["\'])[^>]*>',
        f'<meta id="metaDescription" name="description" content="{escaped_description}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<link\b(?=[^>]*\brel=["\']canonical["\'])[^>]*>',
        f'<link id="canonicalUrl" rel="canonical" href="{canonical}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bproperty=["\']og:title["\'])[^>]*>',
        f'<meta property="og:title" content="{html_escape(page_title, quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bproperty=["\']og:description["\'])[^>]*>',
        f'<meta property="og:description" content="{escaped_description}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bproperty=["\']og:url["\'])[^>]*>',
        f'<meta id="ogUrl" property="og:url" content="{canonical}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bname=["\']twitter:title["\'])[^>]*>',
        f'<meta name="twitter:title" content="{html_escape(page_title, quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bname=["\']twitter:description["\'])[^>]*>',
        f'<meta name="twitter:description" content="{escaped_description}">',
        template,
        count=1,
        flags=re.I | re.S,
    )

    item_list = []
    for actor in rankings:
        if actor.get("url"):
            item_list.append({
                "@type": "ListItem",
                "position": int(actor.get("rank") or len(item_list) + 1),
                "name": str(actor.get("name") or "Actor"),
                "url": "https://boxofficex.in" + str(actor["url"]),
            })

    structured = {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "CollectionPage",
                "name": h1_text,
                "url": canonical,
                "description": description,
                "mainEntity": {
                    "@type": "ItemList",
                    "name": list_heading,
                    "itemListOrder": "https://schema.org/ItemListOrderDescending",
                    "numberOfItems": len(item_list),
                    "itemListElement": item_list,
                },
            },
            {
                "@type": "FAQPage",
                "mainEntity": [
                    {
                        "@type": "Question",
                        "name": question,
                        "acceptedAnswer": {
                            "@type": "Answer",
                            "text": answer,
                        },
                    }
                    for question, answer in faq_items
                ],
            },
            {
                "@type": "BreadcrumbList",
                "itemListElement": [
                    {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://boxofficex.in/"},
                    {"@type": "ListItem", "position": 2, "name": h1_text, "item": canonical},
                ],
            },
        ],
    }
    structured_json = json.dumps(
        structured, ensure_ascii=False, separators=(",", ":")
    ).replace("</", "<\\/")

    template = re.sub(
        r'<script\s+id="actorRankingsStructuredData"\s+type="application/ld\+json"\s*>.*?</script>',
        f'<script id="actorRankingsStructuredData" type="application/ld+json">{structured_json}</script>',
        template,
        count=1,
        flags=re.S | re.I,
    )

    page_config = {
        "targetKey": target_key,
        "language": target["language"],
        "label": target["label"],
        "canonical": canonical,
        "title": page_title,
        "description": description,
        "h1": h1_text,
    }
    config_script = (
        "<script>window.__BOXOFFICEX_ACTOR_RANKINGS_PAGE__="
        + json.dumps(page_config, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
        + ";</script>"
    )
    template = template.replace("</head>", config_script + "\n</head>", 1)

    return template


def _refresh_actor_rankings_cache(target_key):
    try:
        rendered = _render_actor_rankings_html(target_key)
        with _actor_rankings_html_cache_lock:
            _actor_rankings_html_cache[target_key] = {
                "html": rendered,
                "expires_at": time_module.monotonic() + ACTOR_RANKINGS_HTML_CACHE_TTL,
            }
    except Exception as exc:
        print(
            f"Actor Rankings SSR refresh failed ({target_key}):",
            type(exc).__name__,
            exc,
            flush=True,
        )
    finally:
        with _actor_rankings_html_cache_lock:
            _actor_rankings_html_refreshing.discard(target_key)


def _start_actor_rankings_refresh(target_key):
    with _actor_rankings_html_cache_lock:
        if target_key in _actor_rankings_html_refreshing:
            return False
        _actor_rankings_html_refreshing.add(target_key)

    threading.Thread(
        target=_refresh_actor_rankings_cache,
        args=(target_key,),
        name=f"boxofficex-actor-rankings-{target_key}",
        daemon=True,
    ).start()
    return True


def _get_actor_rankings_cached_html(target_key):
    now = time_module.monotonic()

    with _actor_rankings_html_cache_lock:
        entry = _actor_rankings_html_cache.get(target_key) or {}
        cached_html = entry.get("html")
        expires_at = float(entry.get("expires_at") or 0.0)

    if cached_html and expires_at > now:
        return cached_html, "HIT"

    if cached_html:
        _start_actor_rankings_refresh(target_key)
        return cached_html, "STALE"

    # First uncached request renders synchronously so crawlers never receive
    # a JS-only/placeholder ranking page. Subsequent requests use the cache.
    rendered = _render_actor_rankings_html(target_key)
    with _actor_rankings_html_cache_lock:
        _actor_rankings_html_cache[target_key] = {
            "html": rendered,
            "expires_at": time_module.monotonic() + ACTOR_RANKINGS_HTML_CACHE_TTL,
        }
    return rendered, "MISS"


def _actor_rankings_warming_html(target_key):
    target = _ACTOR_RANKING_TARGETS[target_key]
    template = _inject_boxofficex_global_icons((BASE_DIR / "rankings.html").read_text(encoding="utf-8"))

    # Keep the fallback/warming page safe from the global mobile `header` rules too.
    template = re.sub(
        r'<header(?P<attrs>\s+class=["\']rankings-hero["\'][^>]*)>(?P<body>.*?)</header>',
        lambda m: '<section' + m.group('attrs') + '>' + m.group('body') + '</section>',
        template,
        count=1,
        flags=re.I | re.S,
    )

    meta = _actor_rankings_meta(target_key, [])

    template = re.sub(
        r"<title\b[^>]*>.*?</title>",
        f"<title>{html_escape(meta['title'])}</title>",
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bname=["\']description["\'])[^>]*>',
        f'<meta id="metaDescription" name="description" content="{html_escape(meta["description"], quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<link\b(?=[^>]*\brel=["\']canonical["\'])[^>]*>',
        f'<link id="canonicalUrl" rel="canonical" href="{meta["canonical"]}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bproperty=["\']og:title["\'])[^>]*>',
        f'<meta property="og:title" content="{html_escape(meta["title"], quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bproperty=["\']og:description["\'])[^>]*>',
        f'<meta property="og:description" content="{html_escape(meta["description"], quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bproperty=["\']og:url["\'])[^>]*>',
        f'<meta id="ogUrl" property="og:url" content="{meta["canonical"]}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bname=["\']twitter:title["\'])[^>]*>',
        f'<meta name="twitter:title" content="{html_escape(meta["title"], quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )
    template = re.sub(
        r'<meta\b(?=[^>]*\bname=["\']twitter:description["\'])[^>]*>',
        f'<meta name="twitter:description" content="{html_escape(meta["description"], quote=True)}">',
        template,
        count=1,
        flags=re.I | re.S,
    )

    page_config = {
        "targetKey": target_key,
        "language": target["language"],
        "label": target["label"],
        "canonical": meta["canonical"],
        "title": meta["title"],
        "description": meta["description"],
    }
    config_script = (
        "<script>window.__BOXOFFICEX_ACTOR_RANKINGS_PAGE__="
        + json.dumps(page_config, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
        + ";</script>"
    )
    template = template.replace("</head>", config_script + "\n</head>", 1)
    return template


def _actor_rankings_response(target_key):
    try:
        html, cache_state = _get_actor_rankings_cached_html(target_key)

        if html is None:
            html = _actor_rankings_warming_html(target_key)
            return HTMLResponse(
                content=html,
                headers={
                    "Cache-Control": "public, max-age=300, stale-while-revalidate=3600",
                    "X-BoxOfficeX-Actor-Rankings": "warming",
                    "X-BoxOfficeX-Cache": cache_state,
                    "X-BoxOfficeX-Rankings-CTR": "v3-language-seo",
                },
            )

        return HTMLResponse(
            content=html,
            headers={
                "Cache-Control": "public, max-age=300, stale-while-revalidate=3600",
                "X-BoxOfficeX-Actor-Rankings": "cached-ssr",
                "X-BoxOfficeX-Cache": cache_state,
                "X-BoxOfficeX-Rankings-CTR": "v3-language-seo",
            },
        )
    except Exception as exc:
        print(
            f"Actor Rankings SSR fallback ({target_key}):",
            type(exc).__name__,
            exc,
            flush=True,
        )
        _start_actor_rankings_refresh(target_key)
        return HTMLResponse(
            content=_actor_rankings_warming_html(target_key),
            headers={
                "Cache-Control": "public, max-age=300, stale-while-revalidate=3600",
                "X-BoxOfficeX-Actor-Rankings": "ssr-fallback",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
                "X-BoxOfficeX-Rankings-CTR": "v3-language-seo",
            },
        )


@app.on_event("startup")
def warm_actor_rankings_ssr_cache():
    # Keep startup non-blocking. Warm all crawlable actor ranking targets in background.
    for target_key in _ACTOR_RANKING_TARGETS:
        _start_actor_rankings_refresh(target_key)


@app.get("/rankings.html")
def actor_rankings_page():
    return _actor_rankings_response("all")


@app.get("/actor-rankings/{language_slug}")
def actor_rankings_industry_page(language_slug: str):
    target_key = (language_slug or "").strip().lower()

    if target_key not in _ACTOR_RANKING_TARGETS or target_key == "all":
        raise HTTPException(status_code=404, detail="Actor ranking page not found")

    return _actor_rankings_response(target_key)


@app.get("/disclaimer.html")
def disclaimer_page():
    return _boxofficex_html_file("disclaimer.html")


@app.get("/privacy.html")
def privacy_page():

    return _boxofficex_html_file("privacy.html")


@app.get("/terms.html")
def terms_page():

    return _boxofficex_html_file("terms.html")

@app.get("/about.html")
def about_page():

    return _boxofficex_html_file("about.html")

@app.get("/contact.html")
def contact_page():

    return _boxofficex_html_file("contact.html")


@app.get("/advertise.html")
def advertise_page():
    return _boxofficex_html_file("advertise.html")


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
    slug_map = _unique_movie_slug_map(
        [(row[0], row[1], row[2]) for row in rows]
    )

    for row in rows:
        slug = slug_map[row[0]]
        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]),
            "language": row[3],
            "worldwide_collection_crore": float(row[4]) if row[4] is not None else None,
            "verdict": row[5],
            "director": row[6],
            "poster": safe_movie_poster(row[7]),
            "slug": slug,
            "url": f"/movie/{slug}"
        })

    return {
        "movies": movies
    }


@app.get("/movies/comparison-eligible")
def comparison_eligible_movies():
    """
    Movies eligible for public Movie Comparison.
    BoxOfficeX V1 rule: worldwide collection must be at least ₹25 crore.
    Day-wise collection is intentionally NOT required.
    """
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
                WHERE worldwide_collection_crore IS NOT NULL
                  AND worldwide_collection_crore >= 25
                ORDER BY worldwide_collection_crore DESC, id ASC
            """)
            rows = cur.fetchall()

    all_slug_rows = _movie_slug_rows()
    slug_map = _unique_movie_slug_map(all_slug_rows)

    movies = []
    for row in rows:
        slug = slug_map.get(row[0], movie_seo_slug(row[0], row[1], row[2]))
        movies.append({
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "language": row[3],
            "worldwide_collection_crore": float(row[4]),
            "verdict": row[5],
            "director": row[6],
            "poster": safe_movie_poster(row[7]),
            "slug": slug,
            "url": f"/movie/{slug}"
        })

    return {
        "minimum_worldwide_crore": 25,
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
            "movie_url": public_movie_url(movie_id)
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
                "url": public_movie_url(row[0]),
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
                "url": public_movie_url(r[0]),
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

    slug_map = _unique_movie_slug_map()
    slug = slug_map.get(
        row[0],
        movie_seo_slug(row[0], row[1], row[2])
    )

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
        "poster": safe_movie_poster(row[11]),
        "slug": slug,
        "url": f"/movie/{slug}"
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
# PUBLIC MOVIE PREVIEW / PREMIERE COLLECTIONS
# Kept separate so Day 1 always remains the official release date.
# ============================================================

@app.get("/movies/{movie_id}/preview-collections")
def get_movie_preview_collections(movie_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:

            cur.execute("""
                SELECT
                    id,
                    collection_label,
                    collection_date,
                    tamil_nadu_collection,
                    kerala_collection,
                    karnataka_collection,
                    telugu_states_collection,
                    rest_of_india_collection,
                    india_collection,
                    overseas_collection,
                    worldwide_collection
                FROM movie_preview_collections
                WHERE movie_id = %s
                ORDER BY collection_date ASC, id ASC
            """, (movie_id,))

            rows = cur.fetchall()

    previews = []

    for row in rows:
        previews.append({
            "id": row[0],
            "label": row[1],
            "date": str(row[2]) if row[2] else None,
            "tamil_nadu": float(row[3] or 0),
            "kerala": float(row[4] or 0),
            "karnataka": float(row[5] or 0),
            "telugu_states": float(row[6] or 0),
            "rest_of_india": float(row[7] or 0),
            "india": float(row[8] or 0),
            "overseas": float(row[9] or 0),
            "worldwide": float(row[10] or 0),
        })

    return {
        "movie_id": movie_id,
        "previews": previews,
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
    slug_map = _unique_actor_slug_map(
        [(row[0], row[1]) for row in rows]
    )

    for row in rows:
        slug = slug_map[row[0]]
        actors.append({
            "id": row[0],
            "name": row[1],
            "profession": row[2],
            "photo": safe_actor_photo(row[3]),
            "bio": row[4],
            "slug": slug,
            "url": f"/actor/{slug}"
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

            # Build canonical slug maps ONCE using this same DB connection.
            # Previously public_movie_url()/public_actor_url() rebuilt the full
            # slug map for every individual result.
            cur.execute("""
                SELECT id, title, release_date
                FROM movies
                ORDER BY id
            """)
            search_movie_slug_rows = cur.fetchall()

            cur.execute("""
                SELECT id, name
                FROM actors
                ORDER BY id
            """)
            search_actor_slug_rows = cur.fetchall()

    search_movie_slug_map = _unique_movie_slug_map(search_movie_slug_rows)
    search_actor_slug_map = _unique_actor_slug_map(search_actor_slug_rows)

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
            "url": f"/movie/{search_movie_slug_map[row[0]]}" if row[0] in search_movie_slug_map else "/new-movies.html",
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
            "url": f"/actor/{search_actor_slug_map[row[0]]}" if row[0] in search_actor_slug_map else "/actors.html",
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


# ============================================================
# POPULAR ACTORS
# Data-driven ranking from views + comparison fan activity
# IMPORTANT: KEEP BEFORE /actors/{actor_id}
# ============================================================

@app.get("/actors/popular")
def popular_actors(limit: int = 10):
    """Rank homepage actors by BoxOfficeX hype and fan interaction.

    Views still contribute, but logarithmically, so historic traffic cannot
    permanently dominate newer likes, hype, votes and comments.
    """
    import math
    limit = max(1, min(int(limit or 10), 30))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id, a.name, a.profession, a.photo, a.bio,
                    (SELECT COUNT(*) FROM actor_views av WHERE av.actor_id=a.id) AS view_count,
                    (SELECT COUNT(*) FROM hero_comparison_likes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id) AS comparison_likes,
                    (SELECT COUNT(*) FROM hero_comparison_hype h WHERE h.actor1_id=a.id OR h.actor2_id=a.id) AS comparison_hype,
                    (SELECT COUNT(*) FROM hero_comparison_votes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id) AS comparison_votes,
                    (SELECT COUNT(*) FROM hero_comparison_comments h
                     WHERE (h.actor1_id=a.id OR h.actor2_id=a.id)
                       AND h.is_hidden=FALSE AND h.is_deleted=FALSE) AS comparison_comments
                FROM actors a
                ORDER BY (
                    5 * LN(1 + (SELECT COUNT(*) FROM actor_views av WHERE av.actor_id=a.id))
                    + 8 * (SELECT COUNT(*) FROM hero_comparison_likes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id)
                    + 14 * (SELECT COUNT(*) FROM hero_comparison_hype h WHERE h.actor1_id=a.id OR h.actor2_id=a.id)
                    + 10 * (SELECT COUNT(*) FROM hero_comparison_votes h WHERE h.actor1_id=a.id OR h.actor2_id=a.id)
                    + 12 * (SELECT COUNT(*) FROM hero_comparison_comments h
                            WHERE (h.actor1_id=a.id OR h.actor2_id=a.id)
                              AND h.is_hidden=FALSE AND h.is_deleted=FALSE)
                ) DESC, a.id ASC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()

    actors = []
    for rank, row in enumerate(rows, start=1):
        views, likes, hype, votes, comments = [int(v or 0) for v in row[5:10]]
        score = round(5*math.log1p(views) + 8*likes + 14*hype + 10*votes + 12*comments, 2)
        actors.append({
            "rank": rank, "id": row[0], "name": row[1],
            "profession": row[2], "photo": safe_actor_photo(row[3]), "bio": row[4],
            "view_count": views, "comparison_likes": likes, "comparison_hype": hype,
            "comparison_votes": votes, "comparison_comments": comments,
            "popularity_score": score, "url": public_actor_url(row[0]),
        })
    return {"actors": actors, "ranking_basis": "hype_and_interaction"}


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

    slug_map = _unique_actor_slug_map(
        [(row[0], row[1])]
    )
    slug = slug_map.get(
        row[0],
        actor_seo_slug(row[0], row[1])
    )

    return {
        "id": row[0],
        "name": row[1],
        "profession": row[2],
        "photo": safe_actor_photo(row[3]),
        "bio": row[4],
        "slug": slug,
        "url": f"/actor/{slug}"
    }


# ============================================================
# MOVIE CAST / LINKED ACTORS
# Used by Movie Compare for lead-actor recent theatrical ROI.
# actor_movies currently stores links without billing order, so the
# first linked actor (lowest actor id) is treated as the comparison lead.
# ============================================================

@app.get("/movies/{movie_id}/actors")
def get_movie_actors(movie_id: int):

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id,
                    a.name,
                    a.profession,
                    a.photo
                FROM actor_movies am
                JOIN actors a
                    ON a.id = am.actor_id
                WHERE am.movie_id = %s
                ORDER BY a.id ASC;
            """, (movie_id,))

            rows = cur.fetchall()

    return {
        "movie_id": movie_id,
        "actors": [
            {
                "id": row[0],
                "name": row[1],
                "profession": row[2],
                "photo": safe_actor_photo(row[3])
            }
            for row in rows
        ]
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
                    movies.verdict,
                    movies.budget_crore,
                    movies.india_collection_crore,
                    movies.overseas_collection_crore
                FROM actor_movies
                JOIN movies
                    ON actor_movies.movie_id = movies.id
                WHERE actor_movies.actor_id = %s
                ORDER BY movies.release_date DESC;
            """, (actor_id,))

            rows = cur.fetchall()

    # Build the same canonical movie slugs used by /movie/{movie_slug}.
    slug_map = _unique_movie_slug_map()

    movies = []

    for row in rows:
        movie_slug = slug_map.get(
            row[0],
            movie_seo_slug(row[0], row[1], row[3])
        )

        movies.append({
            "id": row[0],
            "title": row[1],
            "poster": safe_movie_poster(row[2]),
            "release_date": str(row[3]),
            "worldwide_collection_crore": float(row[4]) if row[4] is not None else None,
            "verdict": row[5],
            "budget_crore": float(row[6]) if row[6] is not None else None,
            "india_collection_crore": float(row[7]) if row[7] is not None else None,
            "overseas_collection_crore": float(row[8]) if row[8] is not None else None,
            "slug": movie_slug,
            "url": f"/movie/{movie_slug}"
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

    # Verdict-filtered filmographies also return canonical public movie URLs.
    slug_map = _unique_movie_slug_map()

    movies = []

    for row in rows:
        movie_slug = slug_map.get(
            row[0],
            movie_seo_slug(row[0], row[1], row[3])
        )

        movies.append({
            "id": row[0],
            "title": row[1],
            "poster": safe_movie_poster(row[2]),
            "release_date": str(row[3]),
            "worldwide_collection_crore": float(row[4]) if row[4] is not None else None,
            "verdict": row[5],
            "slug": movie_slug,
            "url": f"/movie/{movie_slug}"
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
# ACTOR COMPARISON — OPTIMIZED SINGLE-PAYLOAD ENDPOINT
# ============================================================

@app.get("/compare/actors/{actor1_id}/{actor2_id}")
def compare_actors(
    actor1_id: int,
    actor2_id: int
):
    """
    Return everything required by compare.html in one HTTP request.

    This replaces the old browser waterfall of:
      /actors
      /actors/{id}/stats (x2)
      /actors/{id}/movies (x2)
      /movies
      /actors/{id}/highest-grossing (x2)

    The existing public endpoints remain available for actor/movie pages.
    """

    if actor1_id == actor2_id:
        raise HTTPException(
            status_code=400,
            detail="Choose two different actors"
        )

    requested_ids = (actor1_id, actor2_id)

    with get_connection() as conn:
        with conn.cursor() as cur:

            # 1) Both actors + all comparison statistics in one aggregate query.
            cur.execute("""
                SELECT
                    a.id,
                    a.name,
                    a.photo,
                    COUNT(DISTINCT m.id) AS movie_count,
                    COALESCE(SUM(m.worldwide_collection_crore), 0) AS total_worldwide,
                    COALESCE(AVG(m.worldwide_collection_crore), 0) AS average_worldwide,
                    COUNT(DISTINCT CASE WHEN m.verdict = 'Blockbuster' THEN m.id END) AS blockbusters,
                    COUNT(DISTINCT CASE WHEN m.verdict = 'Hit' THEN m.id END) AS hits,
                    COUNT(DISTINCT CASE WHEN m.verdict = 'Average' THEN m.id END) AS average_movies,
                    COUNT(DISTINCT CASE WHEN m.verdict = 'Flop' THEN m.id END) AS flops
                FROM actors a
                LEFT JOIN actor_movies am
                    ON a.id = am.actor_id
                LEFT JOIN movies m
                    ON am.movie_id = m.id
                WHERE a.id IN (%s, %s)
                GROUP BY a.id, a.name, a.photo
                ORDER BY a.id;
            """, requested_ids)

            stat_rows = cur.fetchall()

            if len(stat_rows) != 2:
                found_ids = {row[0] for row in stat_rows}
                missing = [
                    actor_id
                    for actor_id in requested_ids
                    if actor_id not in found_ids
                ]
                raise HTTPException(
                    status_code=404,
                    detail=f"Actor not found: {', '.join(map(str, missing))}"
                )

            # 2) Filmographies for both actors in ONE query.
            # These fields are exactly what the current era-power, last-five,
            # ROI and highest-grossing calculations need in compare.html.
            cur.execute("""
                SELECT
                    am.actor_id,
                    m.id,
                    m.title,
                    m.poster,
                    m.release_date,
                    m.worldwide_collection_crore,
                    m.verdict,
                    m.budget_crore
                FROM actor_movies am
                JOIN movies m
                    ON m.id = am.movie_id
                WHERE am.actor_id IN (%s, %s)
                ORDER BY am.actor_id, m.release_date DESC NULLS LAST, m.id DESC;
            """, requested_ids)

            movie_rows = cur.fetchall()

            # 3) Minimal era universe. Do NOT send the full /movies payload.
            # Only release date + worldwide gross are required to build the
            # five-year median benchmarks in the existing scoring engine.
            cur.execute("""
                SELECT
                    release_date,
                    worldwide_collection_crore
                FROM movies
                WHERE release_date IS NOT NULL
                  AND worldwide_collection_crore IS NOT NULL
                  AND worldwide_collection_crore > 0
                ORDER BY release_date;
            """)

            era_rows = cur.fetchall()

            # 4) Small actor catalogue used only for related-comparison links.
            cur.execute("""
                SELECT id, name, photo
                FROM actors
                ORDER BY id;
            """)

            actor_catalog_rows = cur.fetchall()

    actor_slug_map = _unique_actor_slug_map()

    comparison = []
    stats_by_id = {}

    for row in stat_rows:
        actor = {
            "id": row[0],
            "name": row[1],
            "photo": safe_actor_photo(row[2]),
            "movie_count": row[3],
            "total_worldwide": float(row[4]),
            "average_worldwide": float(row[5]),
            "blockbusters": row[6],
            "hits": row[7],
            "average_movies": row[8],
            "flops": row[9],
            "slug": actor_slug_map.get(
                row[0],
                actor_seo_slug(row[0], row[1])
            )
        }
        comparison.append(actor)
        stats_by_id[row[0]] = {
            "movie_count": row[3],
            "total_worldwide": float(row[4]),
            "average_worldwide": float(row[5]),
            "blockbusters": row[6],
            "hits": row[7],
            "average_movies": row[8],
            "flops": row[9]
        }

    movies_by_actor = {
        actor1_id: [],
        actor2_id: []
    }

    for row in movie_rows:
        movies_by_actor.setdefault(row[0], []).append({
            "id": row[1],
            "title": row[2],
            "poster": safe_movie_poster(row[3]),
            "release_date": str(row[4]) if row[4] is not None else None,
            "worldwide_collection_crore": float(row[5]) if row[5] is not None else None,
            "verdict": row[6],
            "budget_crore": float(row[7]) if row[7] is not None else None
        })

    def highest_grossing_payload(actor_id: int):
        usable = [
            movie
            for movie in movies_by_actor.get(actor_id, [])
            if movie.get("worldwide_collection_crore") is not None
        ]

        if not usable:
            return {"movie": None}

        movie = max(
            usable,
            key=lambda item: item.get("worldwide_collection_crore") or 0
        )

        return {
            "movie": {
                "id": movie["id"],
                "title": movie["title"],
                "poster": movie["poster"],
                "worldwide_collection_crore": movie["worldwide_collection_crore"],
                "verdict": movie["verdict"]
            }
        }

    era_universe_movies = [
        {
            "release_date": str(row[0]),
            "worldwide_collection_crore": float(row[1])
        }
        for row in era_rows
    ]

    actors_catalog = [
        {
            "id": row[0],
            "name": row[1],
            "photo": safe_actor_photo(row[2]),
            "slug": actor_slug_map.get(
                row[0],
                actor_seo_slug(row[0], row[1])
            )
        }
        for row in actor_catalog_rows
    ]

    canonical_actor_ids = sorted([actor1_id, actor2_id])
    actors_by_id = {actor["id"]: actor for actor in comparison}

    canonical_slug = None
    canonical_url = None

    if all(actor_id in actors_by_id for actor_id in canonical_actor_ids):
        first_slug = actor_slug_map.get(canonical_actor_ids[0])
        second_slug = actor_slug_map.get(canonical_actor_ids[1])

        if first_slug and second_slug:
            canonical_slug = f"{first_slug}-vs-{second_slug}"
            canonical_url = f"/compare/{canonical_slug}"

    return {
        "comparison": comparison,
        "stats": {
            str(actor1_id): stats_by_id[actor1_id],
            str(actor2_id): stats_by_id[actor2_id]
        },
        "movies": {
            str(actor1_id): movies_by_actor.get(actor1_id, []),
            str(actor2_id): movies_by_actor.get(actor2_id, [])
        },
        "highest_grossing": {
            str(actor1_id): highest_grossing_payload(actor1_id),
            str(actor2_id): highest_grossing_payload(actor2_id)
        },
        "era_universe_movies": era_universe_movies,
        "actors_catalog": actors_catalog,
        "seo": {
            "canonical_ids": canonical_actor_ids,
            "canonical_slug": canonical_slug,
            "canonical_url": canonical_url
        }
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
    actor_slug_map = _unique_actor_slug_map()

    for position, row in enumerate(rows, start=1):

        actor_slug = actor_slug_map.get(int(row[0]))
        rankings.append({
            "rank": position,
            "id": row[0],
            "name": row[1],
            "photo": safe_actor_photo(row[2]),
            "movie_count": row[3],
            "total_worldwide": float(row[4]),
            "average_worldwide": float(row[5]),
            "blockbusters": row[6],
            "url": f"/actor/{actor_slug}" if actor_slug else "/actors.html"
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
                        budget_crore,
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
                            budget_crore,
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
                            budget_crore,
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
            "worldwide_collection": round(float(row[5] or 0), 2),
            "budget_crore": round(float(row[6]), 2) if row[6] is not None else None,
            "verdict": row[7],
            "poster": safe_movie_poster(row[8])
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
from datetime import date, datetime



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
from datetime import date, datetime


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


# ============================================================
# ARTICLE DETAIL - CACHED SSR
# ============================================================

ARTICLE_DETAIL_HTML_CACHE_TTL = 60
ARTICLE_DETAIL_HTML_STALE_TTL = 300
_article_detail_html_cache = {}
_article_detail_cache_lock = threading.Lock()
_article_detail_refreshing = set()


def _article_ssr_image(value, fallback="/images/boxofficex-og.png"):
    value = str(value or "").strip()
    if not value:
        return fallback
    if value.startswith(("https://", "http://", "/")):
        return value
    if value.startswith("article-images/"):
        return "/" + value
    return "/article-images/" + quote(value)


def _article_ssr_inline(value):
    safe = html_escape(str(value or ""))
    safe = re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", safe)
    safe = re.sub(r"(^|[^*])\*([^*\n]+)\*", r"\1<em>\2</em>", safe)
    return safe


def _article_ssr_paragraph(value):
    lines = str(value or "").splitlines()
    output, paragraph, items = [], [], []
    list_type = None

    def flush_paragraph():
        nonlocal paragraph
        if paragraph:
            text = "\n".join(paragraph).strip()
            if text:
                output.append("<p>" + _article_ssr_inline(text).replace("\n", "<br>") + "</p>")
            paragraph = []

    def flush_list():
        nonlocal items, list_type
        if items:
            tag = "ol" if list_type == "ol" else "ul"
            output.append(
                f'<{tag} class="bx-article-list">' +
                "".join(f"<li>{_article_ssr_inline(item)}</li>" for item in items) +
                f"</{tag}>"
            )
            items, list_type = [], None

    for line in lines:
        numbered = re.match(r"^\s*\d+[.)]\s+(.+)$", line)
        bullet = re.match(r"^\s*(?:•|-)\s+(.+)$", line)
        if numbered or bullet:
            flush_paragraph()
            current = "ol" if numbered else "ul"
            if list_type and list_type != current:
                flush_list()
            list_type = current
            items.append((numbered or bullet).group(1))
        elif not line.strip():
            flush_paragraph()
            flush_list()
        else:
            flush_list()
            paragraph.append(line)

    flush_paragraph()
    flush_list()
    return "".join(output)


def _article_ssr_money(value):
    try:
        if value is None or str(value).strip() == "":
            return ""
        number = float(str(value).replace(",", "").strip())
        shown = f"{number:,.2f}".rstrip("0").rstrip(".")
        return f"₹{shown} Cr"
    except Exception:
        return html_escape(str(value or ""))


def _article_ssr_live_tracker(data, release_date=None):
    data = data or {}

    # Linked movie release_date is the ONLY Day-N authority.
    # The public Live Tracker's legacy start_date is intentionally ignored.
    ist = ZoneInfo("Asia/Kolkata")
    now_ist = datetime.now(ist)
    boxoffice_date = (now_ist - timedelta(hours=6)).date()

    movie_release_date = None
    try:
        raw_release = str(release_date or "").strip()
        if raw_release:
            movie_release_date = date.fromisoformat(raw_release[:10])
    except Exception:
        movie_release_date = None

    if movie_release_date is None:
        return (
            '<section class="live-tracker lt-shell" data-release-date-required="1">'
            '<div class="lt-head"><div><div class="lt-kicker">BOXOFFICEX LIVE TRACKER</div>'
            '<h2>Movie release date required</h2>'
            '<div class="lt-subtitle">Link a movie with a valid release date to calculate the current box-office day.</div>'
            '</div></div></section>'
        )

    day_number = (boxoffice_date - movie_release_date).days + 1

    # Before release, do not invent Day 0/negative Day N.
    if day_number < 1:
        return (
            '<section class="live-tracker lt-shell" data-before-release="1">'
            '<div class="lt-head"><div><div class="lt-kicker">BOXOFFICEX LIVE TRACKER</div>'
            '<h2>Box Office Tracking</h2>'
            '<div class="lt-subtitle">Tracking begins from the linked movie release date at the BoxOfficeX 6 AM IST day boundary.</div>'
            '</div></div></section>'
        )

    # At every 6 AM IST rollover, yesterday's temporary tracker values must not
    # remain in server-rendered HTML. Only values saved in the current tracking
    # day are rendered. The data itself is not persisted/reset here.
    tracker_is_current = False
    stamp = str(data.get("updated_at") or "").strip()
    if stamp:
        try:
            dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ist)
            dt_ist = dt.astimezone(ist)
            tracker_is_current = (dt_ist - timedelta(hours=6)).date() == boxoffice_date
        except Exception:
            tracker_is_current = False

    if not tracker_is_current:
        preserved = {
            "status": data.get("status") or "live",
            "updated_at": data.get("updated_at"),
        }
        data = preserved

    status = str(data.get("status") or "live").lower()
    labels = {
        "live": "LIVE",
        "update": "LATEST UPDATE",
        "final": "FINAL",
        "closed": "TRACKER ENDED",
    }
    active = status in {"live", "update"}
    tracking_day_label = f"DAY {day_number}"
    tracking_date_label = boxoffice_date.strftime("%d %b %Y").upper()
    cards = []

    def add(key, label, money=False, suffix=""):
        value = data.get(key)
        if value is None or str(value).strip() == "":
            return
        shown = _article_ssr_money(value) if money else html_escape(str(value))
        cards.append(
            f'<div class="lt-card"><div class="lt-value">{shown}{suffix}</div>'
            f'<div class="lt-label">{html_escape(label)}</div></div>'
        )

    add("india_gross", "India Gross", True)
    add("overseas_gross", "Overseas Gross", True)
    add("tickets_sold", "Tickets Sold")
    add("shows_tracked", "Shows Tracked")
    add("occupancy", "Occupancy", suffix="%")
    add("advance_booking", "Advance Booking", True)
    add("premiere_gross", "Premiere Gross", True)
    add("day_gross", "Day Gross", True)
    add("fast_filling", "Fast Filling")
    add("housefull_shows", "Housefull Shows")

    worldwide = ""
    try:
        india = float(str(data.get("india_gross")).replace(",", ""))
        overseas = float(str(data.get("overseas_gross")).replace(",", ""))
        worldwide = (
            '<div class="lt-worldwide"><div class="lt-value">'
            + _article_ssr_money(india + overseas)
            + '</div><div class="lt-label">Worldwide Gross</div>'
              '<span class="lt-auto">Auto Calculated</span></div>'
        )
    except Exception:
        pass

    show_periods = [
        ("Special Shows", "special_shows", "special_occupancy"),
        ("Morning", "morning_shows", "morning_occupancy"),
        ("Afternoon", "afternoon_shows", "afternoon_occupancy"),
        ("Evening", "evening_shows", "evening_occupancy"),
        ("Night", "night_shows", "night_occupancy"),
    ]
    show_cards = []
    for label, shows_key, occ_key in show_periods:
        shows, occ = data.get(shows_key), data.get(occ_key)
        if (shows is None or str(shows).strip() == "") and (occ is None or str(occ).strip() == ""):
            continue
        parts = []
        if shows is not None and str(shows).strip() != "":
            parts.append(f'<div class="lt-show-stat"><strong>{html_escape(str(shows))}</strong><span>Shows Tracked</span></div>')
        if occ is not None and str(occ).strip() != "":
            parts.append(f'<div class="lt-show-stat"><strong>{html_escape(str(occ))}%</strong><span>Occupancy</span></div>')
        show_cards.append(
            f'<div class="lt-show-card"><div class="lt-show-period-name">{label}</div>'
            f'<div class="lt-show-stats">{"".join(parts)}</div></div>'
        )

    note = str(data.get("note") or "").strip()
    if not cards and not worldwide and not show_cards and not note:
        return ""

    return (
        f'<section class="live-tracker-block {"lt-active" if active else ""}" aria-label="Live box office tracker">'
        f'<div class="lt-head"><div class="lt-status"><span class="lt-dot"></span>'
        f'<span class="lt-status-copy"><span>{html_escape(labels.get(status, "LIVE"))}</span>'
        f'{"<span class=\"lt-tracking-copy\">• CURRENTLY TRACKING</span>" if active else ""}'
        f'</span></div></div>'
        f'{"<div class=\"lt-grid\">" + "".join(cards) + "</div>" if cards else ""}'
        f'{worldwide}'
        f'{"<div class=\"lt-show-performance\"><div class=\"lt-show-head\"><strong>Show Performance</strong></div><div class=\"lt-show-grid\">" + "".join(show_cards) + "</div></div>" if show_cards else ""}'
        f'{"<div class=\"lt-note\"><strong>Latest Update</strong>" + _article_ssr_inline(note).replace(chr(10), "<br>") + "</div>" if note else ""}'
        f'</section>'
    )



def _article_ssr_theatrical_performance(data):
    """Server-render the same stored theatrical analysis that the public JS enhances."""
    analysis = data.get("analysis") if isinstance(data, dict) else None
    tp = analysis.get("theatrical_performance") if isinstance(analysis, dict) else None
    if not isinstance(tp, dict):
        return ""

    run_stage = tp.get("run_stage") if isinstance(tp.get("run_stage"), dict) else {}
    verdict_enabled = bool(run_stage.get("verdict_enabled", True))
    stage_label = str(run_stage.get("label") or "Recovery Tracking")

    def public_level(item):
        level = (item or {}).get("current_level") or {}
        if verdict_enabled:
            return str(level.get("key") or "estimated"), str(level.get("label") or "Estimated")
        return str(run_stage.get("key") or "TRACKING"), stage_label

    def money(v):
        return _article_ssr_money(v)

    def level_class(value):
        return re.sub(r"[^a-z0-9-]+", "-", str(value or "flop").lower().replace("_", "-")).strip("-")

    def next_html(item):
        nxt = item.get("next_level") if isinstance(item, dict) else None
        if not isinstance(nxt, dict):
            return '<div class="bx-tp-next"><div class="bx-tp-next-row"><strong>Highest performance level achieved</strong></div></div>'
        if verdict_enabled:
            target_copy = (
                f'<span><strong>{money(nxt.get("remaining"))}</strong> more gross collection needed to reach '
                f'<strong>{html_escape(str(nxt.get("label") or "").upper())}</strong></span>'
            )
        else:
            current_multiple = float((item or {}).get("multiple") or 0)
            target_multiple = float(nxt.get("multiple") or 0)
            target_label = html_escape(str(nxt.get("label") or "Recovery"))
            target_copy = (
                f'<span><strong>Next Target: {target_label} Range ({target_multiple:.2f}×)</strong><br>'
                f'<strong>{money(nxt.get("remaining"))}</strong> more gross needed<br>'
                f'<small>Current: <strong>{current_multiple:.2f}×</strong> → Target: <strong>{target_multiple:.2f}×</strong> '
                f'· Tracking benchmark only; estimated verdict begins from Day 8.</small></span>'
            )
        return (
            '<div class="bx-tp-next"><div class="bx-tp-next-row bx-tp-next-simple">'
            + target_copy +
            '</div></div>'
        )

    combined = tp.get("combined") if isinstance(tp.get("combined"), dict) else None
    combined_html = ""
    if combined and int(combined.get("market_count") or 0) >= 2:
        public_key, public_label = public_level(combined)
        combined_html = (
            '<div class="bx-tp-combined">'
            '<div class="bx-tp-kicker">Combined tracker</div>'
            '<div class="bx-tp-combined-title">Calculated Theatrical Value — Available Markets</div>'
            '<div class="bx-tp-stats">'
            f'<div class="bx-tp-stat"><span>Theatrical Rights</span><strong>{money(combined.get("theatrical_value"))}</strong></div>'
            f'<div class="bx-tp-stat"><span>Current Gross</span><strong>{money(combined.get("gross"))}</strong></div>'
            f'<div class="bx-tp-stat"><span>Estimated Net</span><strong>{money(combined.get("estimated_net"))}</strong></div>'
            f'<div class="bx-tp-stat"><span>Estimated Theatrical Share</span><strong>{money(combined.get("estimated_theatrical_share"))}</strong></div>'
            f'<div class="bx-tp-stat"><span>Performance</span><strong>{float(combined.get("multiple") or 0):.2f}×</strong></div>'
            f'<div class="bx-tp-stat level"><span>{"Estimated Level" if verdict_enabled else "Run Stage"}</span><strong class="bx-tp-level-big bx-tp-level-{level_class(public_key)}">{html_escape(public_label)}</strong></div>'
            '</div>' + next_html(combined) + '</div>'
        )

    region_order = ("tamil_nadu", "kerala", "karnataka", "telugu_states", "rest_of_india", "overseas")
    regions = tp.get("regions") if isinstance(tp.get("regions"), dict) else {}
    region_html = []
    for key in region_order:
        r = regions.get(key)
        if not isinstance(r, dict):
            continue
        public_key, public_label = public_level(r)
        net = "" if key == "overseas" else f'<div class="bx-tp-mini"><span>Estimated Net</span><strong>{money(r.get("estimated_net"))}</strong></div>'
        region_html.append(
            '<article class="bx-tp-region">'
            '<div class="bx-tp-region-head">'
            f'<div class="bx-tp-region-name">{html_escape(str(r.get("label") or key))}</div>'
            f'<span class="bx-tp-badge level-{level_class(public_key)}">{html_escape(public_label)}</span>'
            '</div><div class="bx-tp-region-values">'
            f'<div class="bx-tp-mini"><span>Theatrical Rights</span><strong>{money(r.get("theatrical_value"))}</strong></div>'
            f'<div class="bx-tp-mini"><span>Current Gross</span><strong>{money(r.get("gross"))}</strong></div>'
            + net +
            f'<div class="bx-tp-mini"><span>Estimated Theatrical Share</span><strong>{money(r.get("estimated_theatrical_share"))}</strong></div>'
            f'<div class="bx-tp-mini"><span>Multiple</span><strong>{float(r.get("multiple") or 0):.2f}×</strong></div>'
            '</div>' + next_html(r) + '</article>'
        )

    if not combined_html and not region_html:
        return ""

    seo = analysis.get("tracker_seo") if isinstance(analysis.get("tracker_seo"), dict) else {}
    movie = seo.get("movie") if isinstance(seo.get("movie"), dict) else {}
    movie_title = str(movie.get("title") or "This movie").strip()
    safe_movie_title = html_escape(movie_title)
    run_day = int(run_stage.get("day") or 1)

    combined_for_copy = combined or {}
    current_multiple = float(combined_for_copy.get("multiple") or 0)
    current_gross = money(combined_for_copy.get("gross")) or "the latest reported gross"
    theatrical_value = money(combined_for_copy.get("theatrical_value")) or "the reported theatrical value"
    estimated_net = money(combined_for_copy.get("estimated_net")) or "—"
    estimated_share = money(combined_for_copy.get("estimated_theatrical_share")) or "—"
    rights_number = float(combined_for_copy.get("theatrical_value") or 0)
    share_number = float(combined_for_copy.get("estimated_theatrical_share") or 0)
    share_recovery_pct = (share_number / rights_number * 100) if rights_number > 0 else 0
    remaining_share = money(max(0, rights_number - share_number)) if rights_number > 0 else "—"
    current_level = combined_for_copy.get("current_level") if isinstance(combined_for_copy.get("current_level"), dict) else {}
    current_level_label = str(current_level.get("label") or "Estimated").strip()

    visible_region_names = [
        str((regions.get(k) or {}).get("label") or "").strip()
        for k in region_order if isinstance(regions.get(k), dict)
    ]
    visible_region_names = [x for x in visible_region_names if x]
    if len(visible_region_names) > 1:
        region_phrase = ", ".join(visible_region_names[:-1]) + " and " + visible_region_names[-1]
    elif visible_region_names:
        region_phrase = visible_region_names[0]
    else:
        region_phrase = "currently reported markets"

    intro = (
        f'<section class="bx-tp-seo" aria-label="{safe_movie_title} budget and box office recovery explained">'
        f'<h2>{safe_movie_title} Budget &amp; Box Office Recovery Tracker</h2>'
        f'<p>{safe_movie_title} has <strong>{theatrical_value}</strong> in reported theatrical rights. '
        f'From <strong>{current_gross}</strong> tracked gross, BoxOfficeX estimates <strong>{estimated_net}</strong> net and '
        f'<strong>{estimated_share}</strong> theatrical share, equal to <strong>{share_recovery_pct:.1f}%</strong> of reported theatrical rights. '
        f'An estimated <strong>{remaining_share}</strong> in theatrical share remains to recover the reported rights value; '
        f'track territory-wise recovery and the next box office target below.</p>'
    )

    if visible_region_names:
        intro += (
            f'<h3>{safe_movie_title} Territory-wise Theatrical Performance</h3>'
            f'<p>Current theatrical recovery is being tracked only for markets with reported theatrical values and collection data: '
            f'<strong>{html_escape(region_phrase)}</strong>. Markets without usable reported values are not shown as artificial zeroes.</p>'
        )

    actor_links = seo.get("actor_comparisons") if isinstance(seo.get("actor_comparisons"), list) else []
    movie_links = seo.get("movie_comparisons") if isinstance(seo.get("movie_comparisons"), list) else []
    if actor_links or movie_links:
        intro += '<div class="bx-tp-related"><h3>Compare &amp; Explore on BoxOfficeX</h3>'
        if actor_links:
            intro += '<div class="bx-tp-related-group"><strong>Actor Comparisons</strong><ul>' + "".join(
                f'<li><a href="{html_escape(str(x.get("url") or "#"))}">{html_escape(str(x.get("label") or "Actor comparison"))}</a></li>'
                for x in actor_links[:3]
            ) + '</ul></div>'
        if movie_links:
            intro += '<div class="bx-tp-related-group"><strong>Movie Comparisons</strong><ul>' + "".join(
                f'<li><a href="{html_escape(str(x.get("url") or "#"))}">{html_escape(str(x.get("label") or "Movie comparison"))}</a></li>'
                for x in movie_links[:3]
            ) + '</ul></div>'
        intro += '</div>'

    faq_verdict = (
        f'{safe_movie_title} is still in {html_escape(stage_label)} on Day {run_day}. BoxOfficeX does not assign an estimated hit/flop performance level during the first seven days; verdict tracking begins from Day 8.'
        if not verdict_enabled else
        f'Based on the currently stored theatrical-value and box-office data, {safe_movie_title} is in the {html_escape(current_level_label)} estimated performance range. The estimate can change as the theatrical run develops.'
    )
    intro += (
        f'<div class="bx-tp-faq"><h3>{safe_movie_title} Box Office FAQ</h3>'
        f'<details><summary>Is {safe_movie_title} a hit or flop?</summary><p>{faq_verdict}</p></details>'
        f'<details><summary>What is {safe_movie_title}’s theatrical recovery?</summary>'
        f'<p>The tracker currently shows <strong>{current_multiple:.2f}×</strong> recovery across markets with reported theatrical values, based on a tracked gross of <strong>{current_gross}</strong> against <strong>{theatrical_value}</strong>.</p></details>'
        f'<details><summary>How does BoxOfficeX calculate {safe_movie_title}’s theatrical performance?</summary>'
        f'<p>BoxOfficeX compares reported territory theatrical values with stored box office gross and estimated theatrical share. Missing territories are excluded rather than treated as zero, and the public estimated performance label begins from Day 8.</p></details>'
        '</div></section>'
    )

    disclaimer = html_escape(str(tp.get("disclaimer") or ""))
    note = html_escape(str(tp.get("performance_note") or ""))
    return (
        '<section class="bx-tp" aria-label="Estimated theatrical performance">'
        '<div class="bx-tp-head"><div><div class="bx-tp-title">🎯 Estimated Theatrical Performance</div>'
        f'<div class="bx-tp-sub">{"Recovery tracking during the opening week — verdict labels begin from Day 8" if not verdict_enabled else "Reported theatrical values compared with matching earned box-office gross"}</div></div></div>'
        + combined_html
        + ('<div class="bx-tp-section-title">Area-wise Theatrical Value Tracker</div><div class="bx-tp-regions">' + "".join(region_html) + '</div>' if region_html else '')
        + f'<div class="bx-tp-notes"><p><strong>BoxOfficeX Note:</strong> {disclaimer}</p><p><strong>Performance Note:</strong> {note}</p></div>'
        '</section>'
        + intro
    )


def _article_ssr_boxoffice(data):
    """
    Server-render the persistent Box Office Report.

    Territory visibility is data-driven:
    - a territory is hidden until it has a positive reported collection;
    - once a territory appears on a later day, its column becomes visible;
    - earlier days with no value for that territory show "—", never a fake ₹0;
    - India/Worldwide totals still use every available reported territory.
    """
    data = data or {}
    days = list(data.get("days") or [])

    territory_meta = (
        ("tamil_nadu", "Tamil Nadu"),
        ("kerala", "Kerala"),
        ("karnataka", "Karnataka"),
        ("telugu_states", "AP & Telangana"),
        ("rest_of_india", "Rest of India"),
        ("overseas", "Overseas"),
    )
    india_keys = {
        "tamil_nadu", "kerala", "karnataka",
        "telugu_states", "rest_of_india",
    }

    def raw_present(value):
        if value is None or str(value).strip() == "":
            return False
        try:
            return float(str(value).replace(",", "").strip()) > 0
        except Exception:
            return False

    def num(value):
        try:
            if value is None or str(value).strip() == "":
                return 0.0
            return float(str(value).replace(",", "").strip())
        except Exception:
            return 0.0

    def money(value):
        return _article_ssr_money(value)

    def territory_cell(day, key):
        value = (day or {}).get(key)
        return money(value) if raw_present(value) else "—"

    def day_type(day):
        return str((day or {}).get("type") or "REGULAR").upper()

    def day_label(day):
        if day_type(day) == "PREVIEW":
            return str((day or {}).get("label") or "Preview / Premiere")
        number = (day or {}).get("number")
        return f"Day {number}" if number not in (None, "") else "Day"

    def day_totals(day):
        india = sum(num((day or {}).get(k)) for k in india_keys)
        overseas = num((day or {}).get("overseas"))
        return india, overseas, india + overseas

    # A territory becomes public only after at least one positive value exists
    # somewhere in the stored report. Later additions therefore appear
    # automatically without changing the renderer again.
    visible_territories = [
        (key, label)
        for key, label in territory_meta
        if any(raw_present((day or {}).get(key)) for day in days)
    ]

    report_html = ""
    if days:
        rows = []
        for day in days:
            india, overseas, worldwide = day_totals(day)
            date_text = str((day or {}).get("date") or "").strip()
            status = str((day or {}).get("status") or "").strip().upper()

            territory_cells = "".join(
                f"<td>{territory_cell(day, key)}</td>"
                for key, _label in visible_territories
            )

            rows.append(
                "<tr>"
                f"<th scope=\"row\">{html_escape(day_label(day))}</th>"
                f"<td>{html_escape(date_text)}</td>"
                + territory_cells +
                f"<td>{money(india)}</td>"
                f"<td>{money(worldwide)}</td>"
                f"<td>{html_escape(status)}</td>"
                "</tr>"
            )

        territory_headers = "".join(
            f"<th>{html_escape(label)}</th>"
            for _key, label in visible_territories
        )

        report_html = (
            '<div class="boxoffice-block">'
            '<div class="boxoffice-title">Box Office Collection Report</div>'
            '<div class="table-wrap"><table class="bo-table">'
            '<thead><tr>'
            '<th>Day</th><th>Date</th>'
            + territory_headers +
            '<th>India Gross</th><th>Worldwide</th><th>Status</th>'
            '</tr></thead><tbody>'
            + "".join(rows) +
            '</tbody></table></div></div>'
        )

    if not report_html:
        pairs = []
        for key, label in (
            ("budget", "Budget"),
            ("india", "India Gross"), ("india_gross", "India Gross"),
            ("overseas", "Overseas"), ("overseas_gross", "Overseas"),
            ("worldwide", "Worldwide"), ("worldwide_gross", "Worldwide"),
            ("verdict", "Verdict"),
        ):
            value = data.get(key)
            if value is None or str(value).strip() == "":
                continue
            shown = html_escape(str(value)) if key == "verdict" else money(value)
            pairs.append(
                f'<div class="bo-card"><div class="bo-label">{html_escape(label)}</div>'
                f'<div class="bo-value">{shown}</div></div>'
            )
        if pairs:
            report_html = (
                '<div class="boxoffice-block">'
                '<div class="boxoffice-title">Box Office Collection Report</div>'
                f'<div class="boxoffice-grid">{"".join(pairs)}</div></div>'
            )

    theatrical_html = _article_ssr_theatrical_performance(data)
    return report_html + theatrical_html


def _article_ssr_related_entity(block_type, data):
    entity_id = data.get(f"{block_type}_id")
    if not entity_id:
        return ""

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                if block_type == "movie":
                    cur.execute("SELECT title, release_date, poster FROM movies WHERE id=%s LIMIT 1", (entity_id,))
                    row = cur.fetchone()
                    if not row:
                        return ""
                    title, release_date, poster = row
                    slug = _slugify(title)
                    year = str(release_date)[:4] if release_date else ""
                    if year:
                        slug = f"{slug}-{year}"
                    href = f"/movie/{quote(slug)}"
                    image = safe_movie_poster(poster)
                    if not _is_remote_image(image):
                        image = "/posters/" + quote(str(image))
                    meta = "Movie"
                else:
                    cur.execute("SELECT name, photo FROM actors WHERE id=%s LIMIT 1", (entity_id,))
                    row = cur.fetchone()
                    if not row:
                        return ""
                    title, photo = row
                    href = f"/actor/{quote(_slugify(title))}"
                    image = safe_actor_photo(photo)
                    if not _is_remote_image(image):
                        image = "/actors/" + quote(str(image))
                    meta = "Actor"

        return (
            f'<a class="related-card" href="{html_escape(href, quote=True)}">'
            f'<img src="{html_escape(image, quote=True)}" alt="{html_escape(str(title), quote=True)}" loading="lazy">'
            f'<div><strong>{html_escape(str(title))}</strong><small>{meta}</small></div></a>'
        )
    except Exception as exc:
        print("Article SSR entity block warning:", type(exc).__name__, exc, flush=True)
        return ""


def _article_ssr_block(block, article=None):
    block_type = str(block.get("block_type") or "").lower()
    data = block.get("extra_data") or {}
    content = block.get("content") or ""

    if block_type == "paragraph":
        return _article_ssr_paragraph(content)
    if block_type == "heading":
        heading_level = str(
            data.get("level")
            or data.get("heading_level")
            or "h2"
        ).strip().lower()
        tag = "h3" if heading_level in {"3", "h3"} else "h2"
        return f"<{tag}>{_article_ssr_inline(content)}</{tag}>"
    if block_type == "quote":
        return "<blockquote>" + _article_ssr_inline(content).replace("\n", "<br>") + "</blockquote>"
    if block_type == "image":
        image = _article_ssr_image(block.get("image"))
        caption = str(block.get("image_caption") or "")
        credit = str(block.get("image_credit") or "")
        figcaption = ""
        if caption or credit:
            figcaption = (
                '<figcaption class="media-caption">' + html_escape(caption)
                + (f'<span class="media-credit"> • {html_escape(credit)}</span>' if credit else "")
                + "</figcaption>"
            )
        return (
            '<figure class="article-image">'
            f'<img src="{html_escape(image, quote=True)}" alt="{html_escape(caption or "Article image", quote=True)}" loading="lazy">'
            f'{figcaption}</figure>'
        )
    if block_type == "table":
        headers = data.get("headers") if isinstance(data.get("headers"), list) else []
        rows = data.get("rows") if isinstance(data.get("rows"), list) else []
        if not headers and not rows:
            return ""
        width = max([len(headers)] + [len(r) for r in rows if isinstance(r, list)] + [1])
        head = "".join(f"<th scope=\"col\">{_article_ssr_inline(headers[i] if i < len(headers) else '')}</th>" for i in range(width))
        body = "".join(
            "<tr>" + "".join(f"<td>{_article_ssr_inline(row[i] if i < len(row) else '')}</td>" for i in range(width)) + "</tr>"
            for row in rows if isinstance(row, list)
        )
        return (
            '<div class="article-table-block"><div class="article-table-scroll" role="region" aria-label="Article data table" tabindex="0">'
            f'<table class="article-data-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div></div>'
        )
    if block_type == "gallery":
        images = data.get("images") if isinstance(data.get("images"), list) else []
        return '<div class="gallery-block">' + "".join(
            f'<img src="{html_escape(_article_ssr_image(name), quote=True)}" alt="Article gallery image" loading="lazy">'
            for name in images
        ) + "</div>" if images else ""
    if block_type == "video":
        url = str(data.get("url") or "").strip()
        return (
            f'<a class="video-link" href="{html_escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">▶ Watch Video</a>'
            if url else ""
        )
    if block_type == "live_tracker":
        linked_movie = ((article or {}).get("movies") or [None])[0]
        release_date = (linked_movie or {}).get("release_date")
        return _article_ssr_live_tracker(data, release_date=release_date)
    if block_type == "boxoffice":
        return _article_ssr_boxoffice(data)
    if block_type in {"movie", "actor"}:
        return _article_ssr_related_entity(block_type, data)
    return ""


def _article_ssr_format_date(value):
    if not value:
        return ""
    try:
        return value.strftime("%d %b %Y")
    except Exception:
        return str(value)


def _article_ssr_explore_more(article):
    """Crawlable Internal Linking V1: article -> linked movie/actors + ranking hubs."""
    movies = list(article.get("movies") or [])[:3]
    actors = list(article.get("actors") or [])[:5]

    links = []
    seen = set()

    def add_link(url, label, kind):
        url = str(url or "").strip()
        label = str(label or "").strip()
        if not url or not label or url in seen:
            return
        seen.add(url)
        links.append((url, label, kind))

    for movie in movies:
        add_link(
            movie.get("url"),
            f"{movie.get('title') or 'Movie'} — Box Office & Movie Details",
            "movie",
        )

    for actor in actors:
        add_link(
            actor.get("url"),
            f"{actor.get('name') or 'Actor'} — Movies & Box Office",
            "actor",
        )

    # Stable crawlable hub links. Keep V1 conservative rather than guessing filters.
    add_link("/movie-rankings.html", "Explore Movie Box Office Rankings", "ranking")
    add_link("/rankings.html", "Explore Actor Box Office Rankings", "ranking")

    if not links:
        return ""

    items = "".join(
        f'<a class="bx-explore-link bx-explore-{html_escape(kind, quote=True)}" '
        f'href="{html_escape(url, quote=True)}">{html_escape(label)}</a>'
        for url, label, kind in links
    )
    return (
        '<section class="bx-explore-more" aria-labelledby="bxExploreMoreTitle">'
        '<h2 id="bxExploreMoreTitle">Explore More on BoxOfficeX</h2>'
        '<div class="bx-explore-links">' + items + '</div>'
        '</section>'
    )



def _article_tracking_ctr(article):
    """
    Automatic CTR metadata for Box Office Tracking articles only.

    Activation is deliberately structural: the article must contain BOTH a
    Live Tracker block and a stored Box Office Report block. Normal articles
    therefore keep their admin/SQL title and metadata untouched.

    The stored Box Office Report is the source of truth for collection and
    theatrical-performance numbers. The public Live Tracker is never used as
    the permanent theatrical-analysis source.
    """
    blocks = list(article.get("blocks") or [])
    live_blocks = [b for b in blocks if str(b.get("block_type") or "").lower() == "live_tracker"]
    bo_blocks = [b for b in blocks if str(b.get("block_type") or "").lower() == "boxoffice"]
    if not live_blocks or not bo_blocks:
        return None

    movie = (article.get("movies") or [None])[0]
    movie_title = str((movie or {}).get("title") or "").strip()
    if not movie_title:
        # Do not guess a movie name from an editorial headline.
        return None

    # Use the first Box Office Report with regular day rows.
    bo = None
    for block in bo_blocks:
        extra = block.get("extra_data") or {}
        days = extra.get("days") if isinstance(extra, dict) else None
        if isinstance(days, list) and any(
            isinstance(d, dict) and str(d.get("type") or "REGULAR").upper() != "PREVIEW"
            for d in days
        ):
            bo = block
            break
    if not bo:
        return None

    extra = bo.get("extra_data") or {}
    regular_days = [
        d for d in (extra.get("days") or [])
        if isinstance(d, dict) and str(d.get("type") or "REGULAR").upper() != "PREVIEW"
    ]

    # The site's existing tracking convention is 06:00 IST -> next-day 06:00 IST.
    now_ist = datetime.now(ZoneInfo("Asia/Kolkata"))
    boxoffice_date = (now_ist - timedelta(hours=6)).date()

    current_day = None
    for d in regular_days:
        try:
            if date.fromisoformat(str(d.get("date") or "")) == boxoffice_date:
                current_day = d
                break
        except ValueError:
            continue

    # Temporary Live Tracker state for the active public tracking cycle.
    live_extra = (live_blocks[0].get("extra_data") or {}) if live_blocks else {}

    # DAY-NUMBER AUTHORITY
    # --------------------
    # The linked movie's RELEASE DATE is the single authority for automatic
    # Day 1..7 tracking. BoxOfficeX's active box-office date already follows
    # the existing 06:00 IST -> 06:00 IST boundary.
    #
    # Preview / premiere report rows and Live Tracker start_date do NOT decide
    # Day N. If the linked movie has no valid release date, we do not guess.
    day_number = None
    release_date_missing = False

    movie_release_raw = str((movie or {}).get("release_date") or "").strip()
    if movie_release_raw:
        try:
            movie_release_date = date.fromisoformat(movie_release_raw[:10])
            candidate = (boxoffice_date - movie_release_date).days + 1
            if candidate >= 1:
                day_number = candidate
        except Exception:
            release_date_missing = True
    else:
        release_date_missing = True

    analysis = ((extra.get("analysis") or {}).get("theatrical_performance")
                if isinstance(extra.get("analysis"), dict) else None) or {}
    combined = analysis.get("combined") if isinstance(analysis, dict) else None
    combined = combined if isinstance(combined, dict) else {}

    def money(v):
        try:
            n = float(v)
        except Exception:
            return None
        if n <= 0:
            return None
        shown = f"{n:,.2f}".rstrip("0").rstrip(".")
        return f"₹{shown} Cr"

    def day_worldwide(d):
        if not isinstance(d, dict):
            return 0.0
        india = sum(_bo_number(d.get(k)) for k in (
            "tamil_nadu", "kerala", "karnataka", "telugu_states", "rest_of_india"
        ))
        return india + _bo_number(d.get("overseas"))

    # Temporary public Live Tracker drives ONLY the current live headline amount.
    # It is considered current only when its last save belongs to the active
    # BoxOfficeX 06:00 IST -> 06:00 IST tracking day. This prevents yesterday's
    # temporary number from leaking into a new day's H1.
    def live_tracker_is_current(data):
        stamp = str((data or {}).get("updated_at") or "").strip()
        if not stamp:
            return False
        try:
            dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("Asia/Kolkata"))
            dt_ist = dt.astimezone(ZoneInfo("Asia/Kolkata"))
            return (dt_ist - timedelta(hours=6)).date() == boxoffice_date
        except Exception:
            return False

    def live_tracker_headline_amount(data):
        if not live_tracker_is_current(data):
            return 0.0, ""

        day_gross = _bo_number((data or {}).get("day_gross"))
        if day_gross > 0:
            return day_gross, "Gross So Far"

        india = _bo_number((data or {}).get("india_gross"))
        overseas = _bo_number((data or {}).get("overseas_gross"))

        if india > 0 and overseas > 0:
            return india + overseas, "Worldwide Gross So Far"
        if india > 0:
            return india, "India Gross So Far"
        if overseas > 0:
            return overseas, "Overseas Gross So Far"
        return 0.0, ""

    current_day_gross, current_day_gross_label = live_tracker_headline_amount(live_extra)

    # Stored cumulative totals. ADVANCE is excluded exactly like the theatrical model.
    earned_rows = [
        d for d in regular_days
        if str(d.get("status") or "").upper() != "ADVANCE"
    ]
    earned = _bo_sum_rows(earned_rows)
    cumulative_worldwide = _bo_number(earned.get("worldwide"))

    # FINAL/FROZEN worldwide authority: use the same complete stored Box Office
    # Report gross used by the V9 theatrical-performance model. This prevents a
    # Day 1 subtotal from being frozen when preview/premiere + regular stored
    # report rows produce a larger cumulative worldwide total.
    report_worldwide_total = _bo_number(combined.get("gross"))
    if report_worldwide_total <= 0:
        report_worldwide_total = cumulative_worldwide

    tracking_enabled = bool(article.get("tracking_enabled", True))
    live_mode = tracking_enabled and day_number is not None and day_number >= 1

    if not tracking_enabled:
        # FINAL/FROZEN mode. Prefer the persistent snapshot created when Admin
        # switches tracking OFF. The fallback below is deterministic and uses
        # only the permanent stored Box Office Report, never temporary tracker data.
        frozen_h1 = str(article.get("final_h1") or "").strip()
        frozen_title = str(article.get("final_meta_title") or "").strip()
        frozen_description = str(article.get("final_meta_description") or "").strip()
        frozen_subtitle = str(article.get("final_subtitle") or frozen_description).strip()
        if frozen_h1 and frozen_title and frozen_description:
            return {
                "mode": "FINAL / FROZEN", "day": day_number,
                "h1": frozen_h1, "seo_title": frozen_title,
                "meta_description": frozen_description, "subtitle": frozen_subtitle,
                "source": "frozen_stored_boxoffice_report", "frozen": True,
                "finalized_at": article.get("tracking_finalized_at"),
            }

    if live_mode:
        h1 = f"{movie_title} Day {day_number} Box Office Collection Live"
        if current_day_gross > 0:
            h1 += f": {money(current_day_gross)} {current_day_gross_label}"
    elif tracking_enabled:
        # Before release / missing release date: never guess Day N.
        return None
    else:
        final_worldwide = money(report_worldwide_total)
        h1 = (
            f"{movie_title} Box Office Collection: {final_worldwide} Worldwide, Complete Day-Wise Report"
            if final_worldwide else
            f"{movie_title} Box Office Collection: Complete Day-Wise & Worldwide Report"
        )

    # CTR description is built from the STORED Box Office Report/theatrical analysis.
    parts = []
    rights = money(combined.get("theatrical_value"))
    share = money(combined.get("estimated_theatrical_share"))
    gross = money(combined.get("gross"))
    level = str((combined.get("current_level") or {}).get("label") or "").strip()
    next_level = combined.get("next_level") if isinstance(combined.get("next_level"), dict) else {}
    remaining = money(next_level.get("remaining"))
    next_label = str(next_level.get("label") or "").strip()

    if live_mode and current_day_gross > 0:
        parts.append(f"{movie_title} reaches {money(current_day_gross)} {current_day_gross_label} on Day {day_number}.")
    elif live_mode:
        parts.append(f"{movie_title} Day {day_number} box office collection live.")
    elif report_worldwide_total > 0:
        if rights:
            sentence = f"{movie_title} has collected {money(report_worldwide_total)} worldwide against {rights} reported theatrical rights"
            if share:
                sentence += f", with an estimated theatrical share of {share}"
            sentence += "."
            parts.append(sentence)
        else:
            parts.append(f"{movie_title} has collected {money(report_worldwide_total)} worldwide.")
    else:
        parts.append(f"{movie_title} complete day-wise box office collection report.")

    if rights and (live_mode or report_worldwide_total <= 0):
        sentence = f"Against {rights} reported theatrical rights"
        if share:
            sentence += f", with an estimated theatrical share of {share}"
        sentence += "."
        parts.append(sentence)

    if live_mode:
        if remaining and next_label:
            parts.append(f"{remaining} more gross is needed to reach {next_label}.")
        elif level:
            parts.append(f"Current estimated performance level: {level}.")
        parts.append("See area-wise theatrical value, recovery and performance tracking.")
    else:
        parts.append("Explore the complete day-wise collection, India and overseas totals, area-wise theatrical value and recovery report.")
    description = " ".join(parts)

    # Do not hard-cut generated copy mid-sentence. Search engines may choose a
    # shorter snippet themselves; the SSR source should keep every metric
    # understandable and preserve the next-target label/value together.

    if live_mode:
        seo_title = h1
        if len(seo_title) <= 62 and "boxofficex" not in seo_title.lower():
            seo_title += " | BoxOfficeX"
    else:
        final_worldwide = money(report_worldwide_total)
        seo_title = (
            f"{movie_title} Box Office Collection: {final_worldwide} Worldwide | BoxOfficeX"
            if final_worldwide else
            f"{movie_title} Box Office Collection | BoxOfficeX"
        )

    return {
        "mode": "LIVE" if live_mode else "FINAL / FROZEN",
        "day": day_number,
        "h1": h1,
        "seo_title": seo_title,
        "meta_description": description,
        "source": "stored_boxoffice_report",
        "current_day_gross": round(current_day_gross, 2) if current_day_gross > 0 else None,
        "cumulative_worldwide": round(cumulative_worldwide, 2) if cumulative_worldwide > 0 else None,
        "report_worldwide_total": round(report_worldwide_total, 2) if report_worldwide_total > 0 else None,
        "theatrical_rights": combined.get("theatrical_value"),
        "estimated_theatrical_share": combined.get("estimated_theatrical_share"),
        "performance_level": level or None,
        "next_target_label": next_label or None,
        "next_target_remaining": next_level.get("remaining") if next_level else None,
    }



def _article_normalize_seo_text(value):
    """
    Preserve normal sentence casing while correcting BoxOfficeX's generated
    box-office labels. Never title-case/lowercase the whole sentence.
    """
    text = str(value or "").strip()
    if not text:
        return text

    canonical_phrases = (
        "India Gross So Far",
        "Worldwide Gross So Far",
        "Overseas Gross So Far",
        "Gross So Far",
    )
    for phrase in canonical_phrases:
        text = re.sub(
            re.escape(phrase),
            phrase,
            text,
            flags=re.I,
        )
    return text

def _article_apply_tracking_ctr(article):
    generated = _article_tracking_ctr(article)
    if not generated:
        return article, None

    # V10: for structurally recognized Box Office Tracking articles, the
    # explicit lifecycle switch is authoritative. ON = AUTO for unlimited Day N;
    # OFF = FINAL/FROZEN. Normal articles never reach this function because
    # _article_tracking_ctr() requires both Live Tracker + Box Office Report.
    article = dict(article)
    article["title"] = _article_normalize_seo_text(generated["h1"])
    article["meta_title"] = _article_normalize_seo_text(generated["seo_title"])
    article["meta_description"] = _article_normalize_seo_text(generated["meta_description"])
    article["subtitle"] = _article_normalize_seo_text(
        generated.get("subtitle") or generated["meta_description"]
    )

    # Keep the SSR payload/schema on the exact same normalized text.
    generated = dict(generated)
    generated["h1"] = article["title"]
    generated["seo_title"] = article["meta_title"]
    generated["meta_description"] = article["meta_description"]
    generated["subtitle"] = article["subtitle"]

    generated["priority"] = "AUTO" if bool(article.get("tracking_enabled", True)) else "FINAL"
    generated["automatic_applied"] = bool(article.get("tracking_enabled", True))
    article["generated_tracking_seo"] = generated
    return article, generated



def _article_seo_movie_name(article):
    movies = article.get("movies") or []
    if movies and isinstance(movies[0], dict):
        name = str(movies[0].get("title") or "").strip()
        if name:
            return name
    title = str(article.get("title") or "This movie").strip()
    return re.sub(
        r"\s+(?:Day\s+\d+\s+)?Box Office.*$",
        "",
        title,
        flags=re.I,
    ).strip() or title


def _article_seo_faq_items(article):
    """Create factual FAQ copy only from data already present on this article."""
    movie_name = _article_seo_movie_name(article)
    tracking = article.get("generated_tracking_seo")
    items = []

    if isinstance(tracking, dict):
        day = tracking.get("day")
        current = tracking.get("current_day_gross")
        cumulative = tracking.get("cumulative_worldwide")
        report_total = tracking.get("report_worldwide_total")
        rights = tracking.get("theatrical_rights")
        share = tracking.get("estimated_theatrical_share")
        level = str(tracking.get("performance_level") or "").strip()
        next_label = str(tracking.get("next_target_label") or "").strip()
        remaining = tracking.get("next_target_remaining")

        def cr(value):
            if value is None:
                return None
            try:
                number = float(value)
                shown = f"{number:.2f}".rstrip("0").rstrip(".")
                return f"₹{shown} Cr"
            except (TypeError, ValueError):
                return None

        if day and current is not None:
            items.append((
                f"What is {movie_name} Day {day} box office collection?",
                f"BoxOfficeX currently tracks {cr(current)} as the Day {day} collection figure shown in this live report."
            ))
        if cumulative is not None:
            items.append((
                f"What is {movie_name}'s current worldwide box office collection?",
                f"The current live tracker shows {cr(cumulative)} as the cumulative worldwide collection. The figure can change as this report is updated."
            ))
        elif report_total is not None:
            items.append((
                f"What is {movie_name}'s worldwide box office collection?",
                f"The BoxOfficeX report currently lists {cr(report_total)} as the worldwide collection."
            ))
        if rights is not None:
            answer = f"The reported theatrical rights value used by this BoxOfficeX report is {cr(rights)}."
            if share is not None:
                answer += f" The report currently estimates theatrical share at {cr(share)}."
            items.append((f"What are {movie_name}'s reported theatrical rights?", answer))
        if next_label and remaining is not None:
            items.append((
                f"How much more gross does {movie_name} need to reach {next_label}?",
                f"Based on the current BoxOfficeX tracking model, {cr(remaining)} more gross is needed to reach the {next_label} level."
            ))
        elif level:
            items.append((
                f"What is {movie_name}'s current box office performance level?",
                f"The current BoxOfficeX tracking model shows {level} as the estimated performance level."
            ))

    # Normal editorial articles still get useful, source-grounded FAQ only when
    # the article itself supplies enough metadata to answer it.
    category = str(article.get("category") or "").strip()
    if not items and category:
        items.append((
            f"What does this {movie_name} article cover?",
            f"This BoxOfficeX article is filed under {category} and covers the information presented in the report above."
        ))

    return items[:4]


def _article_seo_faq_html(article):
    items = _article_seo_faq_items(article)
    if not items:
        return ""
    rows = []
    for index, (question, answer) in enumerate(items):
        open_attr = " open" if index == 0 else ""
        rows.append(
            f'<details{open_attr}><summary>{html_escape(question)}</summary>'
            f'<p>{html_escape(answer)}</p></details>'
        )
    return (
        '<section class="bx-article-seo-faq" data-ssr="1" aria-labelledby="bxArticleFaqHeading">'
        '<h2 id="bxArticleFaqHeading">Frequently Asked Questions</h2>'
        f'{"".join(rows)}</section>'
    )


def _article_breadcrumb_schema(article, canonical):
    return {
        "@type": "BreadcrumbList",
        "itemListElement": [
            {
                "@type": "ListItem",
                "position": 1,
                "name": "Home",
                "item": "https://boxofficex.in/",
            },
            {
                "@type": "ListItem",
                "position": 2,
                "name": "Articles",
                "item": "https://boxofficex.in/articles.html",
            },
            {
                "@type": "ListItem",
                "position": 3,
                "name": str(article.get("title") or "Article"),
                "item": canonical,
            },
        ],
    }


def _article_faq_schema(article):
    items = _article_seo_faq_items(article)
    if not items:
        return None
    return {
        "@type": "FAQPage",
        "mainEntity": [
            {
                "@type": "Question",
                "name": question,
                "acceptedAnswer": {"@type": "Answer", "text": answer},
            }
            for question, answer in items
        ],
    }


def _render_article_detail_html(slug):
    response = get_article(slug)
    article = response.get("article") if isinstance(response, dict) else None
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    # Box Office Tracking articles get generated H1/search metadata from the same
    # stored report + theatrical calculations rendered on this page.
    article, _generated_tracking_seo = _article_apply_tracking_ctr(article)

    article_file = BASE_DIR / "article.html"
    if not article_file.is_file():
        raise HTTPException(status_code=500, detail="article.html not found")
    template = article_file.read_text(encoding="utf-8")

    title = str(article.get("title") or "BoxOfficeX Article")
    seo_title = str(article.get("meta_title") or title).strip()
    if "boxofficex" not in seo_title.lower():
        seo_title += " | BoxOfficeX"
    description = str(
        article.get("meta_description")
        or article.get("subtitle")
        or "Read the latest movie, box office and entertainment stories on BoxOfficeX."
    ).strip()
    # Final SEO-output normalization. The same value feeds meta description,
    # Open Graph, Twitter and NewsArticle structured data.
    title = _article_normalize_seo_text(title)
    seo_title = _article_normalize_seo_text(seo_title)
    description = _article_normalize_seo_text(description)
    canonical = f"https://boxofficex.in/article/{article['slug']}"
    author = str(article.get("author") or "BoxOfficeX")
    category = str(article.get("category") or "Movies & Box Office")
    hero = _article_ssr_image(article.get("hero_image"))
    hero_abs = hero if hero.startswith(("http://", "https://")) else f"https://boxofficex.in{hero}"

    published = article.get("published_at") or article.get("created_at")
    modified = article.get("updated_at") or published
    published_iso = published.isoformat() if hasattr(published, "isoformat") else str(published or "")
    modified_iso = modified.isoformat() if hasattr(modified, "isoformat") else str(modified or "")

    replacements = {
        '<title id="pageTitle">Article | BoxOfficeX</title>':
            f'<title id="pageTitle">{html_escape(seo_title)}</title>',
        '<meta id="metaDescription" name="description" content="Read the latest movie, box office and entertainment stories on BoxOfficeX.">':
            f'<meta id="metaDescription" name="description" content="{html_escape(description, quote=True)}">',
        '<meta name="robots" content="index, follow">':
            '<meta name="robots" content="index, follow, max-image-preview:large">',
        '<link id="canonicalUrl" rel="canonical" href="">':
            f'<link id="canonicalUrl" rel="canonical" href="{html_escape(canonical, quote=True)}">',
        '<meta id="ogTitle" property="og:title" content="BoxOfficeX Article">':
            f'<meta id="ogTitle" property="og:title" content="{html_escape(seo_title, quote=True)}">',
        '<meta id="ogDescription" property="og:description" content="">':
            f'<meta id="ogDescription" property="og:description" content="{html_escape(description, quote=True)}">',
        '<meta id="ogImage" property="og:image" content="">':
            f'<meta id="ogImage" property="og:image" content="{html_escape(hero_abs, quote=True)}">',
        '<meta id="ogUrl" property="og:url" content="">':
            f'<meta id="ogUrl" property="og:url" content="{html_escape(canonical, quote=True)}">',
        '<meta id="twitterTitle" name="twitter:title" content="BoxOfficeX Article">':
            f'<meta id="twitterTitle" name="twitter:title" content="{html_escape(seo_title, quote=True)}">',
        '<meta id="twitterDescription" name="twitter:description" content="Read the latest movie and box-office stories on BoxOfficeX.">':
            f'<meta id="twitterDescription" name="twitter:description" content="{html_escape(description, quote=True)}">',
        '<meta id="twitterImage" name="twitter:image" content="">':
            f'<meta id="twitterImage" name="twitter:image" content="{html_escape(hero_abs, quote=True)}">',
        '<meta id="articleAuthorMeta" name="author" content="BoxOfficeX">':
            f'<meta id="articleAuthorMeta" name="author" content="{html_escape(author, quote=True)}">',
        '<meta id="articlePublishedMeta" property="article:published_time" content="">':
            f'<meta id="articlePublishedMeta" property="article:published_time" content="{html_escape(published_iso, quote=True)}">',
        '<meta id="articleModifiedMeta" property="article:modified_time" content="">':
            f'<meta id="articleModifiedMeta" property="article:modified_time" content="{html_escape(modified_iso, quote=True)}">',
        '<meta id="articleSectionMeta" property="article:section" content="Movies & Box Office">':
            f'<meta id="articleSectionMeta" property="article:section" content="{html_escape(category, quote=True)}">',
    }
    for old, new in replacements.items():
        template = template.replace(old, new, 1)

    # Final robust SEO-head pass. Match by stable tag IDs/attributes instead of
    # depending on the placeholder text currently stored in article.html.
    safe_seo_title = html_escape(seo_title, quote=True)
    safe_description = html_escape(description, quote=True)
    safe_canonical = html_escape(canonical, quote=True)
    safe_hero_abs = html_escape(hero_abs, quote=True)

    article_head_replacements = (
        (
            r"<title\b(?=[^>]*\bid=[\"']pageTitle[\"'])[^>]*>.*?</title>",
            f'<title id="pageTitle">{safe_seo_title}</title>',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']metaDescription[\"'])(?=[^>]*\bname=[\"']description[\"'])[^>]*>",
            f'<meta id="metaDescription" name="description" content="{safe_description}">',
        ),
        (
            r"<link\b(?=[^>]*\bid=[\"']canonicalUrl[\"'])(?=[^>]*\brel=[\"']canonical[\"'])[^>]*>",
            f'<link id="canonicalUrl" rel="canonical" href="{safe_canonical}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']ogTitle[\"'])(?=[^>]*\bproperty=[\"']og:title[\"'])[^>]*>",
            f'<meta id="ogTitle" property="og:title" content="{safe_seo_title}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']ogDescription[\"'])(?=[^>]*\bproperty=[\"']og:description[\"'])[^>]*>",
            f'<meta id="ogDescription" property="og:description" content="{safe_description}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']ogUrl[\"'])(?=[^>]*\bproperty=[\"']og:url[\"'])[^>]*>",
            f'<meta id="ogUrl" property="og:url" content="{safe_canonical}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']ogImage[\"'])(?=[^>]*\bproperty=[\"']og:image[\"'])[^>]*>",
            f'<meta id="ogImage" property="og:image" content="{safe_hero_abs}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']twitterTitle[\"'])(?=[^>]*\bname=[\"']twitter:title[\"'])[^>]*>",
            f'<meta id="twitterTitle" name="twitter:title" content="{safe_seo_title}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']twitterDescription[\"'])(?=[^>]*\bname=[\"']twitter:description[\"'])[^>]*>",
            f'<meta id="twitterDescription" name="twitter:description" content="{safe_description}">',
        ),
        (
            r"<meta\b(?=[^>]*\bid=[\"']twitterImage[\"'])(?=[^>]*\bname=[\"']twitter:image[\"'])[^>]*>",
            f'<meta id="twitterImage" name="twitter:image" content="{safe_hero_abs}">',
        ),
    )

    for pattern, replacement_value in article_head_replacements:
        template, replaced = re.subn(
            pattern,
            lambda _match, value=replacement_value: value,
            template,
            count=1,
            flags=re.I | re.S,
        )
        if replaced != 1:
            raise RuntimeError(
                f"Article SSR SEO head injection failed for pattern: {pattern}"
            )

    structured = {
        "@type": "NewsArticle",
        "headline": title,
        "description": description,
        "mainEntityOfPage": {"@type": "WebPage", "@id": canonical},
        "url": canonical,
        "image": [hero_abs],
        "author": {"@type": "Organization", "name": author},
        "publisher": {"@type": "Organization", "name": "BoxOfficeX", "url": "https://boxofficex.in"},
        "articleSection": category,
    }
    if published_iso:
        structured["datePublished"] = published_iso
    if modified_iso:
        structured["dateModified"] = modified_iso

    graph = [
        structured,
        _article_breadcrumb_schema(article, canonical),
    ]
    faq_schema = _article_faq_schema(article)
    if faq_schema:
        graph.append(faq_schema)

    structured_json = json.dumps(
        {"@context": "https://schema.org", "@graph": graph},
        ensure_ascii=False,
        separators=(",", ":"),
    ).replace("</", "<\\/")
    template = re.sub(
        r'<script\s+id="articleStructuredData"\s+type="application/ld\+json"\s*>.*?</script>',
        f'<script id="articleStructuredData" type="application/ld+json">{structured_json}</script>',
        template, count=1, flags=re.S | re.I,
    )

    # Tracking OFF means the temporary Live Tracker is no longer public.
    # Keep the block stored in Admin/DB so it can be turned back ON later.
    # The permanent Box Office Report and FINAL/FROZEN SEO snapshot remain intact.
    public_blocks = [
        block for block in (article.get("blocks") or [])
        if not (
            not bool(article.get("tracking_enabled", True))
            and str(block.get("block_type") or "").strip().lower() == "live_tracker"
        )
    ]

    block_html = [_article_ssr_block(block, article=article) for block in public_blocks]
    faq_html = _article_seo_faq_html(article)

    if block_html:
        length = len(block_html)
        for slot, fraction in ((3, .82), (2, .55), (1, .25)):
            at = max(1, min(length, int(math.ceil(length * fraction))))
            block_html.insert(at, f'<section id="bxSmartAdSlot{slot}" class="bx-smart-ad-slot" aria-label="Advertisement slot {slot}"></section>')
    if faq_html:
        block_html.append(faq_html)

    subtitle = str(article.get("subtitle") or "")
    caption = str(article.get("hero_caption") or "")
    credit = str(article.get("hero_credit") or "")
    hero_caption = ""
    if caption or credit:
        hero_caption = (
            '<figcaption class="media-caption">' + html_escape(caption)
            + (f'<span class="media-credit"> • {html_escape(credit)}</span>' if credit else "")
            + "</figcaption>"
        )

    body = f"""
<main id="app" data-ssr="1">
<article class="article-shell">
<div class="article-top">
<span class="category">{html_escape(category)}</span>
<h1>{html_escape(title)}</h1>
{f'<div class="subtitle">{html_escape(subtitle)}</div>' if subtitle else ''}
<div class="byline-row"><div class="byline">
By <strong>{html_escape(author)}</strong>
{f' • Published {_article_ssr_format_date(published)}' if published else ''}
{f'<span class="article-updated-time"> • Updated {_article_ssr_format_date(modified)}</span>' if modified else ''}
{(
    f'<span class="article-view-count" id="articleViewCount">👁 {int(article.get("views") or 0):,} Views</span>'
    if SHOW_PUBLIC_ARTICLE_VIEWS
    else '<span class="article-view-count" id="articleViewCount" hidden aria-hidden="true"></span>'
)}
</div></div>
<figure class="hero-wrap">
<img src="{html_escape(hero, quote=True)}" alt="{html_escape(caption or title, quote=True)}" loading="lazy">
{hero_caption}
</figure>
</div>
<section id="bxArticleDetailAd" aria-label="Sponsored advertisement"></section>
<div class="article-layout"><div class="article-content">
{"".join(block_html)}
{_article_ssr_explore_more(article)}
<div class="article-end">BoxOfficeX • Movie box office, entertainment news and career data</div>
</div></div>
</article>
</main>"""

    # Inject SSR into the current article shell without depending on the exact
    # loading-placeholder text/whitespace. article.html has evolved over time,
    # so matching only <main id="app">...</main> is substantially more robust.
    shell_pattern = re.compile(
        r'<main\b(?=[^>]*\bid=["\']app["\'])[^>]*>.*?</main>',
        re.S | re.I,
    )
    template, count = shell_pattern.subn(lambda _match: body, template, count=1)

    if count != 1:
        raise RuntimeError("Article SSR app-shell injection failed: #app main shell not found")

    payload = dict(article)
    # Client enhancement must receive the same public block set as SSR.
    # Otherwise JS could re-insert a Live Tracker that SSR intentionally hid.
    payload["blocks"] = public_blocks
    for key in ("published_at", "created_at", "updated_at"):
        value = payload.get(key)
        if hasattr(value, "isoformat"):
            payload[key] = value.isoformat()
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).replace("</", "<\\/")
    template = template.replace(
        "</head>",
        f'<script>window.__BOXOFFICEX_ARTICLE_SSR_DATA__={payload_json};</script>\n</head>',
        1,
    )

    if 'id="app" data-ssr="1"' not in template:
        raise RuntimeError("Article SSR validation failed")
    if "<h1>" not in template:
        raise RuntimeError("Article SSR H1 validation failed")
    return template


@app.get("/article.html", include_in_schema=False)
def article_page(slug: Optional[str] = None):
    if not slug:
        return RedirectResponse(url="/articles.html", status_code=301)

    response = get_article(slug)
    article = response.get("article") if isinstance(response, dict) else None
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return RedirectResponse(url=f"/article/{article['slug']}", status_code=301)


def _refresh_article_detail_cache(slug: str):
    try:
        rendered = _render_article_detail_html(slug)
        now = time_module.monotonic()
        with _article_detail_cache_lock:
            _article_detail_html_cache[slug] = {
                "html": rendered,
                "expires_at": now + ARTICLE_DETAIL_HTML_CACHE_TTL,
                "stale_until": now + ARTICLE_DETAIL_HTML_CACHE_TTL + ARTICLE_DETAIL_HTML_STALE_TTL,
            }
    except Exception as exc:
        print(f"[Article SSR] refresh failed for {slug}: {exc}")
    finally:
        with _article_detail_cache_lock:
            _article_detail_refreshing.discard(slug)


def _start_article_detail_refresh(slug: str) -> bool:
    with _article_detail_cache_lock:
        if slug in _article_detail_refreshing:
            return False
        _article_detail_refreshing.add(slug)

    threading.Thread(
        target=_refresh_article_detail_cache,
        args=(slug,),
        daemon=True,
        name=f"article-ssr-{slug[:40]}",
    ).start()
    return True


def _article_detail_headers(state: str):
    return {
        # Revalidate public article HTML on every request. The server-side
        # article cache still keeps rendering fast, while SEO/live values do
        # not remain stale in browsers/CDNs after an update or deploy.
        "Cache-Control": "no-cache, max-age=0, must-revalidate",
        "X-BoxOfficeX-Article": "ssr",
        "X-BoxOfficeX-Cache": state,
        "X-BoxOfficeX-Article-SEO": "v1-capitalization-unified",
    }


@app.get("/article/{slug}", response_class=HTMLResponse)
def article_pretty_page(slug: str):
    now = time_module.monotonic()

    with _article_detail_cache_lock:
        cached = _article_detail_html_cache.get(slug)
        if cached and cached.get("expires_at", 0) > now:
            return HTMLResponse(
                content=cached["html"],
                headers=_article_detail_headers("HIT"),
            )

        stale_html = None
        if cached and cached.get("html") and cached.get("stale_until", 0) > now:
            stale_html = cached["html"]

    if stale_html is not None:
        _start_article_detail_refresh(slug)
        return HTMLResponse(
            content=stale_html,
            headers=_article_detail_headers("STALE"),
        )

    # Cold/fully-expired cache: render the complete article synchronously.
    # This guarantees that crawlers and first-time visitors receive the real
    # H1, article blocks, metadata and structured data in the initial HTML.
    try:
        rendered = _render_article_detail_html(slug)
        generated_at = time_module.monotonic()

        with _article_detail_cache_lock:
            _article_detail_html_cache[slug] = {
                "html": rendered,
                "expires_at": generated_at + ARTICLE_DETAIL_HTML_CACHE_TTL,
                "stale_until": generated_at + ARTICLE_DETAIL_HTML_CACHE_TTL + ARTICLE_DETAIL_HTML_STALE_TTL,
            }

        return HTMLResponse(
            content=rendered,
            headers=_article_detail_headers("MISS-RENDERED"),
        )

    except HTTPException:
        raise
    except Exception as exc:
        # Do not silently return a crawlable "Loading article..." page when SSR
        # fails. Log the exact renderer failure and return a server error so the
        # request can be retried after the underlying issue is fixed.
        print(
            "[Article SSR] cold render failed:",
            slug,
            type(exc).__name__,
            exc,
            flush=True,
        )
        raise HTTPException(
            status_code=500,
            detail="Article rendering failed",
        )


# BOXOFFICEX ARTICLES API
# ============================================================

@app.get("/articles")
@app.get("/articles")
def get_articles():
    """
    Public article listing.

    Keep this endpoint lightweight. For tracking articles, use the same public
    article resolver as the detail page so the generated H1 appears in cards.
    Only structurally likely tracking articles are enriched.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id,
                    a.title,
                    a.slug,
                    a.subtitle,
                    a.category,
                    a.author,
                    a.hero_image,
                    a.hero_caption,
                    a.hero_credit,
                    a.views,
                    a.published_at,
                    a.updated_at,
                    a.tracking_enabled,
                    a.final_h1,
                    a.final_subtitle,
                    EXISTS (
                        SELECT 1
                        FROM article_blocks lb
                        WHERE lb.article_id = a.id
                          AND lb.block_type = 'live_tracker'
                    ) AS has_live_tracker,
                    EXISTS (
                        SELECT 1
                        FROM article_blocks bb
                        WHERE bb.article_id = a.id
                          AND bb.block_type = 'boxoffice'
                    ) AS has_boxoffice
                FROM articles a
                WHERE a.status = 'published'
                ORDER BY a.published_at DESC NULLS LAST, a.id DESC
            """)
            rows = cur.fetchall()

    articles = []

    for r in rows:
        item = {
            "id": r[0],
            "title": r[1],
            "slug": r[2],
            "subtitle": r[3],
            "category": r[4],
            "author": r[5],
            "hero_image": r[6],
            "hero_caption": r[7],
            "hero_credit": r[8],
            "views": r[9],
            "published_at": r[10],
            "updated_at": r[11],
        }

        tracking_enabled = bool(r[12])
        final_h1 = str(r[13] or "").strip()
        final_subtitle = str(r[14] or "").strip()
        has_live_tracker = bool(r[15])
        has_boxoffice = bool(r[16])

        # FINAL/FROZEN tracking articles already have their public H1 snapshot.
        # No extra article-detail query is needed.
        if (not tracking_enabled) and final_h1:
            item["title"] = final_h1
            if final_subtitle:
                item["subtitle"] = final_subtitle

        # AUTO tracking articles need the current generated Day-N public H1.
        # get_article() already applies _article_apply_tracking_ctr(), so do NOT
        # apply the generator a second time here.
        elif tracking_enabled and has_live_tracker and has_boxoffice:
            try:
                resolved = get_article(str(item["slug"] or ""))
                public_article = (
                    resolved.get("article")
                    if isinstance(resolved, dict)
                    else None
                )
                if public_article:
                    item["title"] = (
                        public_article.get("title")
                        or item["title"]
                    )
                    item["subtitle"] = (
                        public_article.get("subtitle")
                        or item["subtitle"]
                    )
            except Exception as exc:
                # Listing must stay available even if one tracking article has
                # malformed tracking data.
                print(
                    "ARTICLES LIST TRACKING TITLE WARNING:",
                    item["id"],
                    item["slug"],
                    type(exc).__name__,
                    exc,
                    flush=True,
                )

        item["title"] = str(
            item.get("title") or "BoxOfficeX Article"
        ).strip()

        articles.append(item)

    return {"articles": articles}



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

                        COALESCE(a.views, 0)::bigint AS view_count,

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




# ============================================================
# ARTICLE BOX-OFFICE MILESTONE ANALYSIS
# Source of truth: article block_type="boxoffice" extra_data only.
# The public Live Tracker is intentionally NOT used here.
# ============================================================

BOXOFFICEX_MILESTONE_STEP = 50
BOXOFFICEX_MILESTONE_AREAS = (
    "tamil_nadu",
    "kerala",
    "karnataka",
    "telugu_states",
    "rest_of_india",
    "overseas",
)


@app.on_event("startup")
def initialize_article_boxoffice_milestones():
    """Idempotent storage for first-crossing milestone snapshots."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS article_boxoffice_milestones (
                    id BIGSERIAL PRIMARY KEY,
                    article_id BIGINT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                    block_id BIGINT NOT NULL REFERENCES article_blocks(id) ON DELETE CASCADE,
                    movie_id BIGINT REFERENCES movies(id) ON DELETE SET NULL,
                    milestone_amount NUMERIC(12,2) NOT NULL,
                    detected_gross NUMERIC(12,2) NOT NULL,
                    stage TEXT NOT NULL,
                    stage_label TEXT,
                    tamil_nadu NUMERIC(12,2),
                    kerala NUMERIC(12,2),
                    karnataka NUMERIC(12,2),
                    telugu_states NUMERIC(12,2),
                    rest_of_india NUMERIC(12,2),
                    india NUMERIC(12,2),
                    overseas NUMERIC(12,2),
                    worldwide NUMERIC(12,2),
                    is_historical_initialization BOOLEAN NOT NULL DEFAULT FALSE,
                    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (article_id, block_id, milestone_amount)
                )
            """)
            # Safe migration for databases created before historical/genuine
            # milestone snapshots were separated.
            cur.execute("""
                ALTER TABLE article_boxoffice_milestones
                ADD COLUMN IF NOT EXISTS is_historical_initialization
                BOOLEAN NOT NULL DEFAULT FALSE
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_article_boxoffice_milestones_article
                ON article_boxoffice_milestones(article_id, block_id, milestone_amount)
            """)
        conn.commit()


def _bo_number(value):
    """Return a non-negative float or 0. Missing regional data stays distinguishable elsewhere."""
    try:
        if value is None or value == "":
            return 0.0
        number = float(str(value).replace(",", "").strip())
        return number if math.isfinite(number) and number >= 0 else 0.0
    except (TypeError, ValueError):
        return 0.0


def _bo_has_positive(value):
    return _bo_number(value) > 0


def _bo_sum_rows(rows):
    totals = {key: 0.0 for key in BOXOFFICEX_MILESTONE_AREAS}
    present = {key: False for key in BOXOFFICEX_MILESTONE_AREAS}

    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in BOXOFFICEX_MILESTONE_AREAS:
            # Missing/null/blank is not converted into a reported zero territory.
            raw = row.get(key)
            if raw is not None and str(raw).strip() != "":
                value = _bo_number(raw)
                totals[key] += value
                if value > 0:
                    present[key] = True

    totals["india"] = sum(totals[k] for k in (
        "tamil_nadu", "kerala", "karnataka", "telugu_states", "rest_of_india"
    ))
    totals["worldwide"] = totals["india"] + totals["overseas"]
    totals["present"] = present
    return totals


def _bo_stage_for_rows(rows, *, advance=False):
    if advance:
        day_numbers = [
            int(_bo_number(row.get("number")))
            for row in rows if isinstance(row, dict) and _bo_number(row.get("number")) > 0
        ]
        if day_numbers:
            n = max(day_numbers)
            return "ADVANCE", f"DAY {n} ADVANCE"
        return "ADVANCE", "ADVANCE BOOKING"

    regular = [
        int(_bo_number(row.get("number")))
        for row in rows
        if isinstance(row, dict)
        and str(row.get("type") or "REGULAR").upper() != "PREVIEW"
        and str(row.get("status") or "").upper() != "ADVANCE"
        and _bo_number(row.get("number")) > 0
    ]
    if regular:
        n = max(regular)
        return f"DAY_{n}", f"DAY {n}"

    if any(
        isinstance(row, dict)
        and str(row.get("type") or "REGULAR").upper() == "PREVIEW"
        for row in rows
    ):
        return "PREMIERE", "PREVIEW / PREMIERE"

    return "BOX_OFFICE", "BOX OFFICE"


def _capture_article_boxoffice_milestones(cur, article_id: int):
    """Rebuild ₹50 Cr milestone snapshots from CURRENT admin box-office data.

    article_blocks.extra_data is the only source of truth. Every admin add/edit/delete
    rebuilds this derived table, so corrected or removed values cannot leave stale
    milestones behind.
    """
    cur.execute("""
        SELECT movie_id
        FROM article_movies
        WHERE article_id=%s
        ORDER BY movie_id
    """, (article_id,))
    movie_ids = [int(r[0]) for r in cur.fetchall()]
    movie_id = movie_ids[0] if len(movie_ids) == 1 else None

    cur.execute("""
        SELECT id, extra_data
        FROM article_blocks
        WHERE article_id=%s AND block_type='boxoffice'
        ORDER BY block_order, id
    """, (article_id,))
    blocks = cur.fetchall()

    # Milestones are derived/cache data. Remove the previous derivation first.
    cur.execute("""
        DELETE FROM article_boxoffice_milestones
        WHERE article_id=%s
    """, (article_id,))

    def snapshot_values(totals):
        return (
            totals["tamil_nadu"] if totals["present"]["tamil_nadu"] else None,
            totals["kerala"] if totals["present"]["kerala"] else None,
            totals["karnataka"] if totals["present"]["karnataka"] else None,
            totals["telugu_states"] if totals["present"]["telugu_states"] else None,
            totals["rest_of_india"] if totals["present"]["rest_of_india"] else None,
            totals["india"] if totals["india"] > 0 else None,
            totals["overseas"] if totals["present"]["overseas"] else None,
            totals["worldwide"] if totals["worldwide"] > 0 else None,
        )

    def insert_crossings(block_id, rows, *, advance, already_saved):
        # Rebuild progression one currently-saved admin row at a time. This lets
        # ₹50, ₹100, ... keep the values of the first CURRENT row that crosses them.
        running_rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            running_rows.append(row)
            totals = _bo_sum_rows(running_rows)
            gross = float(totals["worldwide"] or 0)
            if gross < BOXOFFICEX_MILESTONE_STEP:
                continue

            highest = int(gross // BOXOFFICEX_MILESTONE_STEP) * BOXOFFICEX_MILESTONE_STEP
            stage, stage_label = _bo_stage_for_rows(running_rows, advance=advance)

            for milestone in range(BOXOFFICEX_MILESTONE_STEP, highest + 1, BOXOFFICEX_MILESTONE_STEP):
                if milestone in already_saved:
                    continue
                areas = snapshot_values(totals)
                cur.execute("""
                    INSERT INTO article_boxoffice_milestones (
                        article_id, block_id, movie_id,
                        milestone_amount, detected_gross,
                        stage, stage_label,
                        tamil_nadu, kerala, karnataka, telugu_states,
                        rest_of_india, india, overseas, worldwide,
                        is_historical_initialization
                    )
                    VALUES (
                        %s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,%s,%s,FALSE
                    )
                    ON CONFLICT (article_id, block_id, milestone_amount) DO UPDATE SET
                        movie_id=EXCLUDED.movie_id,
                        detected_gross=EXCLUDED.detected_gross,
                        stage=EXCLUDED.stage,
                        stage_label=EXCLUDED.stage_label,
                        tamil_nadu=EXCLUDED.tamil_nadu,
                        kerala=EXCLUDED.kerala,
                        karnataka=EXCLUDED.karnataka,
                        telugu_states=EXCLUDED.telugu_states,
                        rest_of_india=EXCLUDED.rest_of_india,
                        india=EXCLUDED.india,
                        overseas=EXCLUDED.overseas,
                        worldwide=EXCLUDED.worldwide,
                        is_historical_initialization=FALSE,
                        detected_at=NOW()
                """, (
                    article_id, int(block_id), movie_id,
                    milestone, gross, stage, stage_label,
                    *areas,
                ))
                already_saved.add(milestone)

    for block_id, extra in blocks:
        extra = extra or {}
        days = extra.get("days") if isinstance(extra, dict) else None
        if not isinstance(days, list) or not days:
            continue

        # Status decides whether a row is ADVANCE, regardless of PREVIEW/REGULAR type.
        # A future Preview/Premiere row can therefore be ADVANCE without being
        # misclassified as earned premiere gross.
        advance_rows = [
            d for d in days
            if isinstance(d, dict)
            and str(d.get("status") or "").upper() == "ADVANCE"
        ]
        earned_rows = [
            d for d in days
            if isinstance(d, dict)
            and str(d.get("status") or "").upper() != "ADVANCE"
        ]

        saved = set()
        # Advance is its own progression and is never added to earned gross.
        insert_crossings(block_id, advance_rows, advance=True, already_saved=saved)
        # Earned/premiere progression is independently cumulative. Milestones
        # already reached during advance are not duplicated.
        insert_crossings(block_id, earned_rows, advance=False, already_saved=saved)

# ============================================================
# BOXOFFICEX ESTIMATED THEATRICAL PERFORMANCE
# Gross-based editorial model. Advance booking is excluded.
# ============================================================

BOXOFFICEX_THEATRICAL_LEVELS = (
    ("AVERAGE", "Average", 1.50),
    ("ABOVE_AVERAGE", "Above Average", 1.75),
    ("BREAK_EVEN", "Break-even", 2.00),
    ("HIT", "Hit", 2.25),
    ("SUPER_HIT", "Super Hit", 2.75),
    ("BLOCKBUSTER", "Blockbuster", 3.50),
    ("ATB", "ATB", 5.00),
)

BOXOFFICEX_THEATRICAL_REGIONS = (
    ("tamil_nadu", "theatrical_tamil_nadu", "Tamil Nadu"),
    ("kerala", "theatrical_kerala", "Kerala"),
    ("karnataka", "theatrical_karnataka", "Karnataka"),
    ("telugu_states", "theatrical_telugu_states", "AP & Telangana"),
    ("rest_of_india", "theatrical_rest_of_india", "Rest of India"),
    ("overseas", "theatrical_overseas", "Overseas"),
)

# Editorial estimation assumptions used only for the public explanatory metrics.
# India: tax-inclusive gross -> estimated net using 18% GST assumption, then
# estimated theatrical/distributor share at 50% of net.
# Overseas: tax/settlement structures vary by country, so BoxOfficeX uses a
# simplified 100% gross-to-net display basis and 40% estimated theatrical share.
BOXOFFICEX_INDIA_GST_RATE = 0.18
BOXOFFICEX_INDIA_SHARE_OF_NET = 0.50
BOXOFFICEX_OVERSEAS_NET_FACTOR = 1.00
BOXOFFICEX_OVERSEAS_SHARE_OF_NET = 0.40


def _bo_estimated_net_share(gross: float, region_key: str):
    current_gross = _bo_number(gross)
    if current_gross <= 0:
        return {
            "estimated_net": 0.0,
            "estimated_theatrical_share": 0.0,
        }

    if region_key == "overseas":
        estimated_net = current_gross * BOXOFFICEX_OVERSEAS_NET_FACTOR
        share_rate = BOXOFFICEX_OVERSEAS_SHARE_OF_NET
    else:
        estimated_net = current_gross / (1.0 + BOXOFFICEX_INDIA_GST_RATE)
        share_rate = BOXOFFICEX_INDIA_SHARE_OF_NET

    return {
        "estimated_net": round(estimated_net, 2),
        "estimated_theatrical_share": round(estimated_net * share_rate, 2),
    }


def _bo_theatrical_level(gross: float, theatrical_value: float):
    """Calculate the locked BoxOfficeX estimated gross/theatrical-value level."""
    value = _bo_number(theatrical_value)
    current_gross = _bo_number(gross)

    if value <= 0:
        return None

    multiple = current_gross / value

    current_key = "FLOP"
    current_label = "Flop"
    current_threshold = 0.0

    for key, label, threshold in BOXOFFICEX_THEATRICAL_LEVELS:
        if multiple >= threshold:
            current_key = key
            current_label = label
            current_threshold = threshold
        else:
            break

    next_level = None
    for key, label, threshold in BOXOFFICEX_THEATRICAL_LEVELS:
        if threshold > multiple:
            target_gross = value * threshold
            remaining = max(0.0, target_gross - current_gross)
            progress = (current_gross / target_gross * 100.0) if target_gross > 0 else 0.0
            next_level = {
                "key": key,
                "label": label,
                "multiple": threshold,
                "target_gross": round(target_gross, 2),
                "remaining": round(remaining, 2),
                "progress_percent": round(min(100.0, max(0.0, progress)), 2),
            }
            break

    return {
        "gross": round(current_gross, 2),
        "theatrical_value": round(value, 2),
        "multiple": round(multiple, 2),
        "current_level": {
            "key": current_key,
            "label": current_label,
            "minimum_multiple": current_threshold,
        },
        "next_level": next_level,
        "atb_achieved": multiple >= 4.0,
    }


def _bo_theatrical_performance(extra):
    """Build current estimated performance from CURRENT admin Box Office extra_data.

    Rules:
    - ADVANCE rows never count as earned gross.
    - Each region is calculated only when that region has a positive reported
      theatrical value.
    - Combined available-markets performance appears only when 2+ regions have
      theatrical values.
    - Combined gross uses exactly the same markets as the combined theatrical value.
    - No historical values are retained here; edits/deletes recalculate immediately.
    """
    if not isinstance(extra, dict):
        return None

    days = extra.get("days")
    if not isinstance(days, list):
        days = []

    earned_rows = [
        row for row in days
        if isinstance(row, dict)
        and str(row.get("status") or "").upper() != "ADVANCE"
    ]
    earned = _bo_sum_rows(earned_rows)

    # Public verdict gating:
    # Day 1-7 is recovery tracking only. Do not call a film Flop/Average/Hit
    # while the first theatrical week is still developing.
    regular_day_numbers = []
    for row in earned_rows:
        if str(row.get("type") or "REGULAR").upper() == "PREVIEW":
            continue
        try:
            number = int(row.get("number"))
        except (TypeError, ValueError):
            continue
        if number > 0:
            regular_day_numbers.append(number)

    current_run_day = max(regular_day_numbers, default=1)
    if current_run_day <= 2:
        run_stage = {
            "key": "OPENING_PHASE",
            "label": "Opening Phase",
            "day": current_run_day,
            "verdict_enabled": False,
        }
    elif current_run_day <= 4:
        run_stage = {
            "key": "EARLY_RUN",
            "label": "Early Run Tracking",
            "day": current_run_day,
            "verdict_enabled": False,
        }
    elif current_run_day <= 7:
        run_stage = {
            "key": "FIRST_WEEK",
            "label": "First Week Tracking",
            "day": current_run_day,
            "verdict_enabled": False,
        }
    else:
        run_stage = {
            "key": "ESTIMATED_PERFORMANCE",
            "label": "Estimated Performance",
            "day": current_run_day,
            "verdict_enabled": True,
        }

    regions = {}
    available_keys = []

    for gross_key, value_key, label in BOXOFFICEX_THEATRICAL_REGIONS:
        theatrical_value = _bo_number(extra.get(value_key))
        if theatrical_value <= 0:
            continue

        gross = _bo_number(earned.get(gross_key))
        regions[gross_key] = {
            "key": gross_key,
            "label": label,
            **_bo_theatrical_level(gross, theatrical_value),
            **_bo_estimated_net_share(gross, gross_key),
        }
        available_keys.append((gross_key, value_key))

    combined = None
    if len(available_keys) >= 2:
        combined_value = sum(_bo_number(extra.get(value_key)) for _, value_key in available_keys)

        # IMPORTANT: Combined/current gross must come from the permanent
        # in-content Box Office Report WORLDWIDE TOTAL, not from summing only
        # territories that have a theatrical-rights value. A missing territory
        # rights value must not remove that territory's earned gross from the
        # movie's total performance gross.
        combined_gross = _bo_number(earned.get("worldwide"))

        # Estimate combined net/share from the complete Box Office Report totals:
        # India gross uses the existing India assumption; Overseas uses the
        # existing overseas assumption. This prevents missing rights fields from
        # silently dropping gross/share from the combined movie-level tracker.
        india_estimate = _bo_estimated_net_share(
            _bo_number(earned.get("india")),
            "india",
        )
        overseas_estimate = _bo_estimated_net_share(
            _bo_number(earned.get("overseas")),
            "overseas",
        )
        combined_net = (
            india_estimate["estimated_net"]
            + overseas_estimate["estimated_net"]
        )
        combined_share = (
            india_estimate["estimated_theatrical_share"]
            + overseas_estimate["estimated_theatrical_share"]
        )

        combined = {
            "label": "Available Markets",
            "market_count": len(available_keys),
            "markets": [gross_key for gross_key, _ in available_keys],
            **_bo_theatrical_level(combined_gross, combined_value),
            "estimated_net": round(combined_net, 2),
            "estimated_theatrical_share": round(combined_share, 2),
        }

    budget = _bo_number(extra.get("budget"))
    budget_tracker = None
    if budget > 0:
        current_worldwide = _bo_number(earned.get("worldwide"))
        budget_tracker = {
            "reported_budget": round(budget, 2),
            "worldwide_gross": round(current_worldwide, 2),
            "gross_budget_multiple": round(current_worldwide / budget, 2),
            "gross_budget_percent": round(current_worldwide / budget * 100.0, 2),
        }

    if not regions and not budget_tracker:
        return None

    return {
        "model": "BOXOFFICEX_ESTIMATED_THEATRICAL_PERFORMANCE_V1",
        "earned_worldwide_gross": round(_bo_number(earned.get("worldwide")), 2),
        "advance_excluded": True,
        "run_stage": run_stage,
        "budget": budget_tracker,
        "combined": combined,
        "regions": regions,
        "disclaimer": (
            "Theatrical values, distribution rights, distributor shares and territory-wise "
            "recovery figures are based on available industry reports and estimates. Actual "
            "commercial agreements, revenue shares and final settlements are private financial "
            "information known fully only to the producers, distributors, exhibitors/theatre "
            "owners and other parties involved."
        ),
        "performance_note": (
            "BoxOfficeX performance labels are estimates based on reported theatrical values "
            "and available box-office gross. Estimated net and theatrical share are editorial "
            "calculations, not official settlements. India net uses an 18% GST assumption and "
            "theatrical share uses 50% of estimated net. Overseas uses a simplified 40% share "
            "assumption because taxes and settlement structures vary by market."
        ),
        "estimation_assumptions": {
            "india_gst_rate_percent": 18.0,
            "india_share_of_net_percent": 50.0,
            "overseas_net_factor_percent": 100.0,
            "overseas_share_of_net_percent": 40.0,
        },
    }


def _article_boxoffice_analysis_map(cur, article_id: int, movie_rows):
    """Return milestone + current theatrical analysis keyed by boxoffice block id."""
    movie_budget = None
    if len(movie_rows) == 1:
        cur.execute("SELECT budget_crore FROM movies WHERE id=%s", (movie_rows[0][0],))
        budget_row = cur.fetchone()
        if budget_row and budget_row[0] is not None and _bo_number(budget_row[0]) > 0:
            movie_budget = _bo_number(budget_row[0])

    # Initialize every current Box Office block, even when it has no ₹50 milestone yet.
    cur.execute("""
        SELECT id, extra_data
        FROM article_blocks
        WHERE article_id=%s AND block_type='boxoffice'
        ORDER BY block_order, id
    """, (article_id,))

    result = {}
    for block_id, extra in cur.fetchall():
        block_id = int(block_id)
        extra = extra or {}
        block_budget = _bo_number(extra.get("budget")) if isinstance(extra, dict) else 0.0
        result[block_id] = {
            "milestone_step": BOXOFFICEX_MILESTONE_STEP,
            "budget_crore": block_budget if block_budget > 0 else movie_budget,
            "milestones": [],
            "theatrical_performance": _bo_theatrical_performance(extra),
        }

    cur.execute("""
        SELECT
            block_id, milestone_amount, detected_gross, stage, stage_label,
            tamil_nadu, kerala, karnataka, telugu_states, rest_of_india,
            india, overseas, worldwide, detected_at,
            is_historical_initialization
        FROM article_boxoffice_milestones
        WHERE article_id=%s
        ORDER BY block_id, milestone_amount
    """, (article_id,))

    for row in cur.fetchall():
        block_id = int(row[0])
        item = result.setdefault(block_id, {
            "milestone_step": BOXOFFICEX_MILESTONE_STEP,
            "budget_crore": movie_budget,
            "milestones": [],
            "theatrical_performance": None,
        })
        item["milestones"].append({
            "milestone": float(row[1]),
            "detected_gross": float(row[2]),
            "stage": row[3],
            "stage_label": row[4],
            "areas": {
                "tamil_nadu": float(row[5]) if row[5] is not None else None,
                "kerala": float(row[6]) if row[6] is not None else None,
                "karnataka": float(row[7]) if row[7] is not None else None,
                "telugu_states": float(row[8]) if row[8] is not None else None,
                "rest_of_india": float(row[9]) if row[9] is not None else None,
                "india": float(row[10]) if row[10] is not None else None,
                "overseas": float(row[11]) if row[11] is not None else None,
                "worldwide": float(row[12]) if row[12] is not None else None,
            },
            "detected_at": row[13].isoformat() if row[13] else None,
            "is_historical_initialization": bool(row[14]),
        })

    return result


def _public_article_boxoffice_extra(extra):
    """
    Return Box Office extra_data with time-derived ADVANCE -> LIVE -> ESTIMATED_FINAL
    applied in memory. Does not publish FINAL and does not sync movie.html.
    """
    if not isinstance(extra, dict):
        return extra or {}

    result = dict(extra)
    result_days = []

    for raw_day in (extra.get("days") or []):
        if not isinstance(raw_day, dict):
            result_days.append(raw_day)
            continue

        day = dict(raw_day)
        raw_date = day.get("date")

        if raw_date:
            try:
                day_date = date.fromisoformat(str(raw_date))
                day["status"] = _boxoffice_tracking_status_for_day(
                    day_date,
                    str(day.get("status") or "LIVE"),
                )
            except ValueError:
                pass

        result_days.append(day)

    result["days"] = result_days
    return result


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
         "image":r[4],"image_caption":r[5],"image_credit":r[6],
         "extra_data":_public_article_boxoffice_extra(r[7] or {}) if r[2]=="boxoffice" else (r[7] or {})}
        for r in rows
    ]}


@app.get("/articles/{slug}")

def _article_tracker_seo_context(cur, movie_rows, actor_rows):
    """
    Build indexable tracker context from linked BoxOfficeX entities.

    Internal links are deliberately conservative:
    - actor comparisons use actors actually linked to the article;
    - movie comparisons use linked movies first, then recent movies sharing a
      linked actor;
    - movie comparison links respect the existing >= ₹25 Cr worldwide rule.
    """
    movies = []
    actors = []
    actor_comparisons = []
    movie_comparisons = []

    movie_slug_map = _unique_movie_slug_map()
    actor_slug_map = _unique_actor_slug_map()

    for row in movie_rows:
        movie_id = int(row[0])
        movies.append({
            "id": movie_id,
            "title": str(row[1] or "Movie"),
            "release_date": str(row[2]) if row[2] else None,
            "language": row[3],
            "industry": row[4],
            "url": f"/movie/{movie_slug_map[movie_id]}" if movie_id in movie_slug_map else "/new-movies.html",
        })

    for row in actor_rows:
        actor_id = int(row[0])
        actors.append({
            "id": actor_id,
            "name": str(row[1] or "Actor"),
            "url": f"/actor/{actor_slug_map[actor_id]}" if actor_id in actor_slug_map else "/actors.html",
        })

    # Actor comparison pages: only pairs of explicitly linked actors.
    for i in range(len(actors)):
        for j in range(i + 1, len(actors)):
            a, b = actors[i], actors[j]
            url = public_actor_comparison_url(a["id"], b["id"])
            if url == "/compare-select.html":
                continue
            actor_comparisons.append({
                "label": f'{a["name"]} vs {b["name"]} Box Office Comparison',
                "url": url,
            })
            if len(actor_comparisons) >= 3:
                break
        if len(actor_comparisons) >= 3:
            break

    linked_movie_ids = [m["id"] for m in movies]
    candidate_pairs = []

    # Prefer explicitly linked movie pairs.
    if len(linked_movie_ids) >= 2:
        for i in range(len(linked_movie_ids)):
            for j in range(i + 1, len(linked_movie_ids)):
                candidate_pairs.append((linked_movie_ids[i], linked_movie_ids[j]))

    # For the usual single-movie tracking article, find recent qualifying movies
    # sharing one of the linked actors.
    if len(linked_movie_ids) == 1:
        current_id = linked_movie_ids[0]
        linked_actor_ids = [a["id"] for a in actors]

        # If article actors are sparse, use the movie's actual cast links too.
        cur.execute("""
            SELECT DISTINCT actor_id
            FROM actor_movies
            WHERE movie_id=%s
            ORDER BY actor_id
        """, (current_id,))
        for row in cur.fetchall():
            aid = int(row[0])
            if aid not in linked_actor_ids:
                linked_actor_ids.append(aid)

        if linked_actor_ids:
            cur.execute("""
                SELECT DISTINCT m.id, m.title, m.release_date,
                                m.worldwide_collection_crore
                FROM actor_movies am
                JOIN movies m ON m.id=am.movie_id
                WHERE am.actor_id = ANY(%s)
                  AND m.id <> %s
                  AND m.worldwide_collection_crore IS NOT NULL
                  AND m.worldwide_collection_crore >= 25
                ORDER BY m.release_date DESC NULLS LAST, m.id DESC
                LIMIT 12
            """, (linked_actor_ids, current_id))
            for row in cur.fetchall():
                candidate_pairs.append((current_id, int(row[0])))

    # Validate both sides against the public movie-comparison rule and build labels.
    seen_urls = set()
    title_by_id = {m["id"]: m["title"] for m in movies}
    for first_id, second_id in candidate_pairs:
        if len(movie_comparisons) >= 3:
            break

        cur.execute("""
            SELECT id, title, worldwide_collection_crore
            FROM movies
            WHERE id IN (%s, %s)
        """, (first_id, second_id))
        rows = cur.fetchall()
        if len(rows) != 2:
            continue

        valid = True
        local_titles = {}
        for row in rows:
            try:
                gross = float(row[2])
            except (TypeError, ValueError):
                gross = 0
            if gross < 25:
                valid = False
                break
            local_titles[int(row[0])] = str(row[1] or "Movie")
        if not valid:
            continue

        url = public_movie_comparison_url(first_id, second_id)
        if url == "/movie-compare-select.html" or url in seen_urls:
            continue
        seen_urls.add(url)
        movie_comparisons.append({
            "label": f'{local_titles[first_id]} vs {local_titles[second_id]} Box Office Comparison',
            "url": url,
        })

    return {
        "movie": movies[0] if movies else None,
        "movies": movies,
        "actors": actors,
        "actor_comparisons": actor_comparisons,
        "movie_comparisons": movie_comparisons,
    }

def get_article(slug: str):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,title,slug,subtitle,category,author,hero_image,
                       hero_caption,hero_credit,status,meta_title,meta_description,
                       views,published_at,created_at,updated_at,
                       tracking_enabled,final_h1,final_subtitle,final_meta_title,
                       final_meta_description,tracking_finalized_at
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

            cur.execute("""
                SELECT m.id, m.title, m.release_date, m.language, m.industry
                FROM article_movies am
                JOIN movies m ON m.id = am.movie_id
                WHERE am.article_id = %s
                ORDER BY m.id
            """, (a[0],))
            movie_rows = cur.fetchall()
            movie_ids = [r[0] for r in movie_rows]

            cur.execute("""
                SELECT ac.id, ac.name
                FROM article_actors aa
                JOIN actors ac ON ac.id = aa.actor_id
                WHERE aa.article_id = %s
                ORDER BY ac.id
            """, (a[0],))
            actor_rows = cur.fetchall()
            actor_ids = [r[0] for r in actor_rows]

            boxoffice_analysis = _article_boxoffice_analysis_map(cur, a[0], movie_rows)
            tracker_seo_context = _article_tracker_seo_context(cur, movie_rows, actor_rows)
            for _analysis in boxoffice_analysis.values():
                if isinstance(_analysis, dict):
                    _analysis["tracker_seo"] = tracker_seo_context

    movie_slug_map = _unique_movie_slug_map()
    actor_slug_map = _unique_actor_slug_map()

    linked_movies = [
        {
            "id": r[0],
            "title": r[1],
            "release_date": r[2],
            "language": r[3],
            "industry": r[4],
            "url": f"/movie/{movie_slug_map[r[0]]}" if r[0] in movie_slug_map else "/new-movies.html",
        }
        for r in movie_rows
    ]
    linked_actors = [
        {
            "id": r[0],
            "name": r[1],
            "url": f"/actor/{actor_slug_map[r[0]]}" if r[0] in actor_slug_map else "/actors.html",
        }
        for r in actor_rows
    ]

    article = {
        "id":a[0],"title":a[1],"slug":a[2],"subtitle":a[3],
        "category":a[4],"author":a[5],"hero_image":a[6],
        "hero_caption":a[7],"hero_credit":a[8],"status":a[9],
        "meta_title":a[10],"meta_description":a[11],"views":a[12],
        "published_at":a[13],"created_at":a[14],"updated_at":a[15],
        "tracking_enabled":bool(a[16]),"final_h1":a[17],"final_subtitle":a[18],
        "final_meta_title":a[19],"final_meta_description":a[20],
        "tracking_finalized_at":a[21],
        "movie_ids":movie_ids,"actor_ids":actor_ids,
        "movies":linked_movies,"actors":linked_actors,
        "blocks":[
            {"id":r[0],"block_order":r[1],"block_type":r[2],"content":r[3],
             "image":r[4],"image_caption":r[5],"image_credit":r[6],
             "extra_data":(
                 {**_public_article_boxoffice_extra(r[7] or {}), "analysis": boxoffice_analysis.get(int(r[0]), {"milestone_step": BOXOFFICEX_MILESTONE_STEP, "budget_crore": None, "milestones": []})}
                 if r[2]=="boxoffice" else (r[7] or {})
             )}
            for r in blocks
        ]
    }

    # Public API and cached SSR must resolve the exact same article state.
    # Without this, the cold article shell fetched the raw Admin title/deck,
    # while the next cached SSR request used the generated tracking title.
    # That made two consecutive reloads show two different headlines.
    article, _generated_tracking_seo = _article_apply_tracking_ctr(article)

    # Tracking OFF keeps the Live Tracker stored for Admin/reuse, but it must
    # never be returned by the public API either. This keeps cold-shell JS
    # behavior identical to cached SSR behavior.
    if not bool(article.get("tracking_enabled", True)):
        article["blocks"] = [
            block for block in (article.get("blocks") or [])
            if str(block.get("block_type") or "").strip().lower() != "live_tracker"
        ]

    return {"article": article}



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
    # Box-office tracking lifecycle. Normal articles ignore this field.
    tracking_enabled: bool = True


class AdminArticleBlock(BaseModel):
    block_order: int
    block_type: str
    content: Optional[str] = None
    image: Optional[str] = None
    image_caption: Optional[str] = None
    image_credit: Optional[str] = None
    extra_data: dict[str, Any] = {}




class AdminArticleBlockSyncItem(BaseModel):
    id: Optional[int] = None
    block_order: int
    block_type: str
    content: Optional[str] = None
    image: Optional[str] = None
    image_caption: Optional[str] = None
    image_credit: Optional[str] = None
    extra_data: dict[str, Any] = {}


class AdminArticleBlocksSync(BaseModel):
    blocks: list[AdminArticleBlockSyncItem] = []
    deleted_block_ids: list[int] = []

class AdminArticleLink(BaseModel):
    movie_ids: list[int] = []
    actor_ids: list[int] = []


def normalize_article_slug(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value


def _article_is_live_boxoffice(title: str) -> bool:
    """Return True only for clearly identified live box-office articles."""
    value = re.sub(r"\s+", " ", str(title or "")).strip().lower()
    return "live" in value and "box office" in value


def _article_admin_seo_values(data):
    """
    SEO System V2.

    Article/H1 and search metadata are intentionally independent.
    This lets live box-office headlines change frequently without
    overwriting manually optimized evergreen SEO metadata.

    Fallbacks are used only when an SEO field is empty:
    - meta title -> article title
    - meta description -> subtitle, then article title
    """
    title = str(data.title or "").strip()
    subtitle = str(data.subtitle or "").strip()
    meta_title = str(data.meta_title or "").strip()
    meta_description = str(data.meta_description or "").strip()

    return (
        meta_title or title,
        meta_description or subtitle or title,
    )


def _invalidate_article_detail_cache(*slugs):
    """Invalidate only the affected per-article SSR cache entries."""
    clean = {str(slug or "").strip() for slug in slugs if str(slug or "").strip()}
    if not clean:
        return
    with _article_detail_cache_lock:
        for slug in clean:
            _article_detail_html_cache.pop(slug, None)


def _invalidate_article_detail_cache_by_id(article_id: int):
    """Resolve an article's current slug and invalidate its SSR detail cache."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT slug FROM articles WHERE id=%s", (article_id,))
                row = cur.fetchone()
        if row and row[0]:
            _invalidate_article_detail_cache(row[0])
    except Exception:
        # Cache invalidation must never turn a successful committed admin save
        # into an apparent content-save failure. At worst the normal cache TTL
        # remains the fallback.
        pass


def validate_article_status(value: str) -> str:
    allowed = {"draft", "published", "archived"}
    value = (value or "draft").lower().strip()
    if value not in allowed:
        raise HTTPException(status_code=400, detail="Invalid article status")
    return value


def validate_block_type(value: str) -> str:
    allowed = {
        "paragraph", "heading", "image", "quote", "gallery",
        "boxoffice", "movie", "actor", "video", "table", "live_tracker",
    }
    value = (value or "").lower().strip()
    if value not in allowed:
        raise HTTPException(status_code=400, detail="Invalid article block type")
    return value


@app.on_event("startup")
def ensure_article_tracking_lifecycle_columns():
    """Idempotent V10 storage for explicit AUTO vs FINAL/FROZEN article tracking."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.articles')")
            row = cur.fetchone()
            if not row or row[0] is None:
                return
            cur.execute("ALTER TABLE articles ADD COLUMN IF NOT EXISTS tracking_enabled BOOLEAN NOT NULL DEFAULT TRUE")
            cur.execute("ALTER TABLE articles ADD COLUMN IF NOT EXISTS final_h1 TEXT")
            cur.execute("ALTER TABLE articles ADD COLUMN IF NOT EXISTS final_subtitle TEXT")
            cur.execute("ALTER TABLE articles ADD COLUMN IF NOT EXISTS final_meta_title TEXT")
            cur.execute("ALTER TABLE articles ADD COLUMN IF NOT EXISTS final_meta_description TEXT")
            cur.execute("ALTER TABLE articles ADD COLUMN IF NOT EXISTS tracking_finalized_at TIMESTAMPTZ")
        conn.commit()
    print("ARTICLE TRACKING LIFECYCLE V10: READY", flush=True)


@app.on_event("startup")
def ensure_live_tracker_article_block_type():
    """
    One-time/idempotent schema compatibility check for the Live Tracker block.

    Older BoxOfficeX databases have article_blocks_type_check without
    'live_tracker'. Only replace that CHECK constraint when live_tracker is
    missing. Future app restarts leave an already-correct constraint alone.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            # Local/dev databases may not have article_blocks yet.
            cur.execute("SELECT to_regclass('public.article_blocks')")
            row = cur.fetchone()
            if not row or row[0] is None:
                return

            cur.execute("""
                SELECT pg_get_constraintdef(c.oid)
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = 'public'
                  AND t.relname = 'article_blocks'
                  AND c.conname = 'article_blocks_type_check'
                  AND c.contype = 'c'
                LIMIT 1
            """)
            constraint_row = cur.fetchone()
            constraint_def = constraint_row[0] if constraint_row else ""

            if "live_tracker" in constraint_def.lower():
                return

            cur.execute("""
                ALTER TABLE article_blocks
                DROP CONSTRAINT IF EXISTS article_blocks_type_check
            """)

            cur.execute("""
                ALTER TABLE article_blocks
                ADD CONSTRAINT article_blocks_type_check
                CHECK (
                    block_type IN (
                        'paragraph',
                        'heading',
                        'image',
                        'quote',
                        'gallery',
                        'boxoffice',
                        'movie',
                        'actor',
                        'video',
                        'table',
                        'live_tracker'
                    )
                )
            """)

        conn.commit()

    print("ARTICLE BLOCK MIGRATION: live_tracker is allowed")


@app.get("/admin/articles", dependencies=[Depends(require_admin)])
def admin_list_articles():
    """
    Admin article list used by the sidebar and Draft Manager.

    Important:
    Return movie_ids and actor_ids here too. Reuse/future-draft creation
    already copies article_movies/article_actors in the database; exposing
    those links in this list response lets Draft Manager group generated
    drafts under the correct linked movie instead of "No linked movie".
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id,
                    a.title,
                    a.slug,
                    a.subtitle,
                    a.category,
                    a.author,
                    a.hero_image,
                    a.status,
                    a.views,
                    a.published_at,
                    a.created_at,
                    a.updated_at,
                    a.is_future_draft,
                    a.tracking_day,
                    a.reused_from_article_id,
                    a.scheduled_publish_at,
                    COALESCE(
                        ARRAY_AGG(DISTINCT am.movie_id)
                            FILTER (WHERE am.movie_id IS NOT NULL),
                        ARRAY[]::BIGINT[]
                    ) AS movie_ids,
                    COALESCE(
                        ARRAY_AGG(DISTINCT aa.actor_id)
                            FILTER (WHERE aa.actor_id IS NOT NULL),
                        ARRAY[]::BIGINT[]
                    ) AS actor_ids
                FROM articles a
                LEFT JOIN article_movies am
                    ON am.article_id = a.id
                LEFT JOIN article_actors aa
                    ON aa.article_id = a.id
                GROUP BY
                    a.id,
                    a.title,
                    a.slug,
                    a.subtitle,
                    a.category,
                    a.author,
                    a.hero_image,
                    a.status,
                    a.views,
                    a.published_at,
                    a.created_at,
                    a.updated_at,
                    a.is_future_draft,
                    a.tracking_day,
                    a.reused_from_article_id,
                    a.scheduled_publish_at
                ORDER BY a.created_at DESC, a.id DESC
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
                "is_future_draft": bool(r[12]),
                "tracking_day": r[13],
                "reused_from_article_id": r[14],
                "scheduled_publish_at": r[15],
                "movie_ids": list(r[16] or []),
                "actor_ids": list(r[17] or []),
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
                    views, published_at, created_at, updated_at,
                    tracking_enabled, final_h1, final_subtitle, final_meta_title,
                    final_meta_description, tracking_finalized_at
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
            "tracking_enabled": bool(a[16]),
            "final_h1": a[17],
            "final_subtitle": a[18],
            "final_meta_title": a[19],
            "final_meta_description": a[20],
            "tracking_finalized_at": a[21],
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



@app.get("/admin/articles/{article_id}/generated-seo-preview", dependencies=[Depends(require_admin)])
def admin_article_generated_seo_preview(article_id: int):
    """
    Return the FINAL public SSR search-layer values for this article.

    This endpoint deliberately runs the same article enrichment and
    _article_apply_tracking_ctr() priority logic used by public SSR, so Admin
    preview cannot disagree with the rendered public page.
    """
    admin_response = admin_get_article(article_id)
    article = admin_response.get("article") if isinstance(admin_response, dict) else None
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT m.id, m.title, m.release_date, m.language, m.industry
                FROM article_movies am
                JOIN movies m ON m.id=am.movie_id
                WHERE am.article_id=%s
                ORDER BY m.id
            """, (article_id,))
            movie_rows = cur.fetchall()
            analysis_map = _article_boxoffice_analysis_map(cur, article_id, movie_rows)

    article["movies"] = [
        {
            "id": r[0],
            "title": r[1],
            "release_date": r[2],
            "language": r[3],
            "industry": r[4],
        }
        for r in movie_rows
    ]

    for block in article.get("blocks") or []:
        if str(block.get("block_type") or "").lower() == "boxoffice":
            extra = dict(_public_article_boxoffice_extra(block.get("extra_data") or {}))
            extra["analysis"] = analysis_map.get(int(block.get("id") or 0), {
                "milestone_step": BOXOFFICEX_MILESTONE_STEP,
                "budget_crore": None,
                "milestones": [],
                "theatrical_performance": None,
            })
            block["extra_data"] = extra

    final_article, generated = _article_apply_tracking_ctr(article)

    title = str(final_article.get("title") or "BoxOfficeX Article").strip()
    seo_title = str(final_article.get("meta_title") or title).strip()
    public_title = seo_title
    if "boxofficex" not in public_title.lower():
        public_title += " | BoxOfficeX"

    description = str(
        final_article.get("meta_description")
        or final_article.get("subtitle")
        or "Read the latest movie, box office and entertainment stories on BoxOfficeX."
    ).strip()
    canonical = f"https://boxofficex.in/article/{final_article.get('slug') or article.get('slug') or ''}"

    priority = (generated or {}).get("priority") or "ADMIN"
    automatic_applied = bool((generated or {}).get("automatic_applied"))

    if not generated:
        mode = "NORMAL"
    elif automatic_applied:
        mode = str(generated.get("mode") or "AUTO")
    else:
        mode = "ADMIN"

    sources = []
    if generated:
        if movie_rows:
            sources.append("Linked movie release date")
        sources.append("Live Tracker (temporary current-cycle values)")
        sources.append("Stored Box Office Report / theatrical analysis")
    else:
        sources.append("Admin article fields")

    return {
        "automatic": automatic_applied,
        "priority": priority,
        "mode": mode,
        "h1": title,
        "seo_title": public_title,
        "meta_description": description,
        "canonical": canonical,
        "generated_at": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
        "sources": sources,
        "checks": {
            "h1_ready": bool(title),
            "seo_title_ready": bool(public_title),
            "description_ready": bool(description),
            "canonical_ready": bool(canonical),
            "linked_movie_release_date": bool(
                movie_rows and movie_rows[0][2]
            ),
            "public_ssr_priority_logic": True,
        },
    }


class AdminArticleTrackingModeData(BaseModel):
    enabled: bool


@app.put("/admin/articles/{article_id}/tracking-mode", dependencies=[Depends(require_admin)])
def admin_set_article_tracking_mode(article_id: int, data: AdminArticleTrackingModeData):
    """
    Switch a tracking article between unlimited AUTO and persistent FINAL/FROZEN.

    OFF is atomic from the public article's point of view:
    1) build the final package in memory from the latest permanent Box Office Report;
    2) only if generation succeeds, persist tracking_enabled=FALSE + the full snapshot
       in one UPDATE;
    3) invalidate SSR cache after commit.

    This prevents a failed freeze from leaving the article OFF with empty final fields.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT slug FROM articles WHERE id=%s", (article_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Article not found")
            slug = row[0]

    if data.enabled:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE articles
                    SET tracking_enabled=TRUE,
                        updated_at=(CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    WHERE id=%s
                """, (article_id,))
            conn.commit()
        # Frozen snapshot is deliberately retained for audit/reuse, but AUTO ignores it.
        _invalidate_article_detail_cache(slug)
        return {"success": True, "tracking_enabled": True, "mode": "AUTO"}

    # Build the exact FINAL package BEFORE changing persistent mode.
    public = get_article(slug).get("article")
    if not public:
        raise HTTPException(
            status_code=400,
            detail="Published tracking article is required before freezing",
        )

    final_candidate = dict(public)
    final_candidate["tracking_enabled"] = False
    # Force regeneration from the latest permanent stored report, not an older snapshot.
    final_candidate["final_h1"] = None
    final_candidate["final_subtitle"] = None
    final_candidate["final_meta_title"] = None
    final_candidate["final_meta_description"] = None
    final_candidate["tracking_finalized_at"] = None

    generated = _article_tracking_ctr(final_candidate)
    if not generated or generated.get("mode") != "FINAL / FROZEN":
        raise HTTPException(
            status_code=400,
            detail="Tracking article requires a linked movie, Live Tracker and stored Box Office Report",
        )

    final_h1 = str(generated.get("h1") or "").strip()
    final_title = str(generated.get("seo_title") or "").strip()
    final_description = str(generated.get("meta_description") or "").strip()
    final_subtitle = str(generated.get("subtitle") or final_description).strip()

    if not (final_h1 and final_title and final_description):
        raise HTTPException(
            status_code=400,
            detail="Final tracking snapshot could not be generated from the stored Box Office Report",
        )

    # Persist OFF + the complete frozen search/public package together.
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE articles SET
                    tracking_enabled=FALSE,
                    final_h1=%s,
                    final_subtitle=%s,
                    final_meta_title=%s,
                    final_meta_description=%s,
                    tracking_finalized_at=NOW(),
                    updated_at=(CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                WHERE id=%s
            """, (
                final_h1,
                final_subtitle,
                final_title,
                final_description,
                article_id,
            ))
        conn.commit()

    _invalidate_article_detail_cache(slug)

    return {
        "success": True,
        "tracking_enabled": False,
        "mode": "FINAL / FROZEN",
        "final_h1": final_h1,
        "final_meta_title": final_title,
        "final_meta_description": final_description,
    }


@app.post("/admin/articles", dependencies=[Depends(require_admin)])
def admin_create_article(data: AdminArticleCreate):
    slug = normalize_article_slug(data.slug or data.title)
    if not slug:
        raise HTTPException(status_code=400, detail="Article slug is required")

    status = validate_article_status(data.status)
    published_at = data.published_at
    effective_meta_title, effective_meta_description = _article_admin_seo_values(data)

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
                        published_at, tracking_enabled, updated_at
                    )
                    VALUES (
                        %s,%s,%s,%s,%s,
                        %s,%s,%s,
                        %s,%s,%s,
                        %s,%s,CURRENT_TIMESTAMP
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
                    effective_meta_title,
                    effective_meta_description,
                    published_at,
                    bool(data.tracking_enabled),
                ))
                article_id = cur.fetchone()[0]
            except psycopg.errors.UniqueViolation:
                raise HTTPException(status_code=409, detail="Article slug already exists")

        conn.commit()

    _invalidate_article_detail_cache(slug)

    return {
        "success": True,
        "seo_auto_synced": False,
        "article_id": article_id,
        "slug": slug,
        "article_url": f"/article/{slug}",
    }


@app.put("/admin/articles/{article_id}", dependencies=[Depends(require_admin)])
def admin_update_article(article_id: int, data: AdminArticleCreate):
    requested_slug = normalize_article_slug(data.slug or data.title)
    if not requested_slug:
        raise HTTPException(status_code=400, detail="Article slug is required")

    status = validate_article_status(data.status)
    published_at = data.published_at
    effective_meta_title, effective_meta_description = _article_admin_seo_values(data)

    with get_connection() as conn:
        with conn.cursor() as cur:
            # SEO safety: once an article has ever been published,
            # its public URL slug becomes permanent.
            cur.execute("""
                SELECT slug, status, published_at
                FROM articles
                WHERE id = %s
            """, (article_id,))
            existing = cur.fetchone()

            if not existing:
                raise HTTPException(status_code=404, detail="Article not found")

            existing_slug = existing[0]
            existing_status = existing[1]
            existing_published_at = existing[2]

            slug_is_locked = (
                existing_status == "published"
                or existing_published_at is not None
            )

            slug = existing_slug if slug_is_locked else requested_slug

            if status == "published" and published_at is None:
                published_at = existing_published_at or datetime.now()

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
                        tracking_enabled = %s,
                        updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
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
                    effective_meta_title,
                    effective_meta_description,
                    published_at,
                    bool(data.tracking_enabled),
                    article_id,
                ))
            except psycopg.errors.UniqueViolation:
                raise HTTPException(status_code=409, detail="Article slug already exists")

        conn.commit()

    _invalidate_article_detail_cache(existing_slug, slug)

    return {
        "success": True,
        "seo_auto_synced": False,
        "article_id": article_id,
        "slug": slug,
        "slug_locked": slug_is_locked or status == "published",
        "article_url": f"/article/{slug}",
    }




class AdminArticleStatusData(BaseModel):
    status: Literal["draft", "published", "archived"]


class AdminTrackingKeyData(BaseModel):
    movie_id: int
    day_number: int


class AdminTrackingUpdateData(BaseModel):
    movie_id: int
    day_number: int
    status: Literal["ADVANCE", "LIVE", "ESTIMATED_FINAL", "FINAL_REVIEW", "FINAL"]
    india_collection: Optional[float] = None
    overseas_collection: Optional[float] = None
    worldwide_collection: Optional[float] = None
    tamil_nadu_collection: Optional[float] = None
    kerala_collection: Optional[float] = None
    karnataka_collection: Optional[float] = None
    telugu_states_collection: Optional[float] = None
    rest_of_india_collection: Optional[float] = None
    final_locked: bool = False




def _boxoffice_tracking_status_for_day(
    collection_date: date,
    current_status: str,
) -> str:
    """
    Automatic status rules (Asia/Kolkata):
      ADVANCE -> LIVE at 06:00 IST on the collection date.
      LIVE -> ESTIMATED_FINAL at 06:00 IST on the next calendar day.

    ESTIMATED_FINAL, FINAL_REVIEW and FINAL are never changed automatically.
    """
    status = str(current_status or "LIVE").upper()

    if status not in {"ADVANCE", "LIVE"}:
        return status

    ist = ZoneInfo("Asia/Kolkata")
    now_ist = datetime.now(ist)

    tracking_start = datetime.combine(
        collection_date,
        time(hour=6, minute=0),
        tzinfo=ist,
    )
    tracking_end = tracking_start + timedelta(days=1)

    if status == "ADVANCE":
        if now_ist < tracking_start:
            return "ADVANCE"
        if now_ist < tracking_end:
            return "LIVE"
        return "ESTIMATED_FINAL"

    if now_ist >= tracking_end:
        return "ESTIMATED_FINAL"

    return "LIVE"


def refresh_article_boxoffice_tracking_statuses(article_id: Optional[int] = None):
    """
    Persist automatic ADVANCE -> LIVE -> ESTIMATED_FINAL transitions inside
    article Box Office blocks and the central movie_boxoffice_tracking table.

    This intentionally never finalizes or syncs a movie collection.
    FINAL remains an explicit editor action.
    """
    changed_blocks = 0
    changed_days = 0

    with get_connection() as conn:
        with conn.cursor() as cur:
            params = []
            where = "WHERE block_type = 'boxoffice'"

            if article_id is not None:
                where += " AND article_id = %s"
                params.append(article_id)

            cur.execute(f"""
                SELECT id, article_id, extra_data
                FROM article_blocks
                {where}
                ORDER BY article_id, block_order, id
            """, tuple(params))

            rows = cur.fetchall()

            for block_id, block_article_id, raw_extra in rows:
                extra = raw_extra or {}

                if isinstance(extra, str):
                    try:
                        extra = json.loads(extra)
                    except Exception:
                        continue

                days = extra.get("days")
                if not isinstance(days, list):
                    continue

                block_changed = False

                try:
                    movie_id = int(extra.get("movie_id"))
                except (TypeError, ValueError):
                    movie_id = None

                for item in days:
                    if not isinstance(item, dict):
                        continue

                    # Preview/Premiere uses its own optional date and follows
                    # the same time-derived status transitions.
                    raw_date = item.get("date")
                    if not raw_date:
                        continue

                    try:
                        item_date = date.fromisoformat(str(raw_date))
                    except ValueError:
                        continue

                    old_status = str(item.get("status") or "LIVE").upper()
                    new_status = _boxoffice_tracking_status_for_day(
                        item_date,
                        old_status,
                    )

                    if new_status != old_status:
                        item["status"] = new_status
                        block_changed = True
                        changed_days += 1

                    # Central tracking is only for regular numbered days.
                    if (
                        movie_id
                        and str(item.get("type") or "REGULAR").upper() == "REGULAR"
                    ):
                        try:
                            day_number = int(item.get("number"))
                        except (TypeError, ValueError):
                            day_number = None

                        if day_number and day_number >= 1:
                            # Keep the central tracking row synchronized with
                            # the same 6 AM IST lifecycle used by the article block.
                            cur.execute("""
                                UPDATE movie_boxoffice_tracking
                                SET status = CASE
                                    WHEN status = 'ADVANCE'
                                         AND tracking_start IS NOT NULL
                                         AND tracking_start <= CURRENT_TIMESTAMP
                                         AND (tracking_end IS NULL OR tracking_end > CURRENT_TIMESTAMP)
                                        THEN 'LIVE'
                                    WHEN status IN ('ADVANCE', 'LIVE')
                                         AND tracking_end IS NOT NULL
                                         AND tracking_end <= CURRENT_TIMESTAMP
                                        THEN 'ESTIMATED_FINAL'
                                    ELSE status
                                END
                                WHERE movie_id = %s
                                  AND day_number = %s
                                  AND status IN ('ADVANCE', 'LIVE')
                                  AND final_locked = FALSE
                            """, (movie_id, day_number))

                if block_changed:
                    cur.execute("""
                        UPDATE article_blocks
                        SET extra_data = %s::jsonb
                        WHERE id = %s
                    """, (
                        json.dumps(extra),
                        block_id,
                    ))
                    changed_blocks += 1

        conn.commit()

    return {
        "changed_blocks": changed_blocks,
        "changed_days": changed_days,
    }


@app.post(
    "/admin/articles/{article_id}/refresh-boxoffice-statuses",
    dependencies=[Depends(require_admin)]
)
def admin_refresh_article_boxoffice_statuses(article_id: int):
    result = refresh_article_boxoffice_tracking_statuses(article_id)
    return {
        "success": True,
        **result,
    }


class AdminTrackingStatusData(BaseModel):
    status: Literal["ADVANCE", "LIVE", "ESTIMATED_FINAL", "FINAL_REVIEW"]


class AdminFinalizeArticleDayData(BaseModel):
    movie_id: int
    day_number: int


class AdminFinalizePreviewData(BaseModel):
    movie_id: int
    collection_type: Literal["PREVIEW"]
    collection_label: str = "Preview / Premiere"
    collection_date: date


# ============================================================
# BOXOFFICEX ARTICLE STATUS + PREVIEW-SAFE ROW TRACKING
# Phase 3
# ============================================================

@app.patch(
    "/admin/articles/{article_id}/status",
    dependencies=[Depends(require_admin)]
)
def admin_set_article_status(
    article_id: int,
    data: AdminArticleStatusData,
):
    """
    Change only article publication state without requiring the full
    article editor payload.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            if data.status == "published":
                cur.execute("""
                    UPDATE articles
                    SET
                        status = 'published',
                        published_at = COALESCE(
                            published_at,
                            (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                        ),
                        is_future_draft = FALSE,
                        updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    WHERE id = %s
                    RETURNING id, status, published_at
                """, (article_id,))
            else:
                cur.execute("""
                    UPDATE articles
                    SET
                        status = %s,
                        updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    WHERE id = %s
                    RETURNING id, status, published_at
                """, (data.status, article_id))

            row = cur.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Article not found",
                )

        conn.commit()

    return {
        "success": True,
        "article": {
            "id": row[0],
            "status": row[1],
            "published_at": row[2].isoformat() if row[2] else None,
        },
    }


@app.post(
    "/admin/boxoffice-tracking/get-or-create",
    dependencies=[Depends(require_admin)]
)
def admin_get_or_create_boxoffice_tracking(
    data: AdminTrackingKeyData,
):
    if data.movie_id < 1 or data.day_number < 1:
        raise HTTPException(
            status_code=400,
            detail="movie_id and day_number must be positive",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT release_date
                FROM movies
                WHERE id = %s
            """, (data.movie_id,))
            movie_row = cur.fetchone()

            if not movie_row:
                raise HTTPException(
                    status_code=404,
                    detail="Movie not found",
                )

            ist = ZoneInfo("Asia/Kolkata")
            release_date = movie_row[0]

            if release_date:
                tracking_local_date = (
                    release_date
                    + timedelta(days=data.day_number - 1)
                )
            else:
                tracking_local_date = datetime.now(ist).date()

            tracking_start = datetime.combine(
                tracking_local_date,
                time(hour=6, minute=0),
                tzinfo=ist,
            )
            tracking_end = tracking_start + timedelta(days=1)

            initial_status = (
                "ADVANCE"
                if datetime.now(ist) < tracking_start
                else "LIVE"
            )

            cur.execute("""
                INSERT INTO movie_boxoffice_tracking (
                    movie_id,
                    day_number,
                    status,
                    tracking_start,
                    tracking_end,
                    final_locked
                )
                VALUES (%s, %s, %s, %s, %s, FALSE)
                ON CONFLICT (movie_id, day_number)
                DO UPDATE SET
                    tracking_start = COALESCE(
                        movie_boxoffice_tracking.tracking_start,
                        EXCLUDED.tracking_start
                    ),
                    tracking_end = COALESCE(
                        movie_boxoffice_tracking.tracking_end,
                        EXCLUDED.tracking_end
                    )
                RETURNING
                    id,
                    movie_id,
                    day_number,
                    status,
                    india_collection,
                    overseas_collection,
                    worldwide_collection,
                    tamil_nadu_collection,
                    kerala_collection,
                    karnataka_collection,
                    telugu_states_collection,
                    rest_of_india_collection,
                    tracking_start,
                    tracking_end,
                    final_locked,
                    updated_at
            """, (
                data.movie_id,
                data.day_number,
                initial_status,
                tracking_start,
                tracking_end,
            ))
            row = cur.fetchone()

        conn.commit()

    return {
        "success": True,
        "tracking": {
            "id": row[0],
            "movie_id": row[1],
            "day_number": row[2],
            "status": row[3],
            "india_collection": row[4],
            "overseas_collection": row[5],
            "worldwide_collection": row[6],
            "tamil_nadu_collection": row[7],
            "kerala_collection": row[8],
            "karnataka_collection": row[9],
            "telugu_states_collection": row[10],
            "rest_of_india_collection": row[11],
            "tracking_start": row[12].isoformat() if row[12] else None,
            "tracking_end": row[13].isoformat() if row[13] else None,
            "final_locked": row[14],
            "updated_at": row[15].isoformat() if row[15] else None,
        },
    }


@app.put(
    "/admin/boxoffice-tracking/{tracking_id}",
    dependencies=[Depends(require_admin)]
)
def admin_update_boxoffice_tracking(
    tracking_id: int,
    data: AdminTrackingUpdateData,
):
    """
    Update one central movie/day tracking record.

    FINAL + final_locked=TRUE freezes the record through the DB trigger.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT movie_id, day_number, final_locked
                FROM movie_boxoffice_tracking
                WHERE id = %s
            """, (tracking_id,))
            existing = cur.fetchone()

            if not existing:
                raise HTTPException(
                    status_code=404,
                    detail="Tracking record not found",
                )

            if existing[2]:
                raise HTTPException(
                    status_code=409,
                    detail="This Final tracking record is locked",
                )

            if existing[0] != data.movie_id or existing[1] != data.day_number:
                raise HTTPException(
                    status_code=400,
                    detail="Movie/day cannot be changed for an existing tracking record",
                )

            cur.execute("""
                UPDATE movie_boxoffice_tracking
                SET
                    status = %s,
                    india_collection = %s,
                    overseas_collection = %s,
                    worldwide_collection = %s,
                    tamil_nadu_collection = %s,
                    kerala_collection = %s,
                    karnataka_collection = %s,
                    telugu_states_collection = %s,
                    rest_of_india_collection = %s,
                    final_locked = %s
                WHERE id = %s
                RETURNING
                    id,
                    movie_id,
                    day_number,
                    status,
                    india_collection,
                    overseas_collection,
                    worldwide_collection,
                    tamil_nadu_collection,
                    kerala_collection,
                    karnataka_collection,
                    telugu_states_collection,
                    rest_of_india_collection,
                    tracking_start,
                    tracking_end,
                    final_locked,
                    updated_at
            """, (
                data.status,
                data.india_collection,
                data.overseas_collection,
                data.worldwide_collection,
                data.tamil_nadu_collection,
                data.kerala_collection,
                data.karnataka_collection,
                data.telugu_states_collection,
                data.rest_of_india_collection,
                data.final_locked,
                tracking_id,
            ))

            row = cur.fetchone()

        conn.commit()

    return {
        "success": True,
        "tracking": {
            "id": row[0],
            "movie_id": row[1],
            "day_number": row[2],
            "status": row[3],
            "india_collection": row[4],
            "overseas_collection": row[5],
            "worldwide_collection": row[6],
            "tamil_nadu_collection": row[7],
            "kerala_collection": row[8],
            "karnataka_collection": row[9],
            "telugu_states_collection": row[10],
            "rest_of_india_collection": row[11],
            "tracking_start": row[12].isoformat() if row[12] else None,
            "tracking_end": row[13].isoformat() if row[13] else None,
            "final_locked": row[14],
            "updated_at": row[15].isoformat() if row[15] else None,
        },
    }




@app.on_event("startup")
def initialize_movie_preview_collections():
    """
    Optional preview/premiere collections.
    Kept separate from movie_daily_collections so Day 1 always remains
    the official release date and existing movie.html day numbering stays intact.
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS movie_preview_collections (
                    id BIGSERIAL PRIMARY KEY,
                    movie_id INTEGER NOT NULL
                        REFERENCES movies(id)
                        ON DELETE CASCADE,
                    collection_label TEXT NOT NULL DEFAULT 'Preview / Premiere',
                    collection_date DATE NOT NULL,
                    tamil_nadu_collection NUMERIC(12,2),
                    kerala_collection NUMERIC(12,2),
                    karnataka_collection NUMERIC(12,2),
                    telugu_states_collection NUMERIC(12,2),
                    rest_of_india_collection NUMERIC(12,2),
                    overseas_collection NUMERIC(12,2),
                    india_collection NUMERIC(12,2),
                    worldwide_collection NUMERIC(12,2),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (movie_id, collection_date, collection_label)
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_movie_preview_collections_movie
                ON movie_preview_collections(movie_id, collection_date)
            """)
        conn.commit()



# ============================================================
# BOXOFFICEX FINALIZED MOVIE TOTAL RECALCULATION
#
# Headline movie totals = finalized Preview/Premiere
#                       + all finalized regular day rows.
#
# Preview stays in movie_preview_collections so it never changes
# Day 1 / Day 2 numbering in movie_daily_collections.
# ============================================================

def recalculate_finalized_movie_totals(conn, movie_id: int):
    """
    Recalculate the movie headline totals from:

      1. movie_preview_collections
      2. movie_daily_collections

    Preview/Premiere therefore contributes to India / Overseas /
    Worldwide totals without being inserted as Day 0 and without
    shifting regular Day numbering.
    """

    with conn.cursor() as cur:

        # Finalized regular-day totals.
        cur.execute("""
            SELECT
                COALESCE(
                    SUM(collection_crore)
                    FILTER (
                        WHERE state = ANY(%s)
                    ),
                    0
                ),
                COALESCE(
                    SUM(collection_crore)
                    FILTER (
                        WHERE state = 'Overseas'
                    ),
                    0
                )
            FROM movie_daily_collections
            WHERE movie_id = %s
        """, (
            list(LIVE_INDIA_REGIONS),
            movie_id,
        ))

        daily_row = cur.fetchone() or (0, 0)

        daily_india = float(daily_row[0] or 0)
        daily_overseas = float(daily_row[1] or 0)

        # Finalized preview / premiere totals.
        cur.execute("""
            SELECT
                COALESCE(SUM(india_collection), 0),
                COALESCE(SUM(overseas_collection), 0)
            FROM movie_preview_collections
            WHERE movie_id = %s
        """, (movie_id,))

        preview_row = cur.fetchone() or (0, 0)

        preview_india = float(preview_row[0] or 0)
        preview_overseas = float(preview_row[1] or 0)

        movie_india = daily_india + preview_india
        movie_overseas = daily_overseas + preview_overseas
        movie_worldwide = movie_india + movie_overseas

        cur.execute("""
            UPDATE movies
            SET
                india_collection_crore = %s,
                overseas_collection_crore = %s,
                worldwide_collection_crore = %s
            WHERE id = %s
        """, (
            movie_india,
            movie_overseas,
            movie_worldwide,
            movie_id,
        ))

    return {
        "india": round(movie_india, 2),
        "overseas": round(movie_overseas, 2),
        "worldwide": round(movie_worldwide, 2),
        "preview_india": round(preview_india, 2),
        "preview_overseas": round(preview_overseas, 2),
        "daily_india": round(daily_india, 2),
        "daily_overseas": round(daily_overseas, 2),
    }


# ============================================================
# BOXOFFICEX FINAL-ONLY MOVIE SYNC
# Phase 4
#
# IMPORTANT RULE:
# Article Box Office block stores working/live/estimated numbers.
# movie_daily_collections (used by movie.html) is updated ONLY
# when the editor explicitly marks a specific day FINAL.
# ============================================================

@app.patch(
    "/admin/boxoffice-tracking/{tracking_id}/status",
    dependencies=[Depends(require_admin)]
)
def admin_update_tracking_status(
    tracking_id: int,
    data: AdminTrackingStatusData,
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT final_locked
                FROM movie_boxoffice_tracking
                WHERE id = %s
            """, (tracking_id,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Tracking record not found",
                )

            if row[0]:
                raise HTTPException(
                    status_code=409,
                    detail="Final tracking record is locked",
                )

            cur.execute("""
                UPDATE movie_boxoffice_tracking
                SET status = %s
                WHERE id = %s
                RETURNING
                    id,
                    movie_id,
                    day_number,
                    status,
                    tracking_start,
                    tracking_end,
                    final_locked,
                    updated_at
            """, (
                data.status,
                tracking_id,
            ))
            updated = cur.fetchone()

        conn.commit()

    return {
        "success": True,
        "tracking": {
            "id": updated[0],
            "movie_id": updated[1],
            "day_number": updated[2],
            "status": updated[3],
            "tracking_start": updated[4].isoformat() if updated[4] else None,
            "tracking_end": updated[5].isoformat() if updated[5] else None,
            "final_locked": updated[6],
            "updated_at": updated[7].isoformat() if updated[7] else None,
        },
    }



@app.post(
    "/admin/articles/{article_id}/finalize-boxoffice-preview",
    dependencies=[Depends(require_admin)]
)
def admin_finalize_article_boxoffice_preview(
    article_id: int,
    data: AdminFinalizePreviewData,
):
    """
    Finalize a Preview/Premiere collection separately from Day 1.
    This never changes regular Day 1 numbering.
    """
    territory_fields = {
        "tamil_nadu": "tamil_nadu_collection",
        "kerala": "kerala_collection",
        "karnataka": "karnataka_collection",
        "telugu_states": "telugu_states_collection",
        "rest_of_india": "rest_of_india_collection",
        "overseas": "overseas_collection",
    }

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id
                FROM articles
                WHERE id = %s
            """, (article_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Article not found")

            cur.execute("""
                SELECT extra_data
                FROM article_blocks
                WHERE article_id = %s
                  AND block_type = 'boxoffice'
                ORDER BY block_order, id
            """, (article_id,))
            rows = cur.fetchall()

            preview = None

            for (extra_data,) in rows:
                extra = extra_data or {}

                if isinstance(extra, str):
                    try:
                        extra = json.loads(extra)
                    except Exception:
                        extra = {}

                try:
                    block_movie_id = int(extra.get("movie_id"))
                except (TypeError, ValueError):
                    continue

                if block_movie_id != data.movie_id:
                    continue

                for item in (extra.get("days") or []):
                    if str(item.get("type") or "REGULAR").upper() != "PREVIEW":
                        continue

                    item_date = item.get("date")
                    if not item_date:
                        continue

                    try:
                        item_date = date.fromisoformat(str(item_date))
                    except ValueError:
                        continue

                    if item_date == data.collection_date:
                        preview = item
                        break

                if preview is not None:
                    break

            if preview is None:
                raise HTTPException(
                    status_code=400,
                    detail="Matching Preview / Premiere collection not found in article",
                )

            if str(preview.get("status") or "").upper() != "FINAL":
                raise HTTPException(
                    status_code=400,
                    detail="Preview / Premiere must be FINAL before syncing",
                )

            values = {}
            for source_field, db_field in territory_fields.items():
                try:
                    values[db_field] = float(preview.get(source_field) or 0)
                except (TypeError, ValueError):
                    values[db_field] = 0.0

            india = (
                values["tamil_nadu_collection"]
                + values["kerala_collection"]
                + values["karnataka_collection"]
                + values["telugu_states_collection"]
                + values["rest_of_india_collection"]
            )
            overseas = values["overseas_collection"]
            worldwide = india + overseas

            cur.execute("""
                INSERT INTO movie_preview_collections (
                    movie_id,
                    collection_label,
                    collection_date,
                    tamil_nadu_collection,
                    kerala_collection,
                    karnataka_collection,
                    telugu_states_collection,
                    rest_of_india_collection,
                    overseas_collection,
                    india_collection,
                    worldwide_collection,
                    updated_at
                )
                VALUES (
                    %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    CURRENT_TIMESTAMP
                )
                ON CONFLICT (movie_id, collection_date, collection_label)
                DO UPDATE SET
                    tamil_nadu_collection = EXCLUDED.tamil_nadu_collection,
                    kerala_collection = EXCLUDED.kerala_collection,
                    karnataka_collection = EXCLUDED.karnataka_collection,
                    telugu_states_collection = EXCLUDED.telugu_states_collection,
                    rest_of_india_collection = EXCLUDED.rest_of_india_collection,
                    overseas_collection = EXCLUDED.overseas_collection,
                    india_collection = EXCLUDED.india_collection,
                    worldwide_collection = EXCLUDED.worldwide_collection,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            """, (
                data.movie_id,
                data.collection_label.strip() or "Preview / Premiere",
                data.collection_date,
                values["tamil_nadu_collection"],
                values["kerala_collection"],
                values["karnataka_collection"],
                values["telugu_states_collection"],
                values["rest_of_india_collection"],
                overseas,
                india,
                worldwide,
            ))

            preview_id = cur.fetchone()[0]

        # Preview/Premiere is part of the movie gross.
        # Recalculate headline totals from Preview + all finalized days.
        movie_totals = recalculate_finalized_movie_totals(
            conn,
            data.movie_id,
        )

        conn.commit()

    return {
        "success": True,
        "preview_id": preview_id,
        "movie_id": data.movie_id,
        "collection_label": data.collection_label,
        "collection_date": data.collection_date.isoformat(),
        "totals": {
            "india": round(india, 2),
            "overseas": round(overseas, 2),
            "worldwide": round(worldwide, 2),
        },
        "movie_totals": {
            "india": movie_totals["india"],
            "overseas": movie_totals["overseas"],
            "worldwide": movie_totals["worldwide"],
        },
    }


@app.post(
    "/admin/articles/{article_id}/finalize-boxoffice-day",
    dependencies=[Depends(require_admin)]
)
def admin_finalize_article_boxoffice_day(
    article_id: int,
    data: AdminFinalizeArticleDayData,
):
    """
    Publish ONE finalized day from an Article Box Office block into
    movie_daily_collections. Previous finalized days are preserved.

    This is the only Phase-4 path that writes an article's current
    day numbers into the movie.html day-wise database.
    """
    if data.movie_id < 1 or data.day_number < 1:
        raise HTTPException(
            status_code=400,
            detail="movie_id and day_number must be positive",
        )

    territory_map = (
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
                FROM articles
                WHERE id = %s
            """, (article_id,))
            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Article not found",
                )

            cur.execute("""
                SELECT id, extra_data
                FROM article_blocks
                WHERE article_id = %s
                  AND block_type = 'boxoffice'
                ORDER BY block_order, id
            """, (article_id,))
            blocks = cur.fetchall()

            selected_day = None

            for block_id, extra_data in blocks:
                extra = extra_data or {}

                if isinstance(extra, str):
                    try:
                        extra = json.loads(extra)
                    except Exception:
                        extra = {}

                block_movie_id = extra.get("movie_id")
                try:
                    block_movie_id = int(block_movie_id)
                except (TypeError, ValueError):
                    continue

                if block_movie_id != data.movie_id:
                    continue

                days = extra.get("days") or []

                for candidate in days:
                    if not isinstance(candidate, dict):
                        continue

                    if str(candidate.get("type") or "REGULAR").upper() != "REGULAR":
                        continue

                    try:
                        candidate_day = int(candidate.get("number"))
                    except (TypeError, ValueError):
                        continue

                    if candidate_day == data.day_number:
                        selected_day = candidate
                        break

                if selected_day is not None:
                    break

            if selected_day is None:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"No Box Office block for movie {data.movie_id} "
                        f"contains Day {data.day_number}"
                    ),
                )

            if str(selected_day.get("status") or "").upper() != "FINAL":
                raise HTTPException(
                    status_code=400,
                    detail=f"Day {data.day_number} must be FINAL before syncing"
                )

            collection_date = selected_day.get("date")
            if not collection_date:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Day {data.day_number} needs a date before it can be Final"
                    ),
                )

            try:
                final_date = date.fromisoformat(str(collection_date))
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid collection date in Box Office block",
                )

            # Verify movie exists.
            cur.execute("""
                SELECT id
                FROM movies
                WHERE id = %s
            """, (data.movie_id,))
            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Movie not found",
                )

            # Write ONLY this final day. Never delete previous days.
            day_india = 0.0
            day_overseas = 0.0

            for territory, field_name in territory_map:
                raw_amount = selected_day.get(field_name)

                try:
                    amount = float(raw_amount or 0)
                except (TypeError, ValueError):
                    amount = 0.0

                cur.execute("""
                    INSERT INTO movie_daily_collections (
                        movie_id,
                        collection_date,
                        state,
                        collection_crore
                    )
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (
                        movie_id,
                        collection_date,
                        state
                    )
                    DO UPDATE SET
                        collection_crore = EXCLUDED.collection_crore
                """, (
                    data.movie_id,
                    final_date,
                    territory,
                    amount,
                ))

                if territory == "Overseas":
                    day_overseas += amount
                else:
                    day_india += amount

            day_worldwide = day_india + day_overseas

            # Recalculate headline totals from:
            # Preview/Premiere + all finalized regular days.
            movie_totals = recalculate_finalized_movie_totals(
                conn,
                data.movie_id,
            )

            movie_india = movie_totals["india"]
            movie_overseas = movie_totals["overseas"]
            movie_worldwide = movie_totals["worldwide"]

            # Mark/create the matching tracking row as FINAL + locked.
            cur.execute("""
                INSERT INTO movie_boxoffice_tracking (
                    movie_id,
                    day_number,
                    status,
                    final_locked
                )
                VALUES (%s, %s, 'FINAL', TRUE)
                ON CONFLICT (movie_id, day_number)
                DO UPDATE SET
                    status = 'FINAL',
                    final_locked = TRUE
                RETURNING id
            """, (
                data.movie_id,
                data.day_number,
            ))
            tracking_id = cur.fetchone()[0]

        conn.commit()

    return {
        "success": True,
        "message": f"Day {data.day_number} finalized and synced to movie.html",
        "tracking_id": tracking_id,
        "movie_id": data.movie_id,
        "day_number": data.day_number,
        "collection_date": final_date.isoformat(),
        "day_totals": {
            "india": round(day_india, 2),
            "overseas": round(day_overseas, 2),
            "worldwide": round(day_worldwide, 2),
        },
        "movie_totals": {
            "india": round(movie_india, 2),
            "overseas": round(movie_overseas, 2),
            "worldwide": round(movie_worldwide, 2),
        },
    }


# ============================================================
# BOXOFFICEX ARTICLE REUSE + FUTURE DRAFT GENERATOR
# Phase 2
# ============================================================

class AdminArticleReuseData(BaseModel):
    target_day: int


class AdminFutureDraftData(BaseModel):
    through_day: int


def _replace_article_day_text(value: Optional[str], source_day: int, target_day: int):
    """
    Replace only explicit article day labels such as:
      Day 1 -> Day 2
      day-1 -> day-2
      day_1 -> day_2

    Box-office amounts and unrelated numbers are never changed.
    """
    if value is None:
        return None

    result = str(value)

    result = re.sub(
        rf"(?i)\bday\s+{source_day}\b",
        lambda m: ("Day" if m.group(0)[0].isupper() else "day") + f" {target_day}",
        result,
    )

    result = re.sub(
        rf"(?i)\bday-{source_day}\b",
        f"day-{target_day}",
        result,
    )

    result = re.sub(
        rf"(?i)\bday_{source_day}\b",
        f"day_{target_day}",
        result,
    )

    return result


def _detect_article_day(title: str, slug: str, stored_day: Optional[int]):
    if stored_day and int(stored_day) >= 1:
        return int(stored_day)

    for value in (title or "", slug or ""):
        match = re.search(r"(?i)\bday[\s_-]*(\d+)\b", value)
        if match:
            return int(match.group(1))

    return 1


def _unique_reused_slug(cur, desired_slug: str):
    """
    Normally Day 1 -> Day 2 already produces a unique slug.
    This fallback prevents a failed draft operation if that slug exists.
    """
    base = normalize_article_slug(desired_slug)

    if not base:
        base = "article-draft"

    candidate = base
    suffix = 2

    while True:
        cur.execute(
            "SELECT 1 FROM articles WHERE slug = %s LIMIT 1",
            (candidate,),
        )
        if not cur.fetchone():
            return candidate

        candidate = f"{base}-{suffix}"
        suffix += 1


def _get_or_create_tracking_record(cur, movie_id: int, day_number: int):
    """
    One movie + one day = one central tracking record.
    Draft generation reuses the same record if it already exists.
    """
    cur.execute("""
        SELECT id
        FROM movie_boxoffice_tracking
        WHERE movie_id = %s
          AND day_number = %s
    """, (movie_id, day_number))

    row = cur.fetchone()

    if row:
        return row[0]

    cur.execute("""
        INSERT INTO movie_boxoffice_tracking (
            movie_id,
            day_number,
            status,
            final_locked
        )
        VALUES (%s, %s, 'LIVE', FALSE)
        ON CONFLICT (movie_id, day_number)
        DO UPDATE SET movie_id = EXCLUDED.movie_id
        RETURNING id
    """, (movie_id, day_number))

    return cur.fetchone()[0]


def _attach_tracking_to_reused_article(
    cur,
    article_id: int,
    movie_ids: list[int],
    target_day: int,
):
    """
    Current day is writable/current.
    Earlier available days are historical/read-only links.

    Tracking is attached automatically only when the article is linked
    to exactly one movie. Multi-movie articles remain normal articles.
    """
    if len(movie_ids) != 1:
        return None

    movie_id = movie_ids[0]

    # Attach any existing earlier tracking days as historical.
    cur.execute("""
        SELECT id, day_number
        FROM movie_boxoffice_tracking
        WHERE movie_id = %s
          AND day_number < %s
        ORDER BY day_number
    """, (movie_id, target_day))

    for tracking_id, day_number in cur.fetchall():
        cur.execute("""
            INSERT INTO article_boxoffice_tracking (
                article_id,
                tracking_id,
                link_type,
                display_order
            )
            VALUES (%s, %s, 'HISTORICAL', %s)
            ON CONFLICT (article_id, tracking_id) DO NOTHING
        """, (
            article_id,
            tracking_id,
            day_number,
        ))

    current_tracking_id = _get_or_create_tracking_record(
        cur,
        movie_id,
        target_day,
    )

    cur.execute("""
        INSERT INTO article_boxoffice_tracking (
            article_id,
            tracking_id,
            link_type,
            display_order
        )
        VALUES (%s, %s, 'CURRENT', %s)
        ON CONFLICT (article_id, tracking_id)
        DO UPDATE SET
            link_type = 'CURRENT',
            display_order = EXCLUDED.display_order
    """, (
        article_id,
        current_tracking_id,
        target_day,
    ))

    return current_tracking_id


def _reuse_article_in_transaction(
    cur,
    source_article_id: int,
    target_day: int,
):
    if target_day < 1:
        raise HTTPException(
            status_code=400,
            detail="Target day must be 1 or greater",
        )

    cur.execute("""
        SELECT
            id,
            title,
            slug,
            subtitle,
            category,
            author,
            hero_image,
            hero_caption,
            hero_credit,
            meta_title,
            meta_description,
            tracking_day
        FROM articles
        WHERE id = %s
    """, (source_article_id,))

    source = cur.fetchone()

    if not source:
        raise HTTPException(
            status_code=404,
            detail="Source article not found",
        )

    source_day = _detect_article_day(
        source[1],
        source[2],
        source[11],
    )

    if target_day == source_day:
        raise HTTPException(
            status_code=400,
            detail=f"Target day is already Day {source_day}",
        )

    new_title = _replace_article_day_text(
        source[1], source_day, target_day
    )
    desired_slug = _replace_article_day_text(
        source[2], source_day, target_day
    )
    new_slug = _unique_reused_slug(cur, desired_slug)

    new_subtitle = _replace_article_day_text(
        source[3], source_day, target_day
    )
    new_meta_title = _replace_article_day_text(
        source[9], source_day, target_day
    )
    new_meta_description = _replace_article_day_text(
        source[10], source_day, target_day
    )

    cur.execute("""
        INSERT INTO articles (
            title,
            slug,
            subtitle,
            category,
            author,
            hero_image,
            hero_caption,
            hero_credit,
            status,
            meta_title,
            meta_description,
            published_at,
            reused_from_article_id,
            tracking_day,
            is_future_draft,
            scheduled_publish_at,
            updated_at
        )
        VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s,
            'draft', %s, %s,
            NULL,
            %s,
            %s,
            TRUE,
            NULL,
            CURRENT_TIMESTAMP
        )
        RETURNING id
    """, (
        new_title,
        new_slug,
        new_subtitle,
        source[4],
        source[5],
        source[6],
        source[7],
        source[8],
        new_meta_title,
        new_meta_description,
        source_article_id,
        target_day,
    ))

    new_article_id = cur.fetchone()[0]

    # Copy all article blocks.
    # Content is copied exactly; collection amounts are never modified.
    cur.execute("""
        INSERT INTO article_blocks (
            article_id,
            block_order,
            block_type,
            content,
            image,
            image_caption,
            image_credit,
            extra_data
        )
        SELECT
            %s,
            block_order,
            block_type,
            content,
            image,
            image_caption,
            image_credit,
            extra_data
        FROM article_blocks
        WHERE article_id = %s
        ORDER BY block_order
    """, (
        new_article_id,
        source_article_id,
    ))

    # Prepare copied Box Office blocks for the target article day.
    # Preview/Premiere stays separate. Historical regular days are preserved.
    # Missing future regular days are appended blank through target_day.
    cur.execute("""
        SELECT id, extra_data
        FROM article_blocks
        WHERE article_id = %s
          AND block_type = 'boxoffice'
        ORDER BY block_order, id
    """, (new_article_id,))

    copied_boxoffice_blocks = cur.fetchall()

    for copied_block_id, raw_extra in copied_boxoffice_blocks:
        extra = raw_extra or {}

        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except Exception:
                extra = {}

        try:
            block_movie_id = int(extra.get("movie_id"))
        except (TypeError, ValueError):
            block_movie_id = None

        release_date = None
        if block_movie_id:
            cur.execute("""
                SELECT release_date
                FROM movies
                WHERE id = %s
            """, (block_movie_id,))
            release_row = cur.fetchone()
            release_date = release_row[0] if release_row else None

        source_days = extra.get("days") or []
        previews = []
        regular_by_number = {}

        for item in source_days:
            if not isinstance(item, dict):
                continue

            item_type = str(item.get("type") or "REGULAR").upper()

            if item_type == "PREVIEW":
                preview_copy = dict(item)
                preview_copy["type"] = "PREVIEW"
                preview_copy["number"] = None
                previews.append(preview_copy)
                continue

            try:
                day_no = int(item.get("number"))
            except (TypeError, ValueError):
                continue

            if day_no < 1 or day_no > target_day:
                continue

            regular_copy = dict(item)
            regular_copy["type"] = "REGULAR"
            regular_copy["number"] = day_no
            regular_by_number[day_no] = regular_copy

        for day_no in range(1, target_day + 1):
            if day_no in regular_by_number:
                continue

            auto_date = None
            if release_date:
                auto_date = release_date + timedelta(days=day_no - 1)

            regular_by_number[day_no] = {
                "number": day_no,
                "type": "REGULAR",
                "label": "",
                "date": auto_date.isoformat() if auto_date else "",
                "status": "LIVE",
                "tamil_nadu": None,
                "kerala": None,
                "karnataka": None,
                "telugu_states": None,
                "rest_of_india": None,
                "overseas": None,
            }

        # The target day must never inherit a previous article's live/final amounts
        # unless that exact target day already existed historically in the source.
        target_item = regular_by_number.get(target_day)
        if target_item and target_day > source_day:
            target_item.update({
                "status": "LIVE",
                "tamil_nadu": None,
                "kerala": None,
                "karnataka": None,
                "telugu_states": None,
                "rest_of_india": None,
                "overseas": None,
            })

        extra["days"] = (
            previews
            + [regular_by_number[n] for n in sorted(regular_by_number)]
        )

        cur.execute("""
            UPDATE article_blocks
            SET extra_data = %s::jsonb
            WHERE id = %s
        """, (
            json.dumps(extra),
            copied_block_id,
        ))

    # Copy movie links.
    cur.execute("""
        INSERT INTO article_movies (article_id, movie_id)
        SELECT %s, movie_id
        FROM article_movies
        WHERE article_id = %s
        ON CONFLICT DO NOTHING
    """, (
        new_article_id,
        source_article_id,
    ))

    # Copy actor links.
    cur.execute("""
        INSERT INTO article_actors (article_id, actor_id)
        SELECT %s, actor_id
        FROM article_actors
        WHERE article_id = %s
        ON CONFLICT DO NOTHING
    """, (
        new_article_id,
        source_article_id,
    ))

    cur.execute("""
        SELECT movie_id
        FROM article_movies
        WHERE article_id = %s
        ORDER BY movie_id
    """, (new_article_id,))

    movie_ids = [row[0] for row in cur.fetchall()]

    current_tracking_id = _attach_tracking_to_reused_article(
        cur,
        new_article_id,
        movie_ids,
        target_day,
    )

    return {
        "article_id": new_article_id,
        "title": new_title,
        "slug": new_slug,
        "tracking_day": target_day,
        "reused_from_article_id": source_article_id,
        "movie_ids": movie_ids,
        "current_tracking_id": current_tracking_id,
    }


@app.post(
    "/admin/articles/{article_id}/reuse",
    dependencies=[Depends(require_admin)]
)
def admin_reuse_article(
    article_id: int,
    data: AdminArticleReuseData,
):
    """
    Create one independent Draft from an existing article.

    Example:
      Day 1 -> Reuse -> Day 2 Draft
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            result = _reuse_article_in_transaction(
                cur,
                article_id,
                data.target_day,
            )

        conn.commit()

    return {
        "success": True,
        "message": f"Day {data.target_day} draft created",
        "article": result,
    }


@app.post(
    "/admin/articles/{article_id}/future-drafts",
    dependencies=[Depends(require_admin)]
)
def admin_create_future_article_drafts(
    article_id: int,
    data: AdminFutureDraftData,
):
    """
    Generate as many future day drafts as the editor chooses.

    Example:
      Source = Day 1
      through_day = 5
      -> creates Day 2, 3, 4 and 5 drafts.

    There is intentionally no fixed 7-day rule.
    """
    if data.through_day < 2:
        raise HTTPException(
            status_code=400,
            detail="through_day must be Day 2 or greater",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT title, slug, tracking_day
                FROM articles
                WHERE id = %s
            """, (article_id,))

            source = cur.fetchone()

            if not source:
                raise HTTPException(
                    status_code=404,
                    detail="Source article not found",
                )

            source_day = _detect_article_day(
                source[0],
                source[1],
                source[2],
            )

            if data.through_day <= source_day:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Source is Day {source_day}. "
                        "Choose a later ending day."
                    ),
                )

            created = []

            for target_day in range(
                source_day + 1,
                data.through_day + 1,
            ):
                result = _reuse_article_in_transaction(
                    cur,
                    article_id,
                    target_day,
                )
                created.append(result)

        conn.commit()

    return {
        "success": True,
        "source_article_id": article_id,
        "from_day": source_day,
        "through_day": data.through_day,
        "drafts_created": len(created),
        "drafts": created,
    }


@app.get(
    "/admin/articles/drafts/list",
    dependencies=[Depends(require_admin)]
)
def admin_list_article_drafts(
    q: Optional[str] = None,
    movie_id: Optional[int] = None,
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id,
                    a.title,
                    a.slug,
                    a.category,
                    a.hero_image,
                    a.tracking_day,
                    a.is_future_draft,
                    a.reused_from_article_id,
                    a.scheduled_publish_at,
                    a.created_at,
                    a.updated_at,
                    ARRAY_REMOVE(
                        ARRAY_AGG(DISTINCT am.movie_id),
                        NULL
                    ) AS movie_ids
                FROM articles a
                LEFT JOIN article_movies am
                    ON am.article_id = a.id
                WHERE a.status = 'draft'
                  AND (
                        %s IS NULL
                        OR a.title ILIKE '%%' || %s || '%%'
                        OR a.slug ILIKE '%%' || %s || '%%'
                  )
                  AND (
                        %s IS NULL
                        OR EXISTS (
                            SELECT 1
                            FROM article_movies am_filter
                            WHERE am_filter.article_id = a.id
                              AND am_filter.movie_id = %s
                        )
                  )
                GROUP BY a.id
                ORDER BY
                    a.tracking_day NULLS LAST,
                    a.created_at DESC,
                    a.id DESC
            """, (
                q.strip() if q and q.strip() else None,
                q.strip() if q and q.strip() else None,
                q.strip() if q and q.strip() else None,
                movie_id,
                movie_id,
            ))
            rows = cur.fetchall()

    return {
        "drafts": [
            {
                "id": row[0],
                "title": row[1],
                "slug": row[2],
                "category": row[3],
                "hero_image": row[4],
                "tracking_day": row[5],
                "is_future_draft": row[6],
                "reused_from_article_id": row[7],
                "scheduled_publish_at": row[8],
                "created_at": row[9],
                "updated_at": row[10],
                "movie_ids": row[11] or [],
            }
            for row in rows
        ]
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




@app.put("/admin/articles/{article_id}/blocks/sync", dependencies=[Depends(require_admin)])
def admin_sync_article_blocks(article_id: int, data: AdminArticleBlocksSync):
    """Fast, atomic and non-destructive article block sync."""
    blocks = data.blocks or []
    deleted_ids = list(dict.fromkeys(int(x) for x in (data.deleted_block_ids or [])))

    expected_orders = list(range(1, len(blocks) + 1))
    received_orders = [int(b.block_order) for b in blocks]
    if received_orders != expected_orders:
        raise HTTPException(status_code=400, detail="Block orders must be sequential from 1")

    existing_ids = [int(b.id) for b in blocks if b.id is not None]
    if len(existing_ids) != len(set(existing_ids)):
        raise HTTPException(status_code=400, detail="Duplicate block IDs in save request")

    if set(existing_ids) & set(deleted_ids):
        raise HTTPException(status_code=400, detail="A block cannot be updated and deleted in the same save")

    validated_types = [validate_block_type(b.block_type) for b in blocks]

    with get_connection() as conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM articles WHERE id=%s FOR UPDATE", (article_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail="Article not found")

                cur.execute("""
                    SELECT id, block_order
                    FROM article_blocks
                    WHERE article_id=%s
                    ORDER BY block_order, id
                    FOR UPDATE
                """, (article_id,))
                current_rows = cur.fetchall()
                current_ids = {int(row[0]) for row in current_rows}
                accounted_ids = set(existing_ids) | set(deleted_ids)

                # Never treat a missing editor block as permission to delete it.
                if current_ids != accounted_ids:
                    raise HTTPException(
                        status_code=409,
                        detail="Article blocks changed or were not fully loaded. Reload the article before saving."
                    )

                # Temporarily move existing submitted blocks away from final orders.
                min_order = min((int(row[1]) for row in current_rows), default=0)
                temp_base = min(min_order, 0) - len(existing_ids) - 1000
                for i, block_id in enumerate(existing_ids):
                    cur.execute("""
                        UPDATE article_blocks
                        SET block_order=%s
                        WHERE id=%s AND article_id=%s
                    """, (temp_base + i, block_id, article_id))
                    if cur.rowcount != 1:
                        raise HTTPException(status_code=409, detail="A block changed while saving. Reload and try again.")

                # Delete only blocks explicitly removed in the editor.
                for block_id in deleted_ids:
                    cur.execute("""
                        DELETE FROM article_blocks
                        WHERE id=%s AND article_id=%s
                    """, (block_id, article_id))
                    if cur.rowcount != 1:
                        raise HTTPException(status_code=409, detail="A removed block changed while saving. Reload and try again.")

                saved_ids = []
                for i, b in enumerate(blocks):
                    block_type = validated_types[i]
                    if b.id is not None:
                        cur.execute("""
                            UPDATE article_blocks
                            SET block_order=%s, block_type=%s, content=%s, image=%s,
                                image_caption=%s, image_credit=%s, extra_data=%s
                            WHERE id=%s AND article_id=%s
                            RETURNING id
                        """, (
                            b.block_order, block_type, b.content, b.image,
                            b.image_caption, b.image_credit,
                            psycopg.types.json.Jsonb(b.extra_data or {}),
                            int(b.id), article_id,
                        ))
                    else:
                        cur.execute("""
                            INSERT INTO article_blocks (
                                article_id, block_order, block_type, content, image,
                                image_caption, image_credit, extra_data
                            )
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            RETURNING id
                        """, (
                            article_id, b.block_order, block_type, b.content, b.image,
                            b.image_caption, b.image_credit,
                            psycopg.types.json.Jsonb(b.extra_data or {}),
                        ))
                    row = cur.fetchone()
                    if not row:
                        raise HTTPException(status_code=409, detail="A block changed while saving. Reload and try again.")
                    saved_ids.append(int(row[0]))

                # Derive and persist new ₹50 Cr milestone snapshots from the
                # just-saved in-content box-office block. This runs inside the
                # same transaction as the block save, so no second admin action
                # or browser request is required.
                _capture_article_boxoffice_milestones(cur, article_id)

                cur.execute("""
                    UPDATE articles
                    SET updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    WHERE id=%s
                """, (article_id,))

            conn.commit()
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise

    _invalidate_article_detail_cache_by_id(article_id)

    return {
        "success": True,
        "article_id": article_id,
        "block_count": len(blocks),
        "block_ids": saved_ids,
    }


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

                _capture_article_boxoffice_milestones(cur, article_id)

                # A block is part of the public article body, so adding one
                # is a meaningful article modification. Keep published_at
                # unchanged and refresh only updated_at.
                cur.execute("""
                    UPDATE articles
                    SET updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    WHERE id = %s
                """, (article_id,))
            except psycopg.errors.UniqueViolation:
                raise HTTPException(
                    status_code=409,
                    detail="That block order already exists for this article"
                )

        conn.commit()

    _invalidate_article_detail_cache_by_id(article_id)
    return {"success": True, "block_id": block_id}


@app.put("/admin/article-blocks/{block_id}", dependencies=[Depends(require_admin)])
def admin_update_article_block(block_id: int, data: AdminArticleBlock):
    block_type = validate_block_type(data.block_type)
    parent_article_id = None

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

            # Find the parent article after a successful block update and
            # refresh its modification timestamp.
            cur.execute("""
                SELECT article_id
                FROM article_blocks
                WHERE id = %s
            """, (block_id,))
            article_row = cur.fetchone()

            if article_row:
                parent_article_id = int(article_row[0])
                _capture_article_boxoffice_milestones(cur, parent_article_id)
                cur.execute("""
                    UPDATE articles
                    SET updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    WHERE id = %s
                """, (parent_article_id,))

        conn.commit()

    if parent_article_id is not None:
        _invalidate_article_detail_cache_by_id(parent_article_id)
    return {"success": True, "block_id": block_id}


@app.delete("/admin/article-blocks/{block_id}", dependencies=[Depends(require_admin)])
def admin_delete_article_block(block_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            # Capture the parent before deleting the block.
            cur.execute("""
                SELECT article_id
                FROM article_blocks
                WHERE id = %s
            """, (block_id,))
            article_row = cur.fetchone()

            if not article_row:
                raise HTTPException(status_code=404, detail="Article block not found")

            article_id = article_row[0]

            cur.execute("""
                DELETE FROM article_blocks
                WHERE id = %s
            """, (block_id,))

            _capture_article_boxoffice_milestones(cur, int(article_id))

            cur.execute("""
                UPDATE articles
                SET updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                WHERE id = %s
            """, (article_id,))

        conn.commit()

    _invalidate_article_detail_cache_by_id(int(article_id))
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
    """Upload article hero/block/gallery images to permanent Cloudinary storage."""
    result = await _upload_admin_image_to_cloudinary(
        file=file,
        folder="boxofficex/article-images",
        default_stem="article-image",
    )

    secure_url = result.get("url")
    if not secure_url:
        raise HTTPException(
            status_code=502,
            detail="Cloudinary did not return an article image URL",
        )

    # Keep `filename` for compatibility with the existing article editor.
    # For new uploads it intentionally contains the permanent HTTPS URL.
    return {
        "success": True,
        "filename": secure_url,
        "url": secure_url,
        "public_id": result.get("public_id"),
        "format": result.get("format"),
        "width": result.get("width"),
        "height": result.get("height"),
        "bytes": result.get("bytes"),
    }


@app.post("/admin/articles/{article_id}/publish", dependencies=[Depends(require_admin)])
def admin_publish_article(article_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE articles
                SET
                    status='published',
                    published_at=COALESCE(
                        published_at,
                        (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                    ),
                    updated_at=(CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
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
                SET status='draft', updated_at=(CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                WHERE id=%s
            """, (article_id,))

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Article not found")

        conn.commit()

    return {"success": True, "message": "Article moved to draft"}

@app.get("/admin-articles.html", dependencies=[Depends(require_admin)])
def admin_articles_page():
    return FileResponse(BASE_DIR / "admin-articles.html")



# ============================================================
# ARTICLES LIST - NON-BLOCKING CACHED SSR
# ============================================================

ARTICLES_LIST_HTML_CACHE_TTL = 300
_articles_list_html_cache = {"html": None, "expires_at": 0.0}
_articles_list_html_cache_lock = threading.Lock()
_articles_list_html_refreshing = False


def _articles_list_image(article):
    value = str(article.get("hero_image") or "").strip()
    if not value:
        return _home_article_placeholder(article)
    if value.startswith(("https://", "http://", "/")):
        return value
    if value.startswith("article-images/"):
        return "/" + value
    return "/article-images/" + quote(value)


def _articles_list_date(value):
    if not value:
        return ""
    if hasattr(value, "strftime"):
        return f"{value.day} {value.strftime('%b %Y')}"
    return str(value)


def _articles_list_meta(article):
    author = str(article.get("author") or "BoxOfficeX").strip() or "BoxOfficeX"
    published = _articles_list_date(article.get("published_at"))
    return html_escape(author) + (f" • {html_escape(published)}" if published else "")


def _articles_list_img(article):
    title = str(article.get("title") or "Latest Cinema Story")
    category = str(article.get("category") or "BOX OFFICE NEWS")
    src = _articles_list_image(article)
    return (
        f'<img src="{html_escape(src, quote=True)}" '
        f'alt="{html_escape(title, quote=True)}" '
        f'data-category="{html_escape(category, quote=True)}" loading="lazy">'
    )


def _articles_list_hero(article):
    slug = quote(str(article.get("slug") or ""), safe="")
    title = str(article.get("title") or "BoxOfficeX Article").strip()
    category = str(article.get("category") or "News")
    subtitle = str(article.get("subtitle") or "").strip()
    subtitle_html = f'<p>{html_escape(subtitle)}</p>' if subtitle else ""
    return (
        f'<a class="hero-main" href="/article/{slug}">'
        f'{_articles_list_img(article)}'
        f'<div class="hero-copy"><span class="badge">{html_escape(category)}</span>'
        f'<h2>{html_escape(title)}</h2>{subtitle_html}'
        f'<div class="meta">{_articles_list_meta(article)}</div></div></a>'
    )


def _articles_list_side(article):
    slug = quote(str(article.get("slug") or ""), safe="")
    title = str(article.get("title") or "BoxOfficeX Article").strip()
    category = str(article.get("category") or "News")
    return (
        f'<a class="side-card" href="/article/{slug}">'
        f'{_articles_list_img(article)}<div>'
        f'<span class="badge">{html_escape(category)}</span>'
        f'<h3>{html_escape(title)}</h3>'
        f'<div class="meta">{_articles_list_meta(article)}</div></div></a>'
    )


def _articles_list_card(article):
    slug = quote(str(article.get("slug") or ""), safe="")
    title = str(article.get("title") or "BoxOfficeX Article").strip()
    category = str(article.get("category") or "News")
    subtitle = str(article.get("subtitle") or "").strip()
    subtitle_html = f'<p>{html_escape(subtitle)}</p>' if subtitle else ""
    return (
        f'<a class="story-card" href="/article/{slug}">'
        f'{_articles_list_img(article)}<div class="story-body">'
        f'<span class="badge">{html_escape(category)}</span>'
        f'<h3>{html_escape(title)}</h3>{subtitle_html}'
        f'<div class="meta">{_articles_list_meta(article)}</div></div></a>'
    )


def _articles_list_trend(article, index):
    slug = quote(str(article.get("slug") or ""), safe="")
    title = str(article.get("title") or "BoxOfficeX Article").strip()
    category = str(article.get("category") or "News")
    views = int(article.get("views") or 0)
    views_html = (
        f'<div class="meta">{views:,} views</div>'
        if SHOW_PUBLIC_ARTICLE_VIEWS
        else ""
    )
    return (
        f'<a class="trend-card" href="/article/{slug}">'
        f'<div class="trend-num">{index:02d}</div><div>'
        f'<span class="badge">{html_escape(category)}</span>'
        f'<h3>{html_escape(title)}</h3>'
        f'{views_html}</div></a>'
    )


def _render_articles_list_html():
    template = _inject_boxofficex_global_icons((BASE_DIR / "articles.html").read_text(encoding="utf-8"))
    data = get_articles()
    articles = list(data.get("articles") or [])

    if not articles:
        content_html = '<div id="content" data-ssr="1"><div class="empty">No published articles yet.</div></div>'
    else:
        hero = articles[0]
        side = articles[1:4]
        latest = articles[1:]

        categories = []
        for article in articles:
            category = str(article.get("category") or "News")
            if category not in categories:
                categories.append(category)

        trending = sorted(
            articles,
            key=lambda item: int(item.get("views") or 0),
            reverse=True,
        )[:6]

        side_html = "".join(_articles_list_side(a) for a in side)
        if not side_html:
            side_html = '<div class="empty">More stories coming soon.</div>'

        latest_html = "".join(_articles_list_card(a) for a in latest)
        if not latest_html:
            latest_html = _articles_list_card(hero)

        category_buttons = ['<button class="active" data-category="All">All</button>']
        category_buttons.extend(
            f'<button data-category="{html_escape(c, quote=True)}">{html_escape(c)}</button>'
            for c in categories
        )

        trending_html = "".join(
            _articles_list_trend(article, position)
            for position, article in enumerate(trending, 1)
        )

        content_html = (
            '<div id="content" data-ssr="1">'
            f'<section class="hero">{_articles_list_hero(hero)}'
            '<div><div class="mobile-swipe-hint">↔ Swipe to explore more</div>'
            f'<div class="hero-side">{side_html}</div></div></section>'
            '<div class="section-head"><h2>Latest Stories</h2>'
            f'<span>{len(articles)} published</span></div>'
            f'<div class="category-tabs">{"".join(category_buttons)}</div>'
            '<div class="mobile-swipe-hint">↔ Swipe to explore more</div>'
            f'<section id="latestGrid" class="latest-grid">{latest_html}</section>'
            '<section id="bxSmartAdSlot1" class="bx-smart-ad-slot" aria-label="Advertisement slot 1"></section>'
            '<div class="section-head"><h2>Trending</h2><span>Most-read BoxOfficeX stories</span></div>'
            '<div class="mobile-swipe-hint">↔ Swipe to explore more</div>'
            f'<section class="trending">{trending_html}</section>'
            '<section id="bxSmartAdSlot2" class="bx-smart-ad-slot" aria-label="Advertisement slot 2"></section>'
            '</div>'
        )

    static_shell = '<div id="content"><div class="loading">Loading latest stories...</div></div>'
    if static_shell not in template:
        raise RuntimeError("Articles list static content shell not found")
    template = template.replace(static_shell, content_html, 1)

    item_list = []
    for position, article in enumerate(articles, 1):
        slug = quote(str(article.get("slug") or ""), safe="")
        item_list.append({
            "@type": "ListItem",
            "position": position,
            "name": article.get("title") or "BoxOfficeX Article",
            "url": f"https://boxofficex.in/article/{slug}",
        })

    structured = {
        "@context": "https://schema.org",
        "@type": "CollectionPage",
        "name": "Movie News & Box Office Articles | BoxOfficeX",
        "url": "https://boxofficex.in/articles.html",
        "description": "Read the latest Indian movie news, box-office reports, theatrical analysis, actor stories, rankings and entertainment articles on BoxOfficeX.",
        "mainEntity": {"@type": "ItemList", "itemListElement": item_list},
    }
    json_ld = json.dumps(structured, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    template, count = re.subn(
        r'<script\s+id="articlesStructuredData"\s+type="application/ld\+json"\s*>.*?</script>',
        f'<script id="articlesStructuredData" type="application/ld+json">{json_ld}</script>',
        template,
        count=1,
        flags=re.S | re.I,
    )
    if count != 1:
        raise RuntimeError("Articles list structured-data injection failed")

    serializable = {"articles": []}
    for article in articles:
        item = dict(article)
        for key in ("published_at", "updated_at"):
            value = item.get(key)
            if value is not None and hasattr(value, "isoformat"):
                item[key] = value.isoformat()
        serializable["articles"].append(item)

    payload = json.dumps(serializable, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    if "</head>" not in template:
        raise RuntimeError("Articles list </head> marker missing")
    template = template.replace(
        "</head>",
        f'<script>window.__BOXOFFICEX_ARTICLES_SSR_DATA__={payload};</script>\n</head>',
        1,
    )

    if 'id="content" data-ssr="1"' not in template:
        raise RuntimeError("Articles list SSR validation failed")
    if 'href="/article/' not in template and articles:
        raise RuntimeError("Articles list crawlable href validation failed")
    return template


def _refresh_articles_list_cache():
    global _articles_list_html_refreshing
    try:
        rendered = _render_articles_list_html()
        with _articles_list_html_cache_lock:
            _articles_list_html_cache["html"] = rendered
            _articles_list_html_cache["expires_at"] = time_module.monotonic() + ARTICLES_LIST_HTML_CACHE_TTL
    except Exception as exc:
        print("Articles list SSR cache refresh failed:", type(exc).__name__, exc, flush=True)
    finally:
        with _articles_list_html_cache_lock:
            _articles_list_html_refreshing = False


def _start_articles_list_refresh():
    global _articles_list_html_refreshing
    with _articles_list_html_cache_lock:
        if _articles_list_html_refreshing:
            return
        _articles_list_html_refreshing = True
    threading.Thread(target=_refresh_articles_list_cache, name="articles-list-ssr", daemon=True).start()


@app.on_event("startup")
def warm_articles_list_ssr_cache():
    _start_articles_list_refresh()


@app.get("/articles.html")
def articles_page():
    now = time_module.monotonic()
    with _articles_list_html_cache_lock:
        cached_html = _articles_list_html_cache.get("html")
        expires_at = float(_articles_list_html_cache.get("expires_at") or 0.0)

    if cached_html and expires_at > now:
        return HTMLResponse(content=cached_html, headers={
            "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
            "X-BoxOfficeX-Articles-List": "cached-ssr",
            "X-BoxOfficeX-Cache": "HIT",
        })

    if cached_html:
        _start_articles_list_refresh()
        return HTMLResponse(content=cached_html, headers={
            "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
            "X-BoxOfficeX-Articles-List": "cached-ssr",
            "X-BoxOfficeX-Cache": "STALE",
        })

    _start_articles_list_refresh()
    return FileResponse(BASE_DIR / "articles.html", headers={
        "Cache-Control": "no-store",
        "X-BoxOfficeX-Articles-List": "warming",
        "X-BoxOfficeX-Cache": "WARMING",
    })



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

    # SEO / quality protection: only meaningful box-office movies are
    # allowed into the public comparison system. Day-wise data is not required.
    ineligible = [
        {"id": row[0], "title": row[1], "worldwide_collection_crore": row[10]}
        for row in rows
        if row[10] is None or float(row[10]) < 25
    ]

    if ineligible:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Movie comparison requires at least ₹25 crore worldwide collection for both movies",
                "minimum_worldwide_crore": 25,
                "ineligible_movies": ineligible,
            }
        )

    def movie_to_dict(row):

        slug_map = _unique_movie_slug_map()
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
            "poster": safe_movie_poster(row[12]),
            "slug": slug_map.get(
                row[0],
                movie_seo_slug(row[0], row[1], row[2])
            )
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

    canonical_movie_ids = sorted([movie1_id, movie2_id])
    canonical_movie_1 = movies_by_id[canonical_movie_ids[0]]
    canonical_movie_2 = movies_by_id[canonical_movie_ids[1]]

    slug_map = _unique_movie_slug_map()
    slug1 = slug_map.get(
        canonical_movie_1["id"],
        movie_seo_slug(
            canonical_movie_1["id"],
            canonical_movie_1["title"],
            canonical_movie_1["release_date"]
        )
    )
    slug2 = slug_map.get(
        canonical_movie_2["id"],
        movie_seo_slug(
            canonical_movie_2["id"],
            canonical_movie_2["title"],
            canonical_movie_2["release_date"]
        )
    )
    canonical_slug = f"{slug1}-vs-{slug2}"

    return {
        "movie1": movie1,
        "movie2": movie2,
        "winners": winners,
        "seo": {
            "canonical_ids": canonical_movie_ids,
            "canonical_slug": canonical_slug,
            "canonical_url": f"/compare/movies/{canonical_slug}",
            "minimum_worldwide_crore": 25
        }
    }



def resolve_movie_comparison_slug(comparison_slug: str):
    slug_map = _unique_movie_slug_map()
    by_slug = {slug: movie_id for movie_id, slug in slug_map.items()}

    # Movie slugs themselves can contain "-vs-", so test known canonical
    # movie slugs rather than splitting the string blindly.
    movie_ids = sorted(slug_map.keys())

    for first_id in movie_ids:
        first_slug = slug_map[first_id]
        prefix = first_slug + "-vs-"

        if not comparison_slug.startswith(prefix):
            continue

        second_slug = comparison_slug[len(prefix):]
        second_id = by_slug.get(second_slug)

        if second_id is None or second_id == first_id:
            continue

        canonical_ids = sorted([first_id, second_id])
        canonical_first_id, canonical_second_id = canonical_ids
        canonical_slug = (
            f"{slug_map[canonical_first_id]}-vs-{slug_map[canonical_second_id]}"
        )

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, title, release_date, worldwide_collection_crore
                    FROM movies
                    WHERE id IN (%s, %s)
                """, (first_id, second_id))
                rows = cur.fetchall()

        movies = {
            row[0]: {
                "id": row[0],
                "title": row[1],
                "release_date": str(row[2]) if row[2] else None,
                "worldwide_collection_crore":
                    float(row[3]) if row[3] is not None else None,
                "slug": slug_map[row[0]]
            }
            for row in rows
        }

        if len(movies) != 2:
            return None

        # Public comparison pages require reliable worldwide gross data
        # and the ₹25 crore minimum.
        for movie_id in canonical_ids:
            gross = movies[movie_id]["worldwide_collection_crore"]
            if gross is None or gross < 25:
                return None

        return {
            "movie1": movies[canonical_first_id],
            "movie2": movies[canonical_second_id],
            "canonical_slug": canonical_slug,
            "canonical_url": f"/compare/movies/{canonical_slug}",
            "is_canonical": comparison_slug == canonical_slug
        }

    return None


# ============================================================
# MOVIE COMPARISON - NON-BLOCKING CACHED SSR
# ============================================================

MOVIE_COMPARISON_HTML_CACHE_TTL = 300
_movie_comparison_html_cache = {}
_movie_comparison_cache_lock = threading.Lock()
_movie_comparison_refreshing = set()


def _movie_comparison_ssr_text(value):
    value = str(value or "").strip()
    return value if value else "N/A"


def _movie_comparison_ssr_money(value):
    try:
        return f"₹{float(value):,.2f} Cr"
    except (TypeError, ValueError):
        return "N/A"


def _movie_comparison_ssr_date(value):
    value = str(value or "").strip()
    if not value:
        return "N/A"
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").strftime("%d %b %Y")
    except Exception:
        return value


def _movie_comparison_ssr_poster(movie):
    title = str(movie.get("title") or "Movie").strip()
    poster = str(movie.get("poster") or "").strip()
    if poster and poster != DEFAULT_MOVIE_POSTER:
        if _is_remote_image(poster) or poster.startswith("/"):
            return poster
        return f"/posters/{quote(poster, safe='')}"
    return _home_movie_placeholder({"title": title})


def _render_movie_comparison_html(comparison):
    template = _inject_boxofficex_global_icons((BASE_DIR / "movie-compare.html").read_text(encoding="utf-8"))

    movie1_ref = comparison["movie1"]
    movie2_ref = comparison["movie2"]
    payload = compare_movies(int(movie1_ref["id"]), int(movie2_ref["id"]))
    a = payload["movie1"]
    b = payload["movie2"]
    winners = payload.get("winners") or {}

    title_a = str(a.get("title") or movie1_ref.get("title") or "Movie").strip()
    title_b = str(b.get("title") or movie2_ref.get("title") or "Movie").strip()
    url_a = f"/movie/{movie1_ref['slug']}"
    url_b = f"/movie/{movie2_ref['slug']}"
    canonical_path = comparison["canonical_url"]
    canonical_url = f"https://boxofficex.in{canonical_path}"

    # CTR metadata only. Keep the visible movie-comparison UI unchanged.
    page_title = f"{title_a} vs {title_b}: Box Office, Budget & Verdict | BoxOfficeX"

    def ctr_money(value):
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(number):
            return None
        if abs(number - round(number)) < 0.05:
            return f"{int(round(number)):,}"
        return f"{number:,.1f}".rstrip("0").rstrip(".")

    def budget_multiple(movie):
        try:
            budget = float(movie.get("budget_crore"))
            worldwide = float(movie.get("worldwide_collection_crore"))
        except (TypeError, ValueError):
            return None
        if (
            not math.isfinite(budget)
            or not math.isfinite(worldwide)
            or budget <= 0
            or worldwide <= 0
        ):
            return None
        return worldwide / budget

    worldwide_a = ctr_money(a.get("worldwide_collection_crore"))
    worldwide_b = ctr_money(b.get("worldwide_collection_crore"))
    multiple_a = budget_multiple(a)
    multiple_b = budget_multiple(b)
    verdict_a = str(a.get("verdict") or "").strip()
    verdict_b = str(b.get("verdict") or "").strip()

    description_parts = [f"{title_a} vs {title_b} Box Office:"]

    if worldwide_a is not None and worldwide_b is not None:
        description_parts.append(
            f"₹{worldwide_a} Cr vs ₹{worldwide_b} Cr worldwide."
        )

    if multiple_a is not None and multiple_b is not None:
        description_parts.append(
            f"Theatrical performance: {multiple_a:.1f}× vs {multiple_b:.1f}× reported budget."
        )

    if verdict_a and verdict_b:
        description_parts.append(
            f"Verdicts: {verdict_a} vs {verdict_b}."
        )

    description_parts.append(
        "Compare budgets, India & overseas collections."
    )
    description = " ".join(description_parts)

    poster_a = _movie_comparison_ssr_poster(a)
    poster_b = _movie_comparison_ssr_poster(b)

    def movie_card(movie, movie_title, movie_url, poster_src):
        meta = " • ".join(
            item for item in [
                _movie_comparison_ssr_text(movie.get("language"))
                if movie.get("language") else "",
                _movie_comparison_ssr_date(movie.get("release_date"))
                if movie.get("release_date") else "",
            ]
            if item
        )
        return (
            '<div class="movie-card">'
            f'<a href="{html_escape(movie_url, quote=True)}" '
            f'aria-label="{html_escape(movie_title, quote=True)} movie page" '
            'style="color:inherit;text-decoration:none">'
            f'<img src="{html_escape(poster_src, quote=True)}" '
            f'alt="{html_escape(movie_title, quote=True)}" loading="lazy">'
            f'<div class="bx-movie-card-title">{html_escape(movie_title)}</div></a>'
            f'<p>{html_escape(meta or "Movie")}</p></div>'
        )

    def row(label, field, formatter=_movie_comparison_ssr_text, winner_key=None):
        va = a.get(field)
        vb = b.get(field)
        left = formatter(va)
        right = formatter(vb)
        winner = (winners.get(winner_key) or {}).get("winner") if winner_key else None

        left_class = "cell value"
        right_class = "cell value"
        if winner == a.get("id"):
            left_class += " winner"
        elif winner == b.get("id"):
            right_class += " winner"
        elif winner == "tie":
            left_class += " tie"
            right_class += " tie"

        if va is None or str(va).strip() == "":
            left_class += " na"
        if vb is None or str(vb).strip() == "":
            right_class += " na"

        return (
            '<div class="row">'
            f'<div class="cell label">{html_escape(label)}</div>'
            f'<div class="{left_class}">{html_escape(left)}</div>'
            f'<div class="{right_class}">{html_escape(right)}</div>'
            '</div>'
        )

    def related_comparisons_html():
        try:
            catalogue = (comparison_eligible_movies() or {}).get("movies") or []
        except Exception:
            catalogue = []

        slug_map = _unique_movie_slug_map()
        current_ids = {int(a["id"]), int(b["id"])}
        candidates = []
        for item in catalogue:
            try:
                item_id = int(item.get("id"))
            except (TypeError, ValueError):
                continue
            if item_id in current_ids:
                continue
            candidates.append(item)

        # Keep the same compact six-link discovery pattern used by the client.
        picked = candidates[:6]
        links = []
        for index, other in enumerate(picked):
            base = a if index % 2 == 0 else b
            try:
                base_id = int(base["id"])
                other_id = int(other["id"])
            except (TypeError, ValueError, KeyError):
                continue

            base_slug = movie1_ref["slug"] if base_id == int(movie1_ref["id"]) else movie2_ref["slug"]
            other_slug = str(
                other.get("slug")
                or slug_map.get(other_id)
                or movie_seo_slug(
                    other_id,
                    other.get("title"),
                    other.get("release_date")
                )
                or ""
            ).strip()
            if not base_slug or not other_slug:
                continue

            ordered = sorted(
                [(base_id, base_slug), (other_id, other_slug)],
                key=lambda item: item[0],
            )
            href = (
                f"/compare/movies/{quote(ordered[0][1], safe='')}"
                f"-vs-{quote(ordered[1][1], safe='')}"
            )

            base_title = str(base.get("title") or "Movie").strip()
            other_title = str(other.get("title") or "Movie").strip()
            base_poster = _movie_comparison_ssr_poster(base)
            other_poster = _movie_comparison_ssr_poster(other)

            links.append(
                f'<a class="more-movie-card" href="{html_escape(href, quote=True)}" '
                f'aria-label="Compare {html_escape(base_title, quote=True)} vs '
                f'{html_escape(other_title, quote=True)}">'
                '<div class="more-movie-pair">'
                '<div class="more-movie-person">'
                f'<img src="{html_escape(base_poster, quote=True)}" '
                f'alt="{html_escape(base_title, quote=True)}" loading="lazy">'
                f'<span class="more-movie-name">{html_escape(base_title)}</span></div>'
                '<div class="more-movie-vs">VS</div>'
                '<div class="more-movie-person">'
                f'<img src="{html_escape(other_poster, quote=True)}" '
                f'alt="{html_escape(other_title, quote=True)}" loading="lazy">'
                f'<span class="more-movie-name">{html_escape(other_title)}</span></div>'
                '</div><div class="more-movie-action">Compare now →</div></a>'
            )

        if not links:
            return ""

        return (
            '<section class="more-movie-comparisons" id="moreMovieComparisons" '
            'aria-labelledby="moreMovieComparisonsTitle">'
            '<div class="more-movie-head"><div>'
            '<h2 class="more-movie-title" id="moreMovieComparisonsTitle">'
            f'{html_escape(title_a)} vs {html_escape(title_b)} Related Movie Comparisons</h2>'
            f'<p class="more-movie-sub">Keep comparing {html_escape(title_a)} and '
            f'{html_escape(title_b)} with other eligible movies.</p></div>'
            '<a class="more-movie-all" href="/movie-compare-select.html">'
            'Choose movies →</a></div>'
            f'<div class="more-movie-grid" id="moreMovieComparisonsGrid">{"".join(links)}</div>'
            '</section>'
        )

    def seo_money(value):
        try:
            return f"₹{float(value):,.2f} Cr"
        except (TypeError, ValueError):
            return "not available"

    intro_bits = []
    if a.get("worldwide_collection_crore") is not None and b.get("worldwide_collection_crore") is not None:
        intro_bits.append(
            f'<strong>{html_escape(title_a)}</strong> has {html_escape(seo_money(a.get("worldwide_collection_crore")))} worldwide gross compared with '
            f'<strong>{html_escape(title_b)}</strong> at {html_escape(seo_money(b.get("worldwide_collection_crore")))}.'
        )
    if a.get("budget_crore") is not None and b.get("budget_crore") is not None:
        intro_bits.append(
            f'Their reported budgets are {html_escape(seo_money(a.get("budget_crore")))} and {html_escape(seo_money(b.get("budget_crore")))} respectively.'
        )
    if a.get("india_collection_crore") is not None and b.get("india_collection_crore") is not None:
        intro_bits.append(
            f'India gross stands at {html_escape(seo_money(a.get("india_collection_crore")))} versus {html_escape(seo_money(b.get("india_collection_crore")))}.'
        )
    if a.get("overseas_collection_crore") is not None and b.get("overseas_collection_crore") is not None:
        intro_bits.append(
            f'Overseas gross is {html_escape(seo_money(a.get("overseas_collection_crore")))} versus {html_escape(seo_money(b.get("overseas_collection_crore")))}.'
        )
    intro_text = " ".join(intro_bits) or (
        f'Compare {html_escape(title_a)} and {html_escape(title_b)} across budget, India gross, overseas gross, worldwide collection and verdict.'
    )

    top_intro_html = (
        '<div class="bx-mc-top-intro">'
        f'<p>{intro_text}</p>'
        '</div>'
    )

    seo_intro_html = (
        '<section class="bx-mc-seo">'
        f'<h2>{html_escape(title_a)} vs {html_escape(title_b)} Box Office &amp; Budget Comparison</h2>'
        f'<h3>{html_escape(title_a)} vs {html_escape(title_b)} Collection &amp; Verdict Details</h3>'
        '<p>The comparison table below shows release details, budget, India and overseas gross, worldwide collection and reported verdict for both movies.</p>'
        '</section>'
    )

    faq_html = (
        '<section class="bx-mc-seo bx-mc-faq">'
        f'<h2>{html_escape(title_a)} vs {html_escape(title_b)} Box Office FAQ</h2>'
        f'<details><summary>What is the worldwide collection of {html_escape(title_a)} and {html_escape(title_b)}?</summary><p>'
        f'{html_escape(title_a)} has {html_escape(seo_money(a.get("worldwide_collection_crore")))} worldwide gross, while {html_escape(title_b)} has {html_escape(seo_money(b.get("worldwide_collection_crore")))}.</p></details>'
        f'<details><summary>What is the budget of {html_escape(title_a)} and {html_escape(title_b)}?</summary><p>'
        f'The reported budgets are {html_escape(seo_money(a.get("budget_crore")))} for {html_escape(title_a)} and {html_escape(seo_money(b.get("budget_crore")))} for {html_escape(title_b)}.</p></details>'
        f'<details><summary>What are the India and overseas collections?</summary><p>{html_escape(title_a)} has {html_escape(seo_money(a.get("india_collection_crore")))} India gross and {html_escape(seo_money(a.get("overseas_collection_crore")))} overseas gross. {html_escape(title_b)} has {html_escape(seo_money(b.get("india_collection_crore")))} India gross and {html_escape(seo_money(b.get("overseas_collection_crore")))} overseas gross.</p></details>'
        f'<details><summary>What are the verdicts of {html_escape(title_a)} and {html_escape(title_b)}?</summary><p>{html_escape(title_a)} is listed as <strong>{html_escape(_movie_comparison_ssr_text(a.get("verdict")))}</strong>, while {html_escape(title_b)} is listed as <strong>{html_escape(_movie_comparison_ssr_text(b.get("verdict")))}</strong>.</p></details>'
        '</section>'
    )

    content = (
        '<main id="app" data-ssr="1">'
        '<div class="top"><div class="eyebrow">BoxOfficeX Movie Comparison</div>'
        f'<h1>{html_escape(title_a)} vs {html_escape(title_b)} Box Office Comparison</h1>'
        '<a class="change" href="/movie-compare-select.html">↔ Change Movies</a></div>'
        + top_intro_html
        + '<section class="movie-heads">'
        + movie_card(a, title_a, url_a, poster_a)
        + '<div class="vs">VS</div>'
        + movie_card(b, title_b, url_b, poster_b)
        + '</section>'
        + seo_intro_html
        + '<section class="table">'
        + row("Release Date", "release_date", _movie_comparison_ssr_date)
        + row("Language", "language")
        + row("Industry", "industry")
        + row("Genre", "genre")
        + row("Director", "director")
        + row("Budget", "budget_crore", _movie_comparison_ssr_money, "budget")
        + row("India Gross", "india_collection_crore", _movie_comparison_ssr_money, "india_collection")
        + row("Overseas Gross", "overseas_collection_crore", _movie_comparison_ssr_money, "overseas_collection")
        + row("Worldwide Gross", "worldwide_collection_crore", _movie_comparison_ssr_money, "worldwide_collection")
        + row("Verdict", "verdict")
        + '</section>'
        '<section id="bxSmartAdSlot1" class="bx-smart-ad-slot" aria-label="Advertisement slot 1"></section>'
        + faq_html
        + related_comparisons_html()
        + '<div class="bx-ssr-comparison-note">'
        f'<p><strong>{html_escape(title_a)} vs {html_escape(title_b)}</strong> '
        'includes budget, India gross, overseas gross, worldwide collection and verdict. '
        'Interactive scoring, Fan Zone, comments, sponsorships and live engagement load in the browser.</p>'
        '</div></main>'
    )

    static_app_shell = '<main id="app"><div class="loading">Loading comparison...</div></main>'
    ssr_app_pattern = re.compile(
        r'<main\b[^>]*\bid="app"[^>]*>.*?</main>',
        flags=re.S | re.I,
    )

    if static_app_shell in template:
        template = template.replace(static_app_shell, content, 1)
    elif ssr_app_pattern.search(template):
        template = ssr_app_pattern.sub(lambda _match: content, template, count=1)
    else:
        raise RuntimeError("Movie comparison SSR app shell not found")

    # Never cache a metadata-only SSR response.
    if '<main id="app" data-ssr="1">' not in template:
        raise RuntimeError("Movie comparison SSR body injection failed")

    safe_title = html_escape(page_title, quote=True)
    safe_description = html_escape(description, quote=True)
    safe_canonical = html_escape(canonical_url, quote=True)
    safe_og_image = html_escape(
        poster_a if poster_a.startswith(("http://", "https://"))
        else f"https://boxofficex.in{poster_a}",
        quote=True,
    )

    template = re.sub(
        r'<title>.*?</title>',
        f'<title>{safe_title}</title>',
        template,
        count=1,
        flags=re.S,
    )
    template = re.sub(
        r'<meta id="metaDescription" name="description" content="[^"]*">',
        f'<meta id="metaDescription" name="description" content="{safe_description}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<link id="canonicalUrl" rel="canonical" href="[^"]*">',
        f'<link id="canonicalUrl" rel="canonical" href="{safe_canonical}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="ogTitle" property="og:title" content="[^"]*">',
        f'<meta id="ogTitle" property="og:title" content="{safe_title}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="ogDescription" property="og:description" content="[^"]*">',
        f'<meta id="ogDescription" property="og:description" content="{safe_description}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="ogUrl" property="og:url" content="[^"]*">',
        f'<meta id="ogUrl" property="og:url" content="{safe_canonical}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="ogImage" property="og:image" content="[^"]*">',
        f'<meta id="ogImage" property="og:image" content="{safe_og_image}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="twitterTitle" name="twitter:title" content="[^"]*">',
        f'<meta id="twitterTitle" name="twitter:title" content="{safe_title}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="twitterDescription" name="twitter:description" content="[^"]*">',
        f'<meta id="twitterDescription" name="twitter:description" content="{safe_description}">',
        template,
        count=1,
    )
    template = re.sub(
        r'<meta id="twitterImage" name="twitter:image" content="[^"]*">',
        f'<meta id="twitterImage" name="twitter:image" content="{safe_og_image}">',
        template,
        count=1,
    )

    structured = {
        "@context": "https://schema.org",
        "@type": "WebPage",
        "name": f"{title_a} vs {title_b} Box Office Comparison",
        "url": canonical_url,
        "description": description,
        "isPartOf": {
            "@type": "WebSite",
            "name": "BoxOfficeX",
            "url": "https://boxofficex.in/",
        },
        "about": [
            {
                "@type": "Movie",
                "name": title_a,
                "url": f"https://boxofficex.in{url_a}",
                "image": (
                    poster_a if poster_a.startswith(("http://", "https://"))
                    else f"https://boxofficex.in{poster_a}"
                ),
            },
            {
                "@type": "Movie",
                "name": title_b,
                "url": f"https://boxofficex.in{url_b}",
                "image": (
                    poster_b if poster_b.startswith(("http://", "https://"))
                    else f"https://boxofficex.in{poster_b}"
                ),
            },
        ],
    }
    json_ld = json.dumps(structured, ensure_ascii=False).replace("</", "<\\/")
    template = re.sub(
        r'<script id="comparisonStructuredData" type="application/ld\+json">.*?</script>',
        f'<script id="comparisonStructuredData" type="application/ld+json">{json_ld}</script>',
        template,
        count=1,
        flags=re.S,
    )

    return template


def _refresh_movie_comparison_cache(comparison_slug, comparison):
    try:
        rendered = _render_movie_comparison_html(comparison)
        with _movie_comparison_cache_lock:
            _movie_comparison_html_cache[comparison_slug] = {
                "html": rendered,
                "expires_at": time_module.monotonic() + MOVIE_COMPARISON_HTML_CACHE_TTL,
            }
    except Exception as exc:
        print(
            "Movie Comparison SSR refresh failed:",
            comparison_slug,
            type(exc).__name__,
            exc,
            flush=True,
        )
    finally:
        with _movie_comparison_cache_lock:
            _movie_comparison_refreshing.discard(comparison_slug)


def _start_movie_comparison_refresh(comparison_slug, comparison):
    with _movie_comparison_cache_lock:
        if comparison_slug in _movie_comparison_refreshing:
            return False
        _movie_comparison_refreshing.add(comparison_slug)

    threading.Thread(
        target=_refresh_movie_comparison_cache,
        args=(comparison_slug, comparison),
        daemon=True,
        name=f"movie-compare-ssr-{comparison_slug[:40]}",
    ).start()
    return True


def _get_movie_comparison_cached_html(comparison_slug, comparison):
    now = time_module.monotonic()

    with _movie_comparison_cache_lock:
        cached = _movie_comparison_html_cache.get(comparison_slug)
        if cached and cached.get("html"):
            if float(cached.get("expires_at") or 0) > now:
                return cached["html"], "HIT"
            stale_html = cached["html"]
        else:
            stale_html = None

    _start_movie_comparison_refresh(comparison_slug, comparison)

    if stale_html is not None:
        return stale_html, "STALE"

    return None, "WARMING"


@app.get("/compare/movies/{comparison_slug}", include_in_schema=False)
def movie_comparison_slug_page(comparison_slug: str):
    comparison = resolve_movie_comparison_slug(comparison_slug)

    if not comparison:
        raise HTTPException(status_code=404, detail="Movie comparison not found")

    if not comparison.get("is_canonical", True):
        return RedirectResponse(url=comparison["canonical_url"], status_code=301)

    try:
        rendered, cache_state = _get_movie_comparison_cached_html(
            comparison_slug,
            comparison,
        )

        if rendered is not None:
            return HTMLResponse(
                content=rendered,
                status_code=200,
                headers={
                    "Cache-Control": "public, max-age=60, stale-while-revalidate=240",
                    "X-BoxOfficeX-Movie-Comparison": "cached-ssr",
                    "X-BoxOfficeX-Cache": cache_state,
                },
            )

        # Cold cache never waits for the expensive comparison renderer.
        # But do not expose generic SEO metadata while the cache warms:
        # build a lightweight comparison-specific shell from the already-resolved
        # movie references, then let the existing JavaScript render the page.
        cold_template = _inject_boxofficex_global_icons((BASE_DIR / "movie-compare.html").read_text(encoding="utf-8"))
        cold_a = str(comparison["movie1"].get("title") or "Movie").strip()
        cold_b = str(comparison["movie2"].get("title") or "Movie").strip()
        cold_title = (
            f"{cold_a} vs {cold_b}: Box Office, Budget & Verdict | BoxOfficeX"
        )
        cold_description = (
            f"{cold_a} vs {cold_b} Box Office: compare budgets, India gross, "
            f"overseas gross, worldwide collections, theatrical performance and verdicts."
        )
        cold_canonical = f"https://boxofficex.in{comparison['canonical_url']}"

        safe_cold_title = html_escape(cold_title, quote=True)
        safe_cold_description = html_escape(cold_description, quote=True)
        safe_cold_canonical = html_escape(cold_canonical, quote=True)

        cold_template = re.sub(
            r'<title\b[^>]*>.*?</title>',
            f'<title>{safe_cold_title}</title>',
            cold_template,
            count=1,
            flags=re.S | re.I,
        )
        cold_template = re.sub(
            r'<meta\b(?=[^>]*\bid=["\\\']metaDescription["\\\'])(?=[^>]*\bname=["\\\']description["\\\'])[^>]*>',
            f'<meta id="metaDescription" name="description" content="{safe_cold_description}">',
            cold_template,
            count=1,
            flags=re.I,
        )
        cold_template = re.sub(
            r'<link\b(?=[^>]*\bid=["\\\']canonicalUrl["\\\'])(?=[^>]*\brel=["\\\']canonical["\\\'])[^>]*>',
            f'<link id="canonicalUrl" rel="canonical" href="{safe_cold_canonical}">',
            cold_template,
            count=1,
            flags=re.I,
        )

        return HTMLResponse(
            content=cold_template,
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Movie-Comparison": "warming-specific-seo",
                "X-BoxOfficeX-Cache": "WARMING",
            },
        )

    except Exception as exc:
        print(
            "Movie Comparison SSR fallback:",
            comparison_slug,
            type(exc).__name__,
            exc,
            flush=True,
        )
        _start_movie_comparison_refresh(comparison_slug, comparison)
        return FileResponse(
            BASE_DIR / "movie-compare.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Movie-Comparison": "ssr-fallback",
                "X-BoxOfficeX-Cache": "FALLBACK",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
            },
        )


@app.get("/seo/resolve/movie-comparison/{comparison_slug}", include_in_schema=False)
def seo_resolve_movie_comparison(comparison_slug: str):
    comparison = resolve_movie_comparison_slug(comparison_slug)
    if not comparison:
        raise HTTPException(status_code=404, detail="Movie comparison not found")
    return comparison


@app.get("/seo/resolve/movie-comparison-by-ids/{movie1_id}/{movie2_id}", include_in_schema=False)
def seo_resolve_movie_comparison_by_ids(movie1_id: int, movie2_id: int):
    if movie1_id == movie2_id:
        raise HTTPException(status_code=400, detail="Choose two different movies")

    slug_map = _unique_movie_slug_map()

    if movie1_id not in slug_map or movie2_id not in slug_map:
        raise HTTPException(status_code=404, detail="Movie not found")

    canonical_ids = sorted([movie1_id, movie2_id])

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, release_date, worldwide_collection_crore
                FROM movies
                WHERE id IN (%s, %s)
            """, (canonical_ids[0], canonical_ids[1]))
            rows = cur.fetchall()

    if len(rows) != 2:
        raise HTTPException(status_code=404, detail="Movie not found")

    movies = {
        row[0]: {
            "id": row[0],
            "title": row[1],
            "release_date": str(row[2]) if row[2] else None,
            "worldwide_collection_crore":
                float(row[3]) if row[3] is not None else None,
            "slug": slug_map[row[0]]
        }
        for row in rows
    }

    for movie_id in canonical_ids:
        gross = movies[movie_id]["worldwide_collection_crore"]
        if gross is None or gross < 25:
            raise HTTPException(
                status_code=404,
                detail="Movie comparison is not eligible for public indexing"
            )

    canonical_slug = (
        f"{slug_map[canonical_ids[0]]}-vs-{slug_map[canonical_ids[1]]}"
    )

    return {
        "movie1": movies[canonical_ids[0]],
        "movie2": movies[canonical_ids[1]],
        "canonical_slug": canonical_slug,
        "canonical_url": f"/compare/movies/{canonical_slug}"
    }


MOVIE_COMPARE_SELECT_CACHE_TTL = 300
_movie_compare_select_html_cache = {"html": None, "expires_at": 0.0}
_movie_compare_select_html_cache_lock = threading.Lock()



# ============================================================
# ACTOR COMPARE SELECT — SSR TRENDING + FAQ
# ============================================================
ACTOR_COMPARE_SELECT_CACHE_TTL = 21600
_actor_compare_select_html_cache = {"html": None, "built_at": 0.0}
_actor_compare_select_cache_lock = threading.Lock()


def _actor_compare_select_trending_rows(limit: int = 5):
    """
    Fast Actor Compare Select rotation.

    Deliberately avoids the four engagement-table UNION query and the
    actor_movies/movies aggregation on every page render. Uses the same
    curated high-value comparison pool already used by the actor comparison
    sitemap, then rotates five pairs every six hours.
    """
    limit = max(1, min(int(limit or 5), 10))

    comparison_pairs = [
        ("Vijay", "Ajith Kumar"),
        ("Rajinikanth", "Kamal Haasan"),
        ("Vijay", "Rajinikanth"),
        ("Vijay", "Suriya"),
        ("Ajith Kumar", "Suriya"),
        ("Prabhas", "Allu Arjun"),
        ("Prabhas", "Ram Charan"),
        ("Prabhas", "N. T. Rama Rao Jr."),
        ("Allu Arjun", "Ram Charan"),
        ("Mahesh Babu", "N. T. Rama Rao Jr."),
        ("Shah Rukh Khan", "Salman Khan"),
        ("Shah Rukh Khan", "Aamir Khan"),
        ("Salman Khan", "Aamir Khan"),
        ("Ranbir Kapoor", "Hrithik Roshan"),
        ("Shah Rukh Khan", "Ranbir Kapoor"),
        ("Mohanlal", "Mammootty"),
        ("Dulquer Salmaan", "Fahadh Faasil"),
        ("Mohanlal", "Prithviraj Sukumaran"),
        ("Mammootty", "Dulquer Salmaan"),
        ("Fahadh Faasil", "Prithviraj Sukumaran"),
        ("Yash", "Kichcha Sudeep"),
        ("Yash", "Darshan"),
        ("Yash", "Rishab Shetty"),
        ("Kichcha Sudeep", "Darshan"),
        ("Shiva Rajkumar", "Rishab Shetty"),
    ]

    required_names = sorted({
        name.strip().lower()
        for pair in comparison_pairs
        for name in pair
    })

    try:
        # ONE lightweight DB query only.
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, name
                    FROM actors
                    WHERE LOWER(TRIM(name)) = ANY(%s)
                """, (required_names,))
                actor_rows = list(cur.fetchall())
    except Exception as exc:
        print("Actor Compare Select fast pool failed:",
              type(exc).__name__, exc, flush=True)
        return []

    if len(actor_rows) < 2:
        return []

    actors_by_name = {
        str(actor_name).strip().lower(): (int(actor_id), str(actor_name))
        for actor_id, actor_name in actor_rows
    }

    # Important performance fix: build slugs from the rows already fetched.
    # This prevents public_actor_comparison_url() from rebuilding the full
    # actor slug map five separate times.
    actor_slug_map = _unique_actor_slug_map(actor_rows)

    prepared = []
    for first_name, second_name in comparison_pairs:
        first = actors_by_name.get(first_name.lower())
        second = actors_by_name.get(second_name.lower())
        if not first or not second:
            continue

        first_id, first_db_name = first
        second_id, second_db_name = second
        first_slug = actor_slug_map.get(first_id)
        second_slug = actor_slug_map.get(second_id)
        if not first_slug or not second_slug:
            continue

        if first_id > second_id:
            first_id, second_id = second_id, first_id
            first_db_name, second_db_name = second_db_name, first_db_name
            first_slug, second_slug = second_slug, first_slug

        public_url = f"/compare/{first_slug}-vs-{second_slug}"
        prepared.append((
            first_id, second_id,
            first_db_name, second_db_name,
            0, None, "featured", public_url
        ))

    if not prepared:
        return []

    rotation_slot = int(datetime.now(timezone.utc).timestamp() // (6 * 60 * 60))
    start_index = (rotation_slot * limit) % len(prepared)
    rotated = prepared[start_index:] + prepared[:start_index]
    return rotated[:limit]

def _render_actor_compare_select_html():
    template_path = os.path.join(BASE_DIR, "compare-select.html")
    with open(template_path, "r", encoding="utf-8") as fh:
        template = _inject_boxofficex_global_icons(fh.read())

    rows = _actor_compare_select_trending_rows(5)
    cards = []
    item_list = []

    for index, row in enumerate(rows, start=1):
        actor1_id, actor2_id, name1, name2, activity_count, _last_activity, source_type, url = row

        if source_type == "trending":
            meta = f"{int(activity_count or 0)} recent interaction" + ("" if int(activity_count or 0) == 1 else "s")
        else:
            meta = "Featured comparison • rotates automatically"

        safe_name1 = html.escape(str(name1))
        safe_name2 = html.escape(str(name2))
        safe_meta = html.escape(meta)

        cards.append(
            f'<a class="trending-actor-card" href="{url}">'
            f'<span class="trending-actor-rank">{index}</span>'
            f'<span><span class="trending-actor-title">{safe_name1} vs {safe_name2}</span>'
            f'<span class="trending-actor-meta">{safe_meta}</span></span>'
            f'<span class="trending-actor-arrow" aria-hidden="true">→</span>'
            f'</a>'
        )
        item_list.append({
            "@type": "ListItem",
            "position": index,
            "name": f"{name1} vs {name2}",
            "url": url if str(url).startswith("http") else f"https://boxofficex.in{url}",
        })

    cards_html = "".join(cards) if cards else (
        '<div class="trending-actor-empty">Select two actors above to start comparing.</div>'
    )

    template = re.sub(
        r'(<div\s+id=["\']trendingActorComparisonsList["\'][^>]*>).*?(</div>\s*</section>)',
        lambda m: m.group(1) + cards_html + m.group(2),
        template,
        count=1,
        flags=re.I | re.S,
    )

    faq_entities = [
        {
            "@type": "Question",
            "name": "How does BoxOfficeX compare two actors?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "BoxOfficeX compares available career data such as movies, box-office collections, hits, blockbusters and overall career performance."
            }
        },
        {
            "@type": "Question",
            "name": "Can I compare actors from different Indian film industries?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "Yes. You can select any two available actors in the BoxOfficeX database and open their comparison page."
            }
        },
        {
            "@type": "Question",
            "name": "What information is shown in an actor comparison?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "Comparison pages can include movie totals, worldwide box office, verdict performance, highest-grossing films and other available career statistics."
            }
        },
        {
            "@type": "Question",
            "name": "How are trending actor comparisons selected?",
            "acceptedAnswer": {
                "@type": "Answer",
                "text": "Recent audience comparison activity is prioritized. When activity is limited, BoxOfficeX automatically features rotating actor matchups."
            }
        }
    ]

    graph = [
        {
            "@type": "WebPage",
            "@id": "https://boxofficex.in/compare-select.html#webpage",
            "url": "https://boxofficex.in/compare-select.html",
            "name": "Compare Indian Actors – Movies, Box Office & Career | BoxOfficeX",
            "description": "Compare two actors on BoxOfficeX by movies, box office collections, hits, blockbusters and career performance."
        },
        {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://boxofficex.in/"},
                {"@type": "ListItem", "position": 2, "name": "Actor Comparison", "item": "https://boxofficex.in/compare-select.html"}
            ]
        },
        {
            "@type": "ItemList",
            "name": "Trending Actor Comparisons",
            "itemListElement": item_list
        },
        {
            "@type": "FAQPage",
            "mainEntity": faq_entities
        }
    ]

    schema = json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False)
    schema_tag = (
        '<script id="compareSelectStructuredData" type="application/ld+json" '
        'data-ssr="1">' + schema.replace("</", "<\\/") + "</script>"
    )
    template = re.sub(
        r'<script\s+id=["\']compareSelectStructuredData["\'][^>]*>.*?</script>',
        schema_tag,
        template,
        count=1,
        flags=re.I | re.S,
    )

    return template


def _get_actor_compare_select_html():
    now = time_module.time()
    cached = _actor_compare_select_html_cache.get("html")
    built_at = float(_actor_compare_select_html_cache.get("built_at") or 0)

    if cached and now - built_at < ACTOR_COMPARE_SELECT_CACHE_TTL:
        return cached

    with _actor_compare_select_cache_lock:
        now = time_module.time()
        cached = _actor_compare_select_html_cache.get("html")
        built_at = float(_actor_compare_select_html_cache.get("built_at") or 0)
        if cached and now - built_at < ACTOR_COMPARE_SELECT_CACHE_TTL:
            return cached

        rendered = _render_actor_compare_select_html()
        _actor_compare_select_html_cache["html"] = rendered
        _actor_compare_select_html_cache["built_at"] = now
        return rendered


def _movie_compare_select_trending_rows(limit: int = 5):
    """
    Always return up to `limit` useful movie comparisons.

    Real 7-day engagement is preferred when the engagement tables are available.
    If those tables are empty, missing, or have an older schema, the selector
    still works by using automatically rotating high-grossing movie matchups.
    """
    limit = max(1, min(int(limit or 5), 10))
    recent_rows = []

    # Recent engagement is optional. It must never be allowed to break the page.
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    WITH recent_activity AS (
                        SELECT movie1_id, movie2_id, created_at FROM movie_comparison_likes
                        UNION ALL
                        SELECT movie1_id, movie2_id, created_at FROM movie_comparison_hype
                        UNION ALL
                        SELECT movie1_id, movie2_id, created_at FROM movie_comparison_votes
                        UNION ALL
                        SELECT movie1_id, movie2_id, created_at FROM movie_comparison_comments
                    )
                    SELECT
                        ra.movie1_id,
                        ra.movie2_id,
                        m1.title,
                        m2.title,
                        COUNT(*)::bigint AS activity_count,
                        MAX(ra.created_at) AS last_activity,
                        'trending'::text AS source_type
                    FROM recent_activity ra
                    JOIN movies m1 ON m1.id = ra.movie1_id
                    JOIN movies m2 ON m2.id = ra.movie2_id
                    WHERE ra.created_at >= NOW() - INTERVAL '7 days'
                      AND COALESCE(m1.worldwide_collection_crore, 0) >= 25
                      AND COALESCE(m2.worldwide_collection_crore, 0) >= 25
                    GROUP BY ra.movie1_id, ra.movie2_id, m1.title, m2.title
                    ORDER BY activity_count DESC, last_activity DESC
                    LIMIT %s
                """, (limit,))
                recent_rows = list(cur.fetchall())
    except Exception as exc:
        print(
            "Movie Compare Select recent activity unavailable; using rotating fallback:",
            type(exc).__name__,
            exc,
            flush=True,
        )
        recent_rows = []

    if len(recent_rows) >= limit:
        return recent_rows[:limit]

    # IMPORTANT: use a fresh DB connection here. If the optional activity query
    # failed, its PostgreSQL transaction is aborted; a fresh connection keeps
    # the fallback independent and guarantees the page can still render.
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, title
                    FROM movies
                    WHERE COALESCE(worldwide_collection_crore, 0) >= 25
                    ORDER BY worldwide_collection_crore DESC NULLS LAST, id ASC
                    LIMIT 20
                """)
                movie_pool = list(cur.fetchall())
    except Exception as exc:
        print(
            "Movie Compare Select fallback movie pool failed:",
            type(exc).__name__,
            exc,
            flush=True,
        )
        return recent_rows

    if len(movie_pool) < 2:
        return recent_rows

    used_pairs = {
        tuple(sorted((int(row[0]), int(row[1]))))
        for row in recent_rows
    }

    # Deterministic 6-hour rotation: all visitors see the same five pairs
    # during a slot, then the featured matchups change automatically.
    rotation_slot = int(datetime.now(timezone.utc).timestamp() // (6 * 60 * 60))
    pool_size = len(movie_pool)
    start_index = rotation_slot % pool_size
    rotated = movie_pool[start_index:] + movie_pool[:start_index]

    fallback_rows = []
    for gap in (1, 3, 5, 7, 9):
        for i in range(pool_size):
            left = rotated[i]
            right = rotated[(i + gap) % pool_size]

            if int(left[0]) == int(right[0]):
                continue

            pair = tuple(sorted((int(left[0]), int(right[0]))))
            if pair in used_pairs:
                continue

            used_pairs.add(pair)
            fallback_rows.append((
                left[0],
                right[0],
                left[1],
                right[1],
                0,
                None,
                "featured",
            ))

            if len(recent_rows) + len(fallback_rows) >= limit:
                return recent_rows + fallback_rows

    return recent_rows + fallback_rows

def _render_movie_compare_select_html():
    template = _inject_boxofficex_global_icons((BASE_DIR / "movie-compare-select.html").read_text(encoding="utf-8"))
    rows = _movie_compare_select_trending_rows(5)
    slug_map = _unique_movie_slug_map()

    cards = []
    schema_items = []
    for rank, row in enumerate(rows, start=1):
        movie1_id, movie2_id, title1, title2, activity_count, _last_activity, source_type = row
        first_id, second_id = _movie_comparison_pair(movie1_id, movie2_id)
        first_slug = slug_map.get(first_id)
        second_slug = slug_map.get(second_id)
        if not first_slug or not second_slug:
            continue

        url = f"/compare/movies/{first_slug}-vs-{second_slug}"
        label = f"{title1} vs {title2}"
        safe_url = html_escape(url, quote=True)
        safe_label = html_escape(label)
        if source_type == "trending":
            activity_text = f"{int(activity_count or 0)} recent interaction" + ("" if int(activity_count or 0) == 1 else "s")
        else:
            activity_text = "Featured comparison • rotates automatically"
        cards.append(
            f'<a class="trending-card" href="{safe_url}">'
            f'<span class="trending-rank">#{rank}</span>'
            f'<span><span class="trending-title">{safe_label}</span>'
            f'<span class="trending-meta">{html_escape(activity_text)}</span></span>'
            f'<span class="trending-arrow" aria-hidden="true">›</span>'
            f'</a>'
        )
        schema_items.append({
            "@type": "ListItem",
            "position": rank,
            "name": label,
            "url": f"https://boxofficex.in{url}",
        })

    trending_html = "\n".join(cards)
    if not trending_html:
        trending_html = (
            '<div class="trending-empty">Trending movie comparisons will appear here '
            'as visitors compare and interact with movie matchups.</div>'
        )
    template = template.replace("<!-- BOXOFFICEX_TRENDING_COMPARISONS -->", trending_html, 1)

    if schema_items:
        schema_json = json.dumps({
            "@type": "ItemList",
            "name": "Trending Movie Comparisons",
            "itemListElement": schema_items,
        }, ensure_ascii=False).replace("</", "<\\/")
        template = template.replace(
            "<!-- BOXOFFICEX_TRENDING_SCHEMA -->",
            "," + schema_json,
            1,
        )
    else:
        template = template.replace("<!-- BOXOFFICEX_TRENDING_SCHEMA -->", "", 1)

    return template


def _get_movie_compare_select_html():
    now = time_module.monotonic()
    with _movie_compare_select_html_cache_lock:
        cached = _movie_compare_select_html_cache.get("html")
        expires_at = float(_movie_compare_select_html_cache.get("expires_at") or 0)
        if cached and expires_at > now:
            return cached, "HIT"

    rendered = _render_movie_compare_select_html()
    with _movie_compare_select_html_cache_lock:
        _movie_compare_select_html_cache["html"] = rendered
        _movie_compare_select_html_cache["expires_at"] = now + MOVIE_COMPARE_SELECT_CACHE_TTL
    return rendered, "MISS"


@app.get("/movie-compare-select.html")
def movie_compare_select_page():
    try:
        rendered, cache_state = _get_movie_compare_select_html()
        return HTMLResponse(
            content=rendered,
            headers={
                "Cache-Control": "public, max-age=300, stale-while-revalidate=600",
                "X-BoxOfficeX-Movie-Compare-Select": "ssr",
                "X-BoxOfficeX-Cache": cache_state,
            },
        )
    except Exception as exc:
        print("Movie Compare Select SSR fallback:", type(exc).__name__, exc, flush=True)
        return FileResponse(
            BASE_DIR / "movie-compare-select.html",
            headers={
                "Cache-Control": "no-store",
                "X-BoxOfficeX-Movie-Compare-Select": "ssr-fallback",
                "X-BoxOfficeX-SSR-Error": type(exc).__name__,
            },
        )


@app.get("/movie-compare.html", include_in_schema=False)
def movie_compare_page(
    movie1: Optional[int] = None,
    movie2: Optional[int] = None
):
    if movie1 is None or movie2 is None:
        return RedirectResponse(url="/movie-compare-select.html", status_code=301)

    if movie1 == movie2:
        raise HTTPException(status_code=400, detail="Choose two different movies")

    canonical_url = public_movie_comparison_url(movie1, movie2)
    if canonical_url == "/movie-compare-select.html":
        raise HTTPException(status_code=404, detail="Movie comparison not found")

    # Verify the clean comparison is actually eligible/indexable.
    comparison_slug = canonical_url.removeprefix("/compare/movies/")
    if not resolve_movie_comparison_slug(comparison_slug):
        raise HTTPException(status_code=404, detail="Movie comparison not found")

    return RedirectResponse(url=canonical_url, status_code=301)




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
def admin_list_all_comments(
    status: Literal["all", "reported", "visible", "hidden"] = "all",
    limit: int = 100,
    offset: int = 0,
):
    limit = max(1, min(limit, 250))
    offset = max(0, offset)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                WITH unified AS (

                    SELECT
                        'movie'::text AS comment_type,
                        c.id AS comment_id,
                        c.display_name,
                        c.comment_text,
                        c.is_hidden,
                        c.created_at,
                        COUNT(DISTINCT l.id)::bigint AS like_count,
                        COUNT(DISTINCT r.id)::bigint AS report_count,
                        m.id::bigint AS source_id,
                        m.title::text AS source_title,
                        '/new-movies.html'::text AS source_url
                    FROM movie_comments c
                    JOIN movies m ON m.id = c.movie_id
                    LEFT JOIN movie_comment_likes l ON l.comment_id = c.id
                    LEFT JOIN movie_comment_reports r ON r.comment_id = c.id
                    WHERE c.is_deleted = FALSE
                    GROUP BY c.id, m.id, m.title

                    UNION ALL

                    SELECT
                        'article'::text,
                        c.id,
                        c.display_name,
                        c.comment_text,
                        c.is_hidden,
                        c.created_at,
                        COUNT(DISTINCT l.id)::bigint,
                        COUNT(DISTINCT r.id)::bigint,
                        a.id::bigint,
                        a.title::text,
                        ('/article/' || a.slug)::text
                    FROM article_comments c
                    JOIN articles a ON a.id = c.article_id
                    LEFT JOIN article_comment_likes l ON l.comment_id = c.id
                    LEFT JOIN article_comment_reports r ON r.comment_id = c.id
                    WHERE c.is_deleted = FALSE
                    GROUP BY c.id, a.id, a.title, a.slug

                    UNION ALL

                    SELECT
                        'hero_comparison'::text,
                        c.id,
                        c.display_name,
                        c.comment_text,
                        c.is_hidden,
                        c.created_at,
                        COUNT(DISTINCT l.id)::bigint,
                        COUNT(DISTINCT r.id)::bigint,
                        c.actor1_id::bigint,
                        (a1.name || ' vs ' || a2.name)::text,
                        '/compare-select.html'::text
                    FROM hero_comparison_comments c
                    JOIN actors a1 ON a1.id = c.actor1_id
                    JOIN actors a2 ON a2.id = c.actor2_id
                    LEFT JOIN hero_comparison_comment_likes l ON l.comment_id = c.id
                    LEFT JOIN hero_comparison_comment_reports r ON r.comment_id = c.id
                    WHERE c.is_deleted = FALSE
                    GROUP BY c.id, a1.name, a2.name

                    UNION ALL

                    SELECT
                        'movie_comparison'::text,
                        c.id,
                        c.display_name,
                        c.comment_text,
                        c.is_hidden,
                        c.created_at,
                        COUNT(DISTINCT l.id)::bigint,
                        COUNT(DISTINCT r.id)::bigint,
                        c.movie1_id::bigint,
                        (m1.title || ' vs ' || m2.title)::text,
                        '/movie-compare-select.html'::text
                    FROM movie_comparison_comments c
                    JOIN movies m1 ON m1.id = c.movie1_id
                    JOIN movies m2 ON m2.id = c.movie2_id
                    LEFT JOIN movie_comparison_comment_likes l ON l.comment_id = c.id
                    LEFT JOIN movie_comparison_comment_reports r ON r.comment_id = c.id
                    WHERE c.is_deleted = FALSE
                    GROUP BY c.id, m1.title, m2.title
                )
                SELECT
                    comment_type,
                    comment_id,
                    display_name,
                    comment_text,
                    is_hidden,
                    created_at,
                    like_count,
                    report_count,
                    source_id,
                    source_title,
                    source_url
                FROM unified
                WHERE
                    (%s = 'all')
                    OR (%s = 'reported' AND report_count > 0)
                    OR (%s = 'visible' AND is_hidden = FALSE)
                    OR (%s = 'hidden' AND is_hidden = TRUE)
                ORDER BY
                    report_count DESC,
                    created_at DESC
                LIMIT %s OFFSET %s
            """, (status, status, status, status, limit, offset))

            rows = cur.fetchall()

            cur.execute("""
                WITH unified AS (
                    SELECT
                        c.is_hidden,
                        c.is_deleted,
                        EXISTS (
                            SELECT 1 FROM movie_comment_reports r
                            WHERE r.comment_id = c.id
                        ) AS reported
                    FROM movie_comments c

                    UNION ALL

                    SELECT
                        c.is_hidden,
                        c.is_deleted,
                        EXISTS (
                            SELECT 1 FROM article_comment_reports r
                            WHERE r.comment_id = c.id
                        )
                    FROM article_comments c

                    UNION ALL

                    SELECT
                        c.is_hidden,
                        c.is_deleted,
                        EXISTS (
                            SELECT 1 FROM hero_comparison_comment_reports r
                            WHERE r.comment_id = c.id
                        )
                    FROM hero_comparison_comments c

                    UNION ALL

                    SELECT
                        c.is_hidden,
                        c.is_deleted,
                        EXISTS (
                            SELECT 1 FROM movie_comparison_comment_reports r
                            WHERE r.comment_id = c.id
                        )
                    FROM movie_comparison_comments c
                )
                SELECT
                    COUNT(*) FILTER (WHERE is_deleted = FALSE),
                    COUNT(*) FILTER (WHERE is_deleted = FALSE AND is_hidden = TRUE),
                    COUNT(*) FILTER (WHERE is_deleted = FALSE AND reported = TRUE)
                FROM unified
            """)
            summary = cur.fetchone()

    comments = [
        {
            "comment_type": row[0],
            "id": row[1],
            "display_name": row[2],
            "comment_text": row[3],
            "is_hidden": row[4],
            "created_at": row[5].isoformat() if row[5] else None,
            "like_count": int(row[6] or 0),
            "report_count": int(row[7] or 0),
            "source_id": row[8],
            "source_title": row[9],
            "source_url": row[10],
        }
        for row in rows
    ]

    return {
        "total": len(comments),
        "summary": {
            "comments": int(summary[0] or 0),
            "hidden": int(summary[1] or 0),
            "reported": int(summary[2] or 0),
        },
        "comments": comments,
    }


_ADMIN_COMMENT_TABLES = {
    "movie": "movie_comments",
    "article": "article_comments",
    "hero_comparison": "hero_comparison_comments",
    "movie_comparison": "movie_comparison_comments",
}


def _admin_comment_table(comment_type: str) -> str:
    table = _ADMIN_COMMENT_TABLES.get(comment_type)
    if not table:
        raise HTTPException(status_code=400, detail="Invalid comment type")
    return table


@app.put(
    "/admin/comments/{comment_type}/{comment_id}/visibility",
    dependencies=[Depends(require_owner)]
)
def admin_toggle_any_comment_visibility(comment_type: str, comment_id: int):
    table = _admin_comment_table(comment_type)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE {table}
                SET is_hidden = NOT is_hidden,
                    updated_at = NOW()
                WHERE id = %s
                  AND is_deleted = FALSE
                RETURNING is_hidden
                """,
                (comment_id,)
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Comment not found")

            conn.commit()

    return {
        "success": True,
        "comment_type": comment_type,
        "comment_id": comment_id,
        "is_hidden": row[0],
    }


@app.delete(
    "/admin/comments/{comment_type}/{comment_id}",
    dependencies=[Depends(require_owner)]
)
def admin_delete_any_comment(comment_type: str, comment_id: int):
    table = _admin_comment_table(comment_type)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE {table}
                SET is_deleted = TRUE,
                    is_hidden = TRUE,
                    updated_at = NOW()
                WHERE id = %s
                  AND is_deleted = FALSE
                RETURNING id
                """,
                (comment_id,)
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Comment not found")

            conn.commit()

    return {
        "success": True,
        "deleted": True,
        "comment_type": comment_type,
        "comment_id": comment_id,
    }


# Backward-compatible movie-only moderation routes.
@app.put("/admin/comments/{comment_id}/visibility", dependencies=[Depends(require_owner)])
def admin_toggle_comment_visibility(comment_id: int):
    return admin_toggle_any_comment_visibility("movie", comment_id)


@app.delete("/admin/comments/{comment_id}", dependencies=[Depends(require_owner)])
def admin_delete_movie_comment(comment_id: int):
    return admin_delete_any_comment("movie", comment_id)


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
                "url": public_movie_url(r[0]),
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
    }

    target_table = {
        ("movie_views", "movie_id"): "movies",
        ("actor_views", "actor_id"): "actors",
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
    # Articles already store their public view total in articles.views.
    # Do not depend on a separate article_views table.
    _clean_visitor_id(data.visitor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE articles
                SET views = COALESCE(views, 0) + 1
                WHERE id = %s
                  AND status = 'published'
                RETURNING views
                """,
                (article_id,)
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Article not found")

        conn.commit()

    return {
        "article_id": article_id,
        "counted": True,
        "views": int(row[0] or 0),
    }


@app.get("/articles/{article_id}/views")
def get_article_views(article_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(views, 0)
                FROM articles
                WHERE id = %s
                  AND status = 'published'
                """,
                (article_id,)
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Article not found")

    return {
        "article_id": article_id,
        "views": int(row[0] or 0),
    }


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
                        ''::text AS url,
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
                        ('/article/' || a.slug),
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
                        ''::text,
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
                        ''::text,
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

    items = []

    for row in rows:
        item_type = row[0]
        item_id = str(row[1])
        url = row[4]

        if item_type == "movie":
            url = public_movie_url(int(item_id))

        elif item_type == "hero_comparison":
            try:
                actor1_id, actor2_id = map(int, item_id.split("-", 1))
                url = public_actor_comparison_url(actor1_id, actor2_id)
            except (TypeError, ValueError):
                url = "/compare-select.html"

        elif item_type == "movie_comparison":
            try:
                movie1_id, movie2_id = map(int, item_id.split("-", 1))
                url = public_movie_comparison_url(movie1_id, movie2_id)
            except (TypeError, ValueError):
                url = "/movie-compare-select.html"

        items.append({
            "type": item_type,
            "id": row[1],
            "title": row[2],
            "image": row[3],
            "url": url,
            "activity_count": row[5],
            "last_activity": row[6].isoformat() if row[6] else None,
        })

    return {
        "period_days": 7,
        "items": items,
    }


# ============================================================
# BOXOFFICEX LAUNCH DASHBOARD FEATURES
# Stats + latest updates + fan leaderboards
# ============================================================

@app.get("/site/stats")
def site_stats():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM movies")
            movies = int(cur.fetchone()[0] or 0)
            cur.execute("SELECT COUNT(*) FROM actors")
            actors = int(cur.fetchone()[0] or 0)
            cur.execute("SELECT COUNT(*) FROM articles WHERE status='published'")
            articles = int(cur.fetchone()[0] or 0)
            cur.execute("SELECT COUNT(*) FROM movies WHERE worldwide_collection_crore IS NOT NULL")
            boxoffice_records = int(cur.fetchone()[0] or 0)

    return {
        "movies_tracked": movies,
        "actors_tracked": actors,
        "published_articles": articles,
        "boxoffice_records": boxoffice_records,
    }


@app.get("/latest-updates")
def latest_updates(limit: int = 10):
    limit = max(1, min(int(limit or 10), 30))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT type, item_id, title, subtitle, image, url, happened_at
                FROM (
                    SELECT
                        'article'::text AS type,
                        a.id AS item_id,
                        a.title,
                        COALESCE(a.category, 'Article') AS subtitle,
                        COALESCE(a.hero_image, '') AS image,
                        ('/article/' || a.slug) AS url,
                        COALESCE(a.updated_at, a.published_at) AS happened_at
                    FROM articles a
                    WHERE a.status='published'

                    UNION ALL

                    SELECT
                        'movie'::text,
                        m.id,
                        m.title,
                        COALESCE(m.language, '') ||
                            CASE WHEN m.industry IS NOT NULL AND m.industry <> ''
                                 THEN ' • ' || m.industry ELSE '' END,
                        COALESCE(m.poster, ''),
                        ''::text,
                        m.release_date::timestamp
                    FROM movies m
                    WHERE m.release_date IS NOT NULL
                ) x
                WHERE happened_at IS NOT NULL
                ORDER BY happened_at DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()

    return {
        "updates": [
            {
                "type": r[0],
                "id": r[1],
                "title": r[2],
                "subtitle": r[3],
                "image": r[4],
                "url": (
                    public_movie_url(r[1])
                    if r[0] == "movie"
                    else r[5]
                ),
                "happened_at": r[6].isoformat() if r[6] else None,
            }
            for r in rows
        ]
    }


@app.get("/fan-leaderboards")
def fan_leaderboards():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT m.id, m.title, COALESCE(COUNT(h.id),0) AS total
                FROM movies m
                LEFT JOIN movie_hype h ON h.movie_id=m.id
                GROUP BY m.id, m.title
                ORDER BY total DESC, m.id ASC
                LIMIT 1
            """)
            hyped = cur.fetchone()

            cur.execute("""
                SELECT m.id, m.title, COALESCE(COUNT(v.id),0) AS total
                FROM movies m
                LEFT JOIN movie_views v ON v.movie_id=m.id
                GROUP BY m.id, m.title
                ORDER BY total DESC, m.id ASC
                LIMIT 1
            """)
            viewed = cur.fetchone()

            cur.execute("""
                SELECT m.id, m.title, COALESCE(COUNT(c.id),0) AS total
                FROM movies m
                LEFT JOIN movie_comments c
                  ON c.movie_id=m.id
                 AND c.is_hidden=FALSE
                 AND c.is_deleted=FALSE
                GROUP BY m.id, m.title
                ORDER BY total DESC, m.id ASC
                LIMIT 1
            """)
            discussed = cur.fetchone()

            cur.execute("""
                SELECT a.id, a.name, COALESCE(COUNT(v.id),0) AS total
                FROM actors a
                LEFT JOIN actor_views v ON v.actor_id=a.id
                GROUP BY a.id, a.name
                ORDER BY total DESC, a.id ASC
                LIMIT 1
            """)
            actor = cur.fetchone()

    def movie_item(row, label):
        return None if not row else {
            "label": label, "id": row[0], "title": row[1],
            "count": int(row[2] or 0), "url": public_movie_url(row[0])
        }

    return {
        "leaders": [
            movie_item(hyped, "🔥 Most Hyped Movie"),
            movie_item(viewed, "👁 Most Viewed Movie"),
            movie_item(discussed, "💬 Most Discussed Movie"),
            None if not actor else {
                "label": "⭐ Most Viewed Actor",
                "id": actor[0], "title": actor[1],
                "count": int(actor[2] or 0), "url": public_actor_url(actor[0])
            }
        ]
    }


# ============================================================
# OWNER: ADVERTISEMENT MANAGEMENT
# ============================================================

ADVERTISEMENT_SELECT_COLUMNS = """
    id,
    advertiser_name,
    business_category,
    campaign_name,
    ad_type,
    media_type,
    media_url,
    mobile_media_url,
    target_url,
    placement,
    page_target,
    duration_seconds,
    frequency,
    start_date,
    end_date,
    is_active,
    amount_paid,
    impressions,
    clicks,
    completed_views,
    skips,
    created_by,
    created_at,
    updated_at,
    total_amount,
    traffic_weight,
    client_email,
    client_phone,
    billing_address,
    invoice_number,
    invoice_date,
    payment_due_date,
    billing_notes,
    ad_slot,
    movie_ranking_industry,
    actor_ranking_industry,
    target_actor_ids,
    target_movie_ids,
    target_actor_movies,
    is_draft,
    start_time,
    end_time,
    COALESCE(ad_package, 'standard'),
    COALESCE(sponsored_package, 'rotation'),
    COALESCE(exclusive_inventory, FALSE)
"""


def _clean_required_ad_text(value: str, field_name: str) -> str:
    value = (value or "").strip()

    if not value:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} is required"
        )

    return value


def _clean_optional_ad_text(value: Optional[str]):
    if value is None:
        return None

    value = value.strip()
    return value or None


def _normalize_id_list(values):
    """Store integer ID lists compactly while accepting None/list/string safely."""
    if values is None:
        return None
    if isinstance(values, str):
        raw = [v.strip() for v in values.split(",") if v.strip()]
    else:
        raw = values
    ids = []
    for value in raw:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0 and number not in ids:
            ids.append(number)
    return ",".join(str(v) for v in ids) or None


def _parse_id_list(value):
    if not value:
        return []
    return [int(v) for v in str(value).split(",") if v.strip().isdigit() and int(v) > 0]


AD_PLACEMENT_GROUPS = {
    # Exact ad-enabled public pages.
    "homepage", "new_movies", "movie_detail", "actors_list",
    "actor_detail", "actor_movies", "articles_list", "article_detail",
    "movie_rankings", "actor_rankings", "actor_compare_select",
    "actor_compare_results", "movie_compare_select", "movie_compare_results",

    # Legacy/broad groups retained so existing campaigns continue to work.
    "movie_pages", "actor_pages", "article_pages", "movie_compare",
    "actor_compare", "rankings", "search", "boxoffice_pages",
    "regional_pages", "discovery_pages", "sponsors_page",
    "selected_pages", "sitewide",
}

AD_PLACEMENT_LEGACY_ALIASES = {
    "new_movies": {"discovery_pages"},
    "movie_detail": {"movie_pages"},
    "actors_list": {"actor_pages"},
    "actor_detail": {"actor_pages"},
    "actor_movies": {"actor_pages"},
    "articles_list": {"article_pages"},
    "article_detail": {"article_pages"},
    "movie_rankings": {"rankings"},
    "actor_rankings": {"rankings"},
    "actor_compare_select": {"actor_compare"},
    "actor_compare_results": {"actor_compare"},
    "movie_compare_select": {"movie_compare"},
    "movie_compare_results": {"movie_compare"},
}

def _normalize_ad_placements(value: str) -> str:
    items = [item.strip() for item in (value or "").split(",") if item.strip()]
    if not items:
        raise HTTPException(status_code=400, detail="At least one advertisement placement is required")
    if "sitewide" in items:
        return "sitewide"
    invalid = [item for item in items if item not in AD_PLACEMENT_GROUPS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid advertisement placement: {invalid[0]}")
    # Preserve selection order while removing duplicates.
    return ",".join(dict.fromkeys(items))




def _validate_ad_slot(ad_type: str, ad_slot: Optional[int]):
    if ad_type != "in_content":
        return
    if ad_slot is None:
        raise HTTPException(
            status_code=400,
            detail="In-content advertisements require Slot 1-6 or All Available Slots"
        )
    if int(ad_slot) not in {0, 1, 2, 3, 4, 5, 6}:
        raise HTTPException(
            status_code=400,
            detail="In-content advertisement slot must be 0 (All Available) or 1-6"
        )


def _normalize_target_url(value: str) -> str:
    value = _clean_required_ad_text(value, "Target URL")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Target URL must be a valid http/https address")
    return value


def _payment_status(total_amount, amount_paid, due_date=None):
    total = float(total_amount or 0)
    paid = float(amount_paid or 0)
    if total <= 0:
        return "paid" if paid > 0 else "unpaid"
    if paid >= total:
        return "paid"
    if due_date and date.today() > due_date:
        return "overdue"
    return "partially_paid" if paid > 0 else "unpaid"

def _validate_advertisement_values(
    *,
    start_date_value: date,
    end_date_value: date,
    start_time_value: Optional[time] = None,
    end_time_value: Optional[time] = None,
    ad_type: str,
    media_type: str,
    duration_seconds: Optional[int],
    total_amount: Optional[float],
    amount_paid: Optional[float],
    traffic_weight: Optional[float]
):
    if end_date_value < start_date_value:
        raise HTTPException(
            status_code=400,
            detail="End date cannot be before start date"
        )

    if end_date_value == start_date_value and start_time_value and end_time_value and end_time_value < start_time_value:
        raise HTTPException(
            status_code=400,
            detail="End time cannot be before start time on the same date"
        )

    if duration_seconds is not None:
        if duration_seconds < 1 or duration_seconds > 60:
            raise HTTPException(
                status_code=400,
                detail="Advertisement duration must be between 1 and 60 seconds"
            )

    if (
        ad_type in {"full_screen", "small_video"}
        and media_type == "video"
        and not duration_seconds
    ):
        raise HTTPException(
            status_code=400,
            detail="Video advertisements require duration_seconds"
        )

    if total_amount is not None and total_amount < 0:
        raise HTTPException(status_code=400, detail="Total amount cannot be negative")
    if amount_paid is not None and amount_paid < 0:
        raise HTTPException(status_code=400, detail="Amount paid cannot be negative")
    if total_amount is not None and amount_paid is not None and amount_paid > total_amount:
        raise HTTPException(status_code=400, detail="Amount paid cannot exceed total amount")
    if traffic_weight is not None and (traffic_weight <= 0 or traffic_weight > 1000):
        raise HTTPException(status_code=400, detail="Traffic weight must be greater than 0 and at most 1000")



def _normalize_ad_package(value):
    value = (value or "standard").strip().lower()
    if value not in {"standard", "premium", "exclusive"}:
        raise HTTPException(status_code=400, detail="Invalid advertisement package")
    return value


def _normalize_sponsored_package(value):
    value = (value or "rotation").strip().lower()
    if value not in {"rotation", "diamond", "platinum", "gold", "silver", "bronze", "takeover"}:
        raise HTTPException(status_code=400, detail="Invalid sponsored-link package")
    return value


def advertisement_status(
    is_active: bool,
    start_date_value: date,
    end_date_value: date,
    start_time_value: Optional[time] = None,
    end_time_value: Optional[time] = None
):
    if not is_active:
        return "paused"

    now_ist = datetime.now(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None)
    starts_at = datetime.combine(start_date_value, start_time_value or time(0, 0, 0))
    ends_at = datetime.combine(end_date_value, end_time_value or time(23, 59, 59, 999999))

    if now_ist < starts_at:
        return "scheduled"
    if now_ist > ends_at:
        return "expired"
    return "active"


def advertisement_row_to_dict(row):
    impressions = int(row[17] or 0)
    clicks = int(row[18] or 0)

    ctr = (
        round((clicks / impressions) * 100, 2)
        if impressions > 0
        else 0.0
    )

    return {
        "id": row[0],
        "advertiser_name": row[1],
        "business_category": row[2],
        "campaign_name": row[3],
        "ad_type": row[4],
        "media_type": row[5],
        "media_url": row[6],
        "mobile_media_url": row[7],
        "target_url": row[8],
        "placement": row[9],
        "page_target": row[10],
        "duration_seconds": row[11],
        "frequency": row[12],
        "start_date": row[13].isoformat() if row[13] else None,
        "end_date": row[14].isoformat() if row[14] else None,
        "is_active": row[15],
        "amount_paid": (
            float(row[16])
            if row[16] is not None
            else None
        ),
        "impressions": impressions,
        "clicks": clicks,
        "ctr_percent": ctr,
        "completed_views": int(row[19] or 0),
        "skips": int(row[20] or 0),
        "created_by": row[21],
        "created_at": row[22].isoformat() if row[22] else None,
        "updated_at": row[23].isoformat() if row[23] else None,
        "total_amount": float(row[24]) if row[24] is not None else 0.0,
        "traffic_weight": float(row[25]) if row[25] is not None else 1.0,
        "client_email": row[26],
        "client_phone": row[27],
        "billing_address": row[28],
        "invoice_number": row[29] or f"BX-AD-{int(row[0]):06d}",
        "invoice_date": row[30].isoformat() if row[30] else None,
        "payment_due_date": row[31].isoformat() if row[31] else None,
        "billing_notes": row[32],
        "ad_slot": int(row[33]) if len(row) > 33 and row[33] is not None else None,
        "movie_ranking_industry": row[34] if len(row) > 34 else None,
        "actor_ranking_industry": row[35] if len(row) > 35 else None,
        "target_actor_ids": _parse_id_list(row[36]) if len(row) > 36 else [],
        "target_movie_ids": _parse_id_list(row[37]) if len(row) > 37 else [],
        "target_actor_movies": bool(row[38]) if len(row) > 38 else False,
        "is_draft": bool(row[39]) if len(row) > 39 else False,
        "start_time": row[40].isoformat(timespec="minutes") if len(row) > 40 and row[40] else None,
        "end_time": row[41].isoformat(timespec="minutes") if len(row) > 41 and row[41] else None,
        "ad_package": row[42] if len(row) > 42 and row[42] else "standard",
        "sponsored_package": row[43] if len(row) > 43 and row[43] else "rotation",
        "exclusive_inventory": bool(row[44]) if len(row) > 44 else False,
        "pending_amount": max(0.0, round(float(row[24] or 0) - float(row[16] or 0), 2)),
        "payment_status": _payment_status(row[24], row[16], row[31]),
        "status": (
            "draft"
            if (len(row) > 39 and bool(row[39]))
            else advertisement_status(row[15], row[13], row[14], row[40] if len(row) > 40 else None, row[41] if len(row) > 41 else None)
        )
    }


@app.get(
    "/admin/advertisements",
    dependencies=[Depends(require_owner)]
)
def admin_list_advertisements():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT
                    {ADVERTISEMENT_SELECT_COLUMNS}
                FROM advertisements
                ORDER BY
                    created_at DESC,
                    id DESC
            """)
            rows = cur.fetchall()

    advertisements = [
        advertisement_row_to_dict(row)
        for row in rows
    ]

    summary = {
        "total": len(advertisements),
        "active": 0,
        "scheduled": 0,
        "paused": 0,
        "expired": 0,
        "impressions": 0,
        "clicks": 0,
    }

    for ad in advertisements:
        status = ad["status"]

        if status in summary:
            summary[status] += 1

        summary["impressions"] += ad["impressions"]
        summary["clicks"] += ad["clicks"]

    summary["ctr_percent"] = (
        round(
            (summary["clicks"] / summary["impressions"]) * 100,
            2
        )
        if summary["impressions"] > 0
        else 0.0
    )

    return {
        "summary": summary,
        "advertisements": advertisements
    }


@app.get(
    "/admin/advertisements/{advertisement_id:int}",
    dependencies=[Depends(require_owner)]
)
def admin_get_advertisement(
    advertisement_id: int
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                    SELECT
                        {ADVERTISEMENT_SELECT_COLUMNS}
                    FROM advertisements
                    WHERE id = %s
                """,
                (advertisement_id,)
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Advertisement not found"
        )

    return {
        "advertisement": advertisement_row_to_dict(row)
    }


@app.post(
    "/admin/advertisements",
    dependencies=[Depends(require_owner)]
)
def admin_create_advertisement(
    data: AdvertisementCreateData,
    request: Request
):
    admin = current_admin(request)

    advertiser_name = _clean_required_ad_text(
        data.advertiser_name,
        "Advertiser name"
    )
    campaign_name = _clean_required_ad_text(
        data.campaign_name,
        "Campaign name"
    )
    media_url = _clean_required_ad_text(
        data.media_url,
        "Media URL"
    )
    target_url = _normalize_target_url(data.target_url)

    normalized_placement = _normalize_ad_placements(data.placement)

    _validate_advertisement_values(
        start_date_value=data.start_date,
        end_date_value=data.end_date,
        start_time_value=data.start_time,
        end_time_value=data.end_time,
        ad_type=data.ad_type,
        media_type=data.media_type,
        duration_seconds=data.duration_seconds,
        total_amount=data.total_amount,
        amount_paid=data.amount_paid,
        traffic_weight=data.traffic_weight
    )
    _validate_ad_slot(data.ad_type, data.ad_slot)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO advertisements (
                    advertiser_name,
                    business_category,
                    campaign_name,
                    ad_type,
                    media_type,
                    media_url,
                    mobile_media_url,
                    target_url,
                    placement,
                    page_target,
                    duration_seconds,
                    frequency,
                    start_date,
                    end_date,
                    is_active,
                    amount_paid,
                    created_by,
                    total_amount,
                    traffic_weight,
                    client_email,
                    client_phone,
                    billing_address,
                    invoice_number,
                    invoice_date,
                    payment_due_date,
                    billing_notes,
                    ad_slot,
                    movie_ranking_industry,
                    actor_ranking_industry,
                    target_actor_ids,
                    target_movie_ids,
                    target_actor_movies,
                    is_draft,
                    start_time,
                    end_time,
                    ad_package,
                    sponsored_package,
                    exclusive_inventory
                )
                VALUES (
                    %s, %s, %s,
                    %s, %s,
                    %s, %s,
                    %s,
                    %s, %s,
                    %s, %s,
                    %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s
                )
                RETURNING id
            """, (
                advertiser_name,
                _clean_optional_ad_text(data.business_category),
                campaign_name,
                data.ad_type,
                data.media_type,
                media_url,
                _clean_optional_ad_text(data.mobile_media_url),
                target_url,
                normalized_placement,
                _clean_optional_ad_text(data.page_target),
                data.duration_seconds,
                data.frequency,
                data.start_date,
                data.end_date,
                data.is_active,
                data.amount_paid,
                admin["id"],
                data.total_amount,
                data.traffic_weight or 1.0,
                _clean_optional_ad_text(data.client_email),
                _clean_optional_ad_text(data.client_phone),
                _clean_optional_ad_text(data.billing_address),
                _clean_optional_ad_text(data.invoice_number),
                data.invoice_date,
                data.payment_due_date,
                _clean_optional_ad_text(data.billing_notes),
                data.ad_slot,
                _clean_optional_ad_text(data.movie_ranking_industry),
                _clean_optional_ad_text(data.actor_ranking_industry),
                _normalize_id_list(data.target_actor_ids),
                _normalize_id_list(data.target_movie_ids),
                bool(data.target_actor_movies),
                bool(data.is_draft),
                data.start_time,
                data.end_time,
                _normalize_ad_package(data.ad_package),
                _normalize_sponsored_package(data.sponsored_package),
                bool(data.exclusive_inventory)
            ))

            advertisement_id = cur.fetchone()[0]

        conn.commit()

    return {
        "success": True,
        "message": "Advertisement draft saved successfully" if data.is_draft else "Advertisement created successfully",
        "advertisement_id": advertisement_id
    }


@app.put(
    "/admin/advertisements/{advertisement_id:int}",
    dependencies=[Depends(require_owner)]
)
def admin_update_advertisement(
    advertisement_id: int,
    data: AdvertisementUpdateData
):
    update_data = data.model_dump(
        exclude_unset=True
    )

    if not update_data:
        raise HTTPException(
            status_code=400,
            detail="No advertisement changes supplied"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    advertiser_name,
                    campaign_name,
                    ad_type,
                    media_type,
                    media_url,
                    target_url,
                    start_date,
                    end_date,
                    duration_seconds,
                    amount_paid,
                    total_amount,
                    traffic_weight,
                    ad_slot,
                    start_time,
                    end_time
                FROM advertisements
                WHERE id = %s
            """, (advertisement_id,))

            existing = cur.fetchone()

            if not existing:
                raise HTTPException(
                    status_code=404,
                    detail="Advertisement not found"
                )

            prospective_ad_type = update_data.get(
                "ad_type",
                existing[2]
            )
            prospective_media_type = update_data.get(
                "media_type",
                existing[3]
            )
            prospective_start_date = update_data.get(
                "start_date",
                existing[6]
            )
            prospective_end_date = update_data.get(
                "end_date",
                existing[7]
            )
            prospective_duration = update_data.get(
                "duration_seconds",
                existing[8]
            )
            prospective_amount = update_data.get("amount_paid", existing[9])
            prospective_total = update_data.get("total_amount", existing[10])
            prospective_weight = update_data.get("traffic_weight", existing[11])
            prospective_ad_slot = update_data.get("ad_slot", existing[12])
            prospective_start_time = update_data.get("start_time", existing[13])
            prospective_end_time = update_data.get("end_time", existing[14])

            _validate_advertisement_values(
                start_date_value=prospective_start_date,
                end_date_value=prospective_end_date,
                start_time_value=prospective_start_time,
                end_time_value=prospective_end_time,
                ad_type=prospective_ad_type,
                media_type=prospective_media_type,
                duration_seconds=prospective_duration,
                total_amount=float(prospective_total) if prospective_total is not None else None,
                amount_paid=float(prospective_amount) if prospective_amount is not None else None,
                traffic_weight=float(prospective_weight) if prospective_weight is not None else None
            )
            _validate_ad_slot(prospective_ad_type, prospective_ad_slot)

            required_text_fields = {
                "advertiser_name": "Advertiser name",
                "campaign_name": "Campaign name",
                "media_url": "Media URL",
                "target_url": "Target URL",
            }

            optional_text_fields = {
                "business_category",
                "mobile_media_url",
                "page_target",
                "client_email",
                "client_phone",
                "billing_address",
                "invoice_number",
                "billing_notes",
                "movie_ranking_industry",
                "actor_ranking_industry",
                "target_actor_ids",
                "target_movie_ids",
                "target_actor_movies",
                "is_draft",
            }

            allowed_fields = {
                "advertiser_name",
                "business_category",
                "campaign_name",
                "ad_type",
                "media_type",
                "media_url",
                "mobile_media_url",
                "target_url",
                "placement",
                "page_target",
                "duration_seconds",
                "frequency",
                "start_date",
                "start_time",
                "end_date",
                "end_time",
                "is_active",
                "amount_paid",
                "total_amount",
                "traffic_weight",
                "client_email",
                "client_phone",
                "billing_address",
                "invoice_number",
                "invoice_date",
                "payment_due_date",
                "billing_notes",
                "ad_slot",
                "movie_ranking_industry",
                "actor_ranking_industry",
                "target_actor_ids",
                "target_movie_ids",
                "target_actor_movies",
                "is_draft",
                "ad_package",
                "sponsored_package",
                "exclusive_inventory",
                "suggested_rate",
                "final_rate",
            }

            if "placement" in update_data:
                update_data["placement"] = _normalize_ad_placements(update_data["placement"])

            fields = []
            values = []

            for field, value in update_data.items():
                if field not in allowed_fields:
                    continue

                if field == "target_url":
                    value = _normalize_target_url(value)
                elif field in {"target_actor_ids", "target_movie_ids"}:
                    value = _normalize_id_list(value)
                elif field == "ad_package":
                    value = _normalize_ad_package(value)
                elif field == "sponsored_package":
                    value = _normalize_sponsored_package(value)
                elif field in required_text_fields:
                    value = _clean_required_ad_text(
                        value,
                        required_text_fields[field]
                    )
                elif field in optional_text_fields:
                    value = _clean_optional_ad_text(value)

                fields.append(f"{field} = %s")
                values.append(value)

            if not fields:
                raise HTTPException(
                    status_code=400,
                    detail="No valid advertisement changes supplied"
                )

            fields.append("updated_at = NOW()")
            values.append(advertisement_id)

            cur.execute(
                f"""
                    UPDATE advertisements
                    SET {", ".join(fields)}
                    WHERE id = %s
                """,
                tuple(values)
            )

        conn.commit()

    return {
        "success": True,
        "message": "Advertisement updated successfully"
    }


@app.patch(
    "/admin/advertisements/{advertisement_id:int}/status",
    dependencies=[Depends(require_owner)]
)
def admin_set_advertisement_status(
    advertisement_id: int,
    data: AdvertisementStatusData
):
    """Set exactly one campaign to the requested active state."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE advertisements
                SET
                    is_active = %s,
                    is_draft = CASE WHEN %s THEN FALSE ELSE is_draft END,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, is_active, is_draft
            """, (bool(data.is_active), bool(data.is_active), advertisement_id))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Advertisement not found")
        conn.commit()
    return {
        "success": True,
        "advertisement_id": row[0],
        "is_active": bool(row[1]),
        "is_draft": bool(row[2]),
        "message": "Draft activated as live campaign" if row[1] else "Advertisement paused"
    }


@app.patch(
    "/admin/advertisements/{advertisement_id:int}/toggle",
    dependencies=[Depends(require_owner)]
)
def admin_toggle_advertisement(
    advertisement_id: int
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE advertisements
                SET
                    is_active = NOT is_active,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING is_active
            """, (advertisement_id,))

            row = cur.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Advertisement not found"
                )

        conn.commit()

    return {
        "success": True,
        "is_active": row[0],
        "message": (
            "Advertisement activated"
            if row[0]
            else "Advertisement paused"
        )
    }


@app.delete(
    "/admin/advertisements/{advertisement_id:int}",
    dependencies=[Depends(require_owner)]
)
def admin_delete_advertisement(
    advertisement_id: int
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM advertisements
                WHERE id = %s
            """, (advertisement_id,))

            if cur.rowcount == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Advertisement not found"
                )

        conn.commit()

    return {
        "success": True,
        "message": "Advertisement deleted successfully"
    }



# ============================================================
# OWNER: ADVERTISEMENT BILLING / PDF INVOICES
# ============================================================

def _pdf_escape(value):
    return str(value or "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_simple_invoice_pdf(invoice: dict) -> bytes:
    lines = [
        "BOXOFFICEX - ADVERTISING INVOICE",
        "",
        f"Invoice: {invoice['invoice_number']}",
        f"Invoice date: {invoice['invoice_date']}",
        f"Advertiser: {invoice['advertiser_name']}",
        f"Email: {invoice.get('client_email') or '-'}",
        f"Phone: {invoice.get('client_phone') or '-'}",
        f"Billing address: {invoice.get('billing_address') or '-'}",
        "",
        f"Campaign: {invoice['campaign_name']}",
        f"Ad type: {invoice['ad_type']}",
        f"Pages: {invoice['placement']}",
        f"Campaign period: {invoice['start_date']} to {invoice['end_date']}",
        f"Traffic weight: {invoice['traffic_weight']}",
        "",
        "CAMPAIGN PERFORMANCE SNAPSHOT",
        f"Impressions: {int(invoice.get('impressions') or 0):,}",
        f"Clicks: {int(invoice.get('clicks') or 0):,}",
        f"CTR: {(int(invoice.get('clicks') or 0) / int(invoice.get('impressions') or 1) * 100) if int(invoice.get('impressions') or 0) > 0 else 0:.2f}%",
        f"Completed video views: {int(invoice.get('completed_views') or 0):,}",
        f"Skips: {int(invoice.get('skips') or 0):,}",
        "",
        f"Total amount: INR {float(invoice['total_amount'] or 0):,.2f}",
        f"Amount paid: INR {float(invoice['amount_paid'] or 0):,.2f}",
        f"Pending balance: INR {float(invoice['pending_amount'] or 0):,.2f}",
        f"Payment status: {str(invoice['payment_status']).replace('_', ' ').title()}",
        f"Payment due: {invoice.get('payment_due_date') or '-'}",
        "",
        f"Notes: {invoice.get('billing_notes') or '-'}",
        "",
        "Thank you for advertising with BoxOfficeX.",
    ]
    wrapped=[]
    for line in lines:
        wrapped.extend(textwrap.wrap(str(line), width=88) or [""])
    y=790
    content=["BT", "/F1 16 Tf", "50 815 Td", f"({_pdf_escape(wrapped[0])}) Tj", "/F1 10 Tf"]
    first=True
    for line in wrapped[1:]:
        content.append("0 -18 Td")
        content.append(f"({_pdf_escape(line)}) Tj")
    content.append("ET")
    stream="\n".join(content).encode("latin-1", "replace")
    objects=[]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
    objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    pdf=bytearray(b"%PDF-1.4\n")
    offsets=[0]
    for i,obj in enumerate(objects,1):
        offsets.append(len(pdf)); pdf.extend(f"{i} 0 obj\n".encode()); pdf.extend(obj); pdf.extend(b"\nendobj\n")
    xref=len(pdf)
    pdf.extend(f"xref\n0 {len(objects)+1}\n".encode()); pdf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]: pdf.extend(f"{off:010d} 00000 n \n".encode())
    pdf.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(pdf)


@app.post("/admin/advertisements/{advertisement_id:int}/invoice", dependencies=[Depends(require_owner)])
def admin_generate_advertisement_invoice(advertisement_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT advertiser_name, client_email, client_phone, billing_address,
                       campaign_name, ad_type, placement, start_date, end_date,
                       traffic_weight, total_amount, amount_paid, payment_due_date,
                       billing_notes, invoice_number, invoice_date,
                       impressions, clicks, completed_views, skips
                FROM advertisements WHERE id = %s
            """, (advertisement_id,))
            row=cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Advertisement not found")
            total=float(row[10] or 0); paid=float(row[11] or 0); pending=max(0.0, round(total-paid,2))
            inv_date=row[15] or date.today()
            base=(row[14] or f"BX-AD-{advertisement_id:06d}").strip()
            invoice_number=f"{base}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            status=_payment_status(total, paid, row[12])
            cur.execute("""
                INSERT INTO advertisement_invoices (
                    advertisement_id, invoice_number, invoice_date, advertiser_name,
                    client_email, client_phone, billing_address, campaign_name, ad_type,
                    placement, start_date, end_date, traffic_weight, total_amount,
                    amount_paid, pending_amount, payment_status, payment_due_date, billing_notes,
                    impressions, clicks, completed_views, skips
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
            """, (advertisement_id, invoice_number, inv_date, row[0], row[1], row[2], row[3],
                  row[4], row[5], row[6], row[7], row[8], row[9] or 1, total, paid, pending,
                  status, row[12], row[13], int(row[16] or 0), int(row[17] or 0),
                  int(row[18] or 0), int(row[19] or 0)))
            invoice_id=cur.fetchone()[0]
        conn.commit()
    return {"success": True, "invoice_id": invoice_id, "invoice_number": invoice_number,
            "download_url": f"/admin/invoices/{invoice_id}/pdf"}


@app.get("/admin/advertisements/{advertisement_id:int}/invoices", dependencies=[Depends(require_owner)])
def admin_advertisement_invoice_history(advertisement_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, invoice_number, invoice_date, total_amount, amount_paid,
                       pending_amount, payment_status, created_at
                FROM advertisement_invoices WHERE advertisement_id=%s
                ORDER BY created_at DESC
            """, (advertisement_id,))
            rows=cur.fetchall()
    return {"invoices": [{"id":r[0],"invoice_number":r[1],"invoice_date":r[2].isoformat(),
                           "total_amount":float(r[3] or 0),"amount_paid":float(r[4] or 0),
                           "pending_amount":float(r[5] or 0),"payment_status":r[6],
                           "created_at":r[7].isoformat()} for r in rows]}


@app.get("/admin/invoices/{invoice_id}/pdf", dependencies=[Depends(require_owner)])
def admin_download_invoice_pdf(invoice_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT invoice_number, invoice_date, advertiser_name, client_email, client_phone,
                       billing_address, campaign_name, ad_type, placement, start_date, end_date,
                       traffic_weight, total_amount, amount_paid, pending_amount, payment_status,
                       payment_due_date, billing_notes, impressions, clicks, completed_views, skips
                FROM advertisement_invoices WHERE id=%s
            """, (invoice_id,))
            row=cur.fetchone()
    if not row: raise HTTPException(status_code=404, detail="Invoice not found")
    keys=["invoice_number","invoice_date","advertiser_name","client_email","client_phone","billing_address",
          "campaign_name","ad_type","placement","start_date","end_date","traffic_weight","total_amount",
          "amount_paid","pending_amount","payment_status","payment_due_date","billing_notes",
          "impressions","clicks","completed_views","skips"]
    invoice=dict(zip(keys,row))
    pdf=_build_simple_invoice_pdf(invoice)
    filename=re.sub(r"[^A-Za-z0-9._-]+","-",invoice["invoice_number"])+".pdf"
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# ============================================================
# PUBLIC ADVERTISEMENT DELIVERY + TRACKING
# ============================================================

PUBLIC_AD_SELECT_COLUMNS = """
    id,
    advertiser_name,
    business_category,
    campaign_name,
    ad_type,
    media_type,
    media_url,
    mobile_media_url,
    target_url,
    placement,
    page_target,
    duration_seconds,
    frequency,
    start_date,
    end_date,
    is_active,
    traffic_weight,
    ad_slot,
    movie_ranking_industry,
    actor_ranking_industry,
    target_actor_ids,
    target_movie_ids,
    target_actor_movies,
    is_draft,
    start_time,
    end_time
"""


def _ad_matches_precise_target(ad: dict, placement: Optional[str], actor_id: Optional[int], movie_id: Optional[int]) -> bool:
    actor_ids = _parse_id_list(ad.get("target_actor_ids"))
    movie_ids = _parse_id_list(ad.get("target_movie_ids"))

    if placement in {"actor_detail", "actor_movies"} and actor_ids:
        if not actor_id or int(actor_id) not in actor_ids:
            return False

    if placement == "movie_detail" and movie_ids:
        if not movie_id or int(movie_id) not in movie_ids:
            return False

    # A movie campaign selected through an actor may target all of that actor's movies.
    if placement == "movie_detail" and ad.get("target_actor_movies") and actor_ids and not movie_ids:
        if not movie_id:
            return False
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM actor_movies
                    WHERE movie_id=%s AND actor_id = ANY(%s)
                    LIMIT 1
                """, (int(movie_id), actor_ids))
                if not cur.fetchone():
                    return False
    return True


def _weighted_pick(items, count=1):
    """Weighted sampling without replacement; deterministic safety for zero/invalid weights."""
    import random
    pool = list(items)
    selected = []
    count = max(0, min(int(count), len(pool)))
    while pool and len(selected) < count:
        weights = [max(0.0001, float(item.get("traffic_weight") or 1)) for item in pool]
        chosen = random.choices(pool, weights=weights, k=1)[0]
        selected.append(chosen)
        pool.remove(chosen)
    return selected


def _inventory_key(ad: dict):
    if ad.get("ad_type") == "in_content":
        return f"in_content:{int(ad.get('ad_slot') or 1)}"
    return str(ad.get("ad_type") or "unknown")


@app.get("/ads/active")
def get_active_public_advertisements(
    placement: Optional[str] = None,
    page: Optional[str] = None,
    ranking_industry: Optional[str] = None,
    actor_id: Optional[int] = None,
    movie_id: Optional[int] = None
):
    today = date.today()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {PUBLIC_AD_SELECT_COLUMNS}
                FROM advertisements
                WHERE is_active = TRUE
                  AND is_draft = FALSE
                  AND (start_date + COALESCE(start_time, TIME '00:00:00')) <= (NOW() AT TIME ZONE 'Asia/Kolkata')
                  AND (end_date + COALESCE(end_time, TIME '23:59:59.999999')) >= (NOW() AT TIME ZONE 'Asia/Kolkata')
                ORDER BY random()
                """,
                ()
            )
            rows = cur.fetchall()

    ads = []

    for row in rows:
        ad = dict(zip(
            [
                "id", "advertiser_name", "business_category",
                "campaign_name", "ad_type", "media_type",
                "media_url", "mobile_media_url", "target_url",
                "placement", "page_target", "duration_seconds",
                "frequency", "start_date", "end_date", "is_active",
                "traffic_weight", "ad_slot",
                "movie_ranking_industry", "actor_ranking_industry",
                "target_actor_ids", "target_movie_ids", "target_actor_movies", "is_draft",
                "start_time", "end_time"
            ],
            row
        ))

        placement_groups = {
            item.strip()
            for item in (ad.get("placement") or "").split(",")
            if item.strip()
        }

        if placement:
            compatible_placements = {placement}
            compatible_placements.update(
                AD_PLACEMENT_LEGACY_ALIASES.get(placement, set())
            )
            allowed = (
                "sitewide" in placement_groups
                or bool(placement_groups.intersection(compatible_placements))
            )
            if not allowed:
                continue

        # Optional industry/language targeting for ranking pages.
        if placement in {"movie_rankings", "actor_rankings"} and ranking_industry:
            requested = ranking_industry.strip().lower()
            selected = (
                ad.get("movie_ranking_industry")
                if placement == "movie_rankings"
                else ad.get("actor_ranking_industry")
            )
            selected = (selected or "*").strip().lower()
            if selected not in {"*", "all", "all industries"} and selected != requested:
                continue

        if "selected_pages" in placement_groups:
            target = (ad.get("page_target") or "").strip()
            if not page or not target:
                continue

            # Normalize public pretty URLs to the page keys saved by Admin.
            # Example:
            #   browser: /article/jailer-2-600-crore-pre-release-business
            #   admin target: /article.html (or article.html)
            requested_page = str(page).strip()
            requested_path = requested_page.split("?", 1)[0].rstrip("/") or "/"

            page_aliases = {requested_page, requested_path}

            if requested_path.startswith("/article/"):
                page_aliases.update({
                    "/article.html",
                    "article.html",
                    "article_detail",
                })

            # Accept both leading-slash and no-leading-slash forms.
            page_aliases.update({
                p[1:] if p.startswith("/") else "/" + p
                for p in list(page_aliases)
                if p and p != "/"
            })

            targets = {
                item.strip()
                for item in target.split(",")
                if item.strip()
            }

            normalized_targets = set(targets)
            normalized_targets.update({
                p[1:] if p.startswith("/") else "/" + p
                for p in list(targets)
                if p and p != "/"
            })

            if page_aliases.isdisjoint(normalized_targets):
                continue

        if not _ad_matches_precise_target(ad, placement, actor_id, movie_id):
            continue

        for key in ("start_date", "end_date", "start_time", "end_time"):
            if ad.get(key):
                ad[key] = ad[key].isoformat()

        if ad.get("ad_type") == "in_content" and ad.get("ad_slot") == 0:
            expanded = []
            for slot_no in range(1, 7):
                virtual = dict(ad)
                virtual["ad_slot"] = slot_no
                # Unique negative virtual ID per slot while preserving source campaign ID.
                virtual["source_advertisement_id"] = int(ad["id"])
                virtual["id"] = -(abs(int(ad["id"])) * 10 + slot_no)
                expanded.append(virtual)
            ads.extend(expanded)
        else:
            ads.append(ad)

    return {
        "advertisements": ads
    }


@app.post("/ads/{advertisement_id}/impression")
def track_advertisement_impression(advertisement_id: int):
    advertisement_id = abs(advertisement_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE advertisements
                SET impressions = impressions + 1,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id
                """,
                (advertisement_id,)
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    return {"success": True}


@app.post("/ads/{advertisement_id}/click")
def track_advertisement_click(advertisement_id: int):
    advertisement_id = abs(advertisement_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE advertisements
                SET clicks = clicks + 1,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id
                """,
                (advertisement_id,)
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    return {"success": True}


@app.post("/ads/{advertisement_id}/complete")
def track_advertisement_complete(advertisement_id: int):
    advertisement_id = abs(advertisement_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE advertisements
                SET completed_views = completed_views + 1,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id
                """,
                (advertisement_id,)
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    return {"success": True}


@app.post("/ads/{advertisement_id}/skip")
def track_advertisement_skip(advertisement_id: int):
    advertisement_id = abs(advertisement_id)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE advertisements
                SET skips = skips + 1,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id
                """,
                (advertisement_id,)
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Advertisement not found")

    return {"success": True}




# ============================================================
# BOXOFFICEX AD V2: ROTATION + MASTER INVENTORY
# ============================================================

AD_ROTATION_CAPACITY = 5
SPONSORED_LINK_VISIBLE_LIMIT = 10
MASTER_PUBLIC_PLACEMENTS = [
    "homepage", "new_movies", "movie_detail", "actors_list", "actor_detail",
    "actor_movies", "articles_list", "article_detail", "movie_rankings",
    "actor_rankings", "actor_compare_select", "actor_compare_results",
    "movie_compare_select", "movie_compare_results",
]
MASTER_STANDARD_TYPES = [
    "full_screen", "top_banner", "top_sticky", "bottom_sticky", "small_video",
]


def _fetch_eligible_ads_for_inventory(placement: str, actor_id=None, movie_id=None):
    today = date.today()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT {PUBLIC_AD_SELECT_COLUMNS}
                FROM advertisements
                WHERE is_active=TRUE AND is_draft=FALSE
                  AND (start_date + COALESCE(start_time, TIME '00:00:00')) <= (NOW() AT TIME ZONE 'Asia/Kolkata')
                  AND (end_date + COALESCE(end_time, TIME '23:59:59.999999')) >= (NOW() AT TIME ZONE 'Asia/Kolkata')
            """)
            rows = cur.fetchall()
    keys = [
        "id", "advertiser_name", "business_category", "campaign_name", "ad_type",
        "media_type", "media_url", "mobile_media_url", "target_url", "placement",
        "page_target", "duration_seconds", "frequency", "start_date", "end_date",
        "is_active", "traffic_weight", "ad_slot", "movie_ranking_industry",
        "actor_ranking_industry", "target_actor_ids", "target_movie_ids",
        "target_actor_movies", "is_draft", "start_time", "end_time"
    ]
    eligible=[]
    for row in rows:
        ad=dict(zip(keys,row))
        groups={p.strip() for p in (ad.get("placement") or "").split(",") if p.strip()}
        compatibles={placement}|AD_PLACEMENT_LEGACY_ALIASES.get(placement,set())
        if "sitewide" not in groups and not groups.intersection(compatibles):
            continue
        if not _ad_matches_precise_target(ad, placement, actor_id, movie_id):
            continue
        eligible.append(ad)
    return eligible


@app.get("/ads/rotate")
def rotate_public_advertisements(
    placement: str,
    actor_id: Optional[int] = None,
    movie_id: Optional[int] = None
):
    """Return one weighted campaign per standard/in-content inventory key."""
    eligible = _fetch_eligible_ads_for_inventory(placement, actor_id, movie_id)
    pools = {}
    for ad in eligible:
        if ad.get("ad_type") == "sponsored_link":
            continue
        if ad.get("ad_type") == "in_content" and int(ad.get("ad_slot") or 0) == 0:
            for slot_no in range(1,7):
                clone=dict(ad); clone["ad_slot"]=slot_no
                pools.setdefault(_inventory_key(clone), []).append(clone)
        else:
            pools.setdefault(_inventory_key(ad), []).append(ad)
    selected=[]
    for key, pool in pools.items():
        chosen=_weighted_pick(pool,1)
        if chosen:
            item=chosen[0]
            item["inventory_key"]=key
            for d in ("start_date","end_date","start_time","end_time"):
                if item.get(d): item[d]=item[d].isoformat()
            selected.append(item)
    return {"advertisements": selected}


@app.get("/ads/sponsored-links")
def rotate_sponsored_links(
    placement: str,
    actor_id: Optional[int] = None,
    movie_id: Optional[int] = None,
    limit: int = SPONSORED_LINK_VISIBLE_LIMIT
):
    eligible = [a for a in _fetch_eligible_ads_for_inventory(placement, actor_id, movie_id)
                if a.get("ad_type") == "sponsored_link"]
    chosen = _weighted_pick(eligible, min(max(int(limit or 10),1), SPONSORED_LINK_VISIBLE_LIMIT))
    result=[]
    for ad in chosen:
        result.append({
            "id": ad["id"], "advertiser_name": ad["advertiser_name"],
            "campaign_name": ad["campaign_name"], "media_url": ad["media_url"],
            "mobile_media_url": ad.get("mobile_media_url"), "target_url": ad["target_url"],
            "traffic_weight": float(ad.get("traffic_weight") or 1),
        })
    return {"count": len(result), "max_visible": SPONSORED_LINK_VISIBLE_LIMIT, "sponsors": result}



def _inventory_package_label(ad):
    if ad.get("ad_type") == "sponsored_link":
        return ad.get("sponsored_package") or "rotation"
    return ad.get("ad_package") or "standard"


def _inventory_campaign_locks(ad):
    return bool(
        ad.get("exclusive_inventory")
        or ad.get("ad_package") == "exclusive"
        or ad.get("sponsored_package") == "takeover"
    )


def _time_to_minutes(value, default_minutes):
    if value is None:
        return default_minutes
    try:
        return value.hour * 60 + value.minute
    except Exception:
        text = str(value)
        parts = text.split(":")
        try:
            return int(parts[0]) * 60 + int(parts[1])
        except Exception:
            return default_minutes


def _ad_intervals_overlap(
    start_date_a, end_date_a, start_time_a, end_time_a,
    start_date_b, end_date_b, start_time_b, end_time_b
):
    # Date ranges do not overlap.
    if end_date_a < start_date_b or end_date_b < start_date_a:
        return False

    # If overlap spans more than one calendar day, they overlap regardless of exact times.
    latest_start = max(start_date_a, start_date_b)
    earliest_end = min(end_date_a, end_date_b)
    if latest_start < earliest_end:
        return True

    # Same boundary day only: compare time windows.
    a_start = _time_to_minutes(start_time_a, 0)
    a_end = _time_to_minutes(end_time_a, 23 * 60 + 59)
    b_start = _time_to_minutes(start_time_b, 0)
    b_end = _time_to_minutes(end_time_b, 23 * 60 + 59)
    return not (a_end < b_start or b_end < a_start)


def _package_label(ad):
    if ad.get("ad_type") == "sponsored_link":
        return ad.get("sponsored_package") or "rotation"
    return ad.get("ad_package") or "standard"


def _campaign_locks_inventory(ad):
    return bool(
        ad.get("exclusive_inventory")
        or (ad.get("ad_package") == "exclusive")
        or (ad.get("sponsored_package") == "takeover")
    )




@app.get("/admin/advertisements/master-inventory", dependencies=[Depends(require_owner)])
def admin_advertisement_master_inventory(
    placement: str,
    actor_id: Optional[int] = None,
    movie_id: Optional[int] = None,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    start_time: Optional[time] = None,
    end_time: Optional[time] = None
):
    requested_start = start_date or date.today()
    requested_end = end_date or requested_start

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    advertiser_name,
                    campaign_name,
                    ad_type,
                    placement,
                    page_target,
                    ad_slot,
                    frequency,
                    traffic_weight,
                    start_date,
                    end_date,
                    start_time,
                    end_time,
                    is_active,
                    COALESCE(is_draft, FALSE),
                    target_actor_ids,
                    target_movie_ids,
                    target_actor_movies,
                    COALESCE(ad_package, 'standard'),
                    COALESCE(sponsored_package, 'rotation'),
                    COALESCE(exclusive_inventory, FALSE)
                FROM advertisements
                WHERE is_active = TRUE
                  AND COALESCE(is_draft, FALSE) = FALSE
                ORDER BY start_date, id
            """)
            rows = cur.fetchall()

    cols = [
        "id","advertiser_name","campaign_name","ad_type","placement","page_target",
        "ad_slot","frequency","traffic_weight","start_date","end_date",
        "start_time","end_time","is_active","is_draft","target_actor_ids",
        "target_movie_ids","target_actor_movies",
        "ad_package","sponsored_package","exclusive_inventory"
    ]

    def parse_ids(value):
        if value is None:
            return set()
        if isinstance(value, (list, tuple, set)):
            raw = value
        else:
            raw = re.findall(r"\d+", str(value))
        out = set()
        for item in raw:
            try:
                out.add(int(item))
            except Exception:
                pass
        return out

    eligible = []

    for row in rows:
        ad = dict(zip(cols, row))

        groups = {
            item.strip()
            for item in str(ad.get("placement") or "").split(",")
            if item.strip()
        }

        compatible_placements = {placement}
        compatible_placements.update(
            AD_PLACEMENT_LEGACY_ALIASES.get(placement, set())
        )
        if (
            "sitewide" not in groups
            and not groups.intersection(compatible_placements)
        ):
            continue

        actor_targets = parse_ids(ad.get("target_actor_ids"))
        if actor_targets:
            if actor_id is None or actor_id not in actor_targets:
                continue
            # actor_detail is selected by placement itself.
            # actor_movies can additionally be restricted by target_actor_movies.
            if placement == "actor_movies" and ad.get("target_actor_movies") is False:
                continue

        movie_targets = parse_ids(ad.get("target_movie_ids"))
        if movie_targets and (movie_id is None or movie_id not in movie_targets):
            continue

        if not _ad_intervals_overlap(
            ad["start_date"], ad["end_date"], ad.get("start_time"), ad.get("end_time"),
            requested_start, requested_end, start_time, end_time
        ):
            continue

        ad["package"] = _inventory_package_label(ad)
        ad["locks_inventory"] = _inventory_campaign_locks(ad)

        for key in ("start_date", "end_date"):
            if ad.get(key):
                ad[key] = ad[key].isoformat()
        for key in ("start_time", "end_time"):
            if ad.get(key):
                ad[key] = ad[key].isoformat()

        eligible.append(ad)

    inventory = []

    for ad_type in ["full_screen", "top_banner", "top_sticky", "bottom_sticky", "small_video"]:
        campaigns = [a for a in eligible if a["ad_type"] == ad_type]
        locked = next((a for a in campaigns if a["locks_inventory"]), None)
        used = 5 if locked else min(5, len(campaigns))
        inventory.append({
            "key": ad_type,
            "label": ad_type.replace("_", " ").title(),
            "kind": "standard",
            "capacity": 5,
            "used": used,
            "available": 0 if locked else max(0, 5 - used),
            "locked": bool(locked),
            "locked_by": locked,
            "campaigns": campaigns,
        })

    for slot in range(1, 7):
        campaigns = [
            a for a in eligible
            if a["ad_type"] == "in_content"
            and int(a.get("ad_slot") or 0) in {0, slot}
        ]
        locked = next((a for a in campaigns if a["locks_inventory"]), None)
        used = 5 if locked else min(5, len(campaigns))
        inventory.append({
            "key": f"in_content_{slot}",
            "label": f"In-Content Slot {slot}",
            "kind": "in_content",
            "capacity": 5,
            "used": used,
            "available": 0 if locked else max(0, 5 - used),
            "locked": bool(locked),
            "locked_by": locked,
            "campaigns": campaigns,
        })

    sponsored = [a for a in eligible if a["ad_type"] == "sponsored_link"]
    takeover = next((a for a in sponsored if a.get("sponsored_package") == "takeover"), None)

    fixed_map = {"diamond": 1, "platinum": 2, "gold": 3, "silver": 4, "bronze": 5}
    occupied = {}
    for ad in sponsored:
        pkg = ad.get("sponsored_package") or "rotation"
        if pkg in fixed_map and fixed_map[pkg] not in occupied:
            occupied[fixed_map[pkg]] = ad

    fixed_positions = []
    for pkg, pos in fixed_map.items():
        fixed_positions.append({
            "position": pos,
            "package": pkg,
            "campaign": occupied.get(pos),
            "available": takeover is None and occupied.get(pos) is None,
        })

    return {
        "placement": placement,
        "actor_id": actor_id,
        "movie_id": movie_id,
        "requested_window": {
            "start_date": requested_start.isoformat(),
            "end_date": requested_end.isoformat(),
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
        },
        "inventory": inventory,
        "sponsored_links": {
            "takeover": takeover,
            "fixed_positions": fixed_positions,
            "rotation_pool": [
                ad for ad in sponsored
                if (ad.get("sponsored_package") or "rotation") == "rotation"
            ],
            "visible_rotation_positions": 5,
            "max_visible_links": 10,
        }
    }

@app.get("/admin/advertisements/target-actors", dependencies=[Depends(require_owner)])
def admin_ad_target_actor_search(q: str = ""):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,name,profession,photo FROM actors
                WHERE (%s='' OR name ILIKE %s)
                ORDER BY name LIMIT 30
            """, ((q or '').strip(), f"%{(q or '').strip()}%"))
            rows=cur.fetchall()
    return {"actors":[{"id":r[0],"name":r[1],"profession":r[2],"photo":safe_actor_photo(r[3])} for r in rows]}


@app.get("/admin/advertisements/target-actors/{actor_id}/movies", dependencies=[Depends(require_owner)])
def admin_ad_target_actor_movies(actor_id: int, q: str = ""):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT m.id,m.title,m.release_date,m.poster
                FROM actor_movies am JOIN movies m ON m.id=am.movie_id
                WHERE am.actor_id=%s AND (%s='' OR m.title ILIKE %s)
                ORDER BY m.release_date DESC NULLS LAST, m.title
                LIMIT 100
            """, (actor_id, (q or '').strip(), f"%{(q or '').strip()}%"))
            rows=cur.fetchall()
    return {"movies":[{"id":r[0],"title":r[1],"release_date":str(r[2]) if r[2] else None,
                        "poster":safe_movie_poster(r[3])} for r in rows]}


# ============================================================
# BOXOFFICEX OTT CONTEXTUAL SPONSORSHIP
# V1 - BACKEND FOUNDATION
# ============================================================

class OTTSponsorshipCreateData(BaseModel):
    platform_name: str
    campaign_name: str
    logo_url: Optional[str] = None
    sponsored_text: str
    cta_text: str = "Watch Now"
    target_url: str
    fixed_fee: float = 0
    cpc_rate: float = 0
    cpa_rate: float = 0
    start_date: date
    start_time: Optional[time] = None
    end_date: date
    end_time: Optional[time] = None
    is_draft: bool = True
    is_active: bool = False
    movie_ids: Optional[list[int]] = None
    actor_ids: Optional[list[int]] = None
    placements: Optional[list[Literal[
        "movie_page", "movie_compare", "actor_page", "actor_compare"
    ]]] = None
    package_tier: Literal["diamond", "platinum", "gold", "silver"] = "silver"
    rotation_weight: float = 1.0
    quoted_rate: float = 0


class OTTSponsorshipUpdateData(BaseModel):
    platform_name: Optional[str] = None
    campaign_name: Optional[str] = None
    logo_url: Optional[str] = None
    sponsored_text: Optional[str] = None
    cta_text: Optional[str] = None
    target_url: Optional[str] = None
    fixed_fee: Optional[float] = None
    cpc_rate: Optional[float] = None
    cpa_rate: Optional[float] = None
    start_date: Optional[date] = None
    start_time: Optional[time] = None
    end_date: Optional[date] = None
    end_time: Optional[time] = None
    is_draft: Optional[bool] = None
    is_active: Optional[bool] = None
    movie_ids: Optional[list[int]] = None
    actor_ids: Optional[list[int]] = None
    placements: Optional[list[Literal[
        "movie_page", "movie_compare", "actor_page", "actor_compare"
    ]]] = None
    package_tier: Optional[Literal["diamond", "platinum", "gold", "silver"]] = None
    rotation_weight: Optional[float] = None
    quoted_rate: Optional[float] = None


class OTTSponsorshipConversionData(BaseModel):
    conversions: int


OTT_PLACEMENTS = {
    "movie_page",
    "movie_compare",
    "actor_page",
    "actor_compare",
}

OTT_PACKAGE_CAPACITY = {
    "diamond": 1,
    "platinum": 2,
    "gold": 3,
    "silver": 4,
}

OTT_PACKAGE_LABELS = {
    "diamond": "Diamond · Exclusive",
    "platinum": "Platinum · 2-way rotation",
    "gold": "Gold · 3-way rotation",
    "silver": "Silver · 4-way rotation",
}


def _ott_package_capacity(tier: str) -> int:
    return int(OTT_PACKAGE_CAPACITY.get((tier or "silver").lower(), 4))


def _ott_clean_package_tier(tier: Optional[str]) -> str:
    value = (tier or "silver").strip().lower()
    if value not in OTT_PACKAGE_CAPACITY:
        raise HTTPException(status_code=400, detail="Invalid OTT package tier")
    return value


@app.on_event("startup")
def initialize_ott_sponsorship_system():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ott_sponsorships (
                    id BIGSERIAL PRIMARY KEY,
                    platform_name TEXT NOT NULL,
                    campaign_name TEXT NOT NULL,
                    logo_url TEXT,
                    sponsored_text TEXT NOT NULL,
                    cta_text TEXT NOT NULL DEFAULT 'Watch Now',
                    target_url TEXT NOT NULL,
                    fixed_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (fixed_fee >= 0),
                    cpc_rate NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (cpc_rate >= 0),
                    cpa_rate NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (cpa_rate >= 0),
                    start_date DATE NOT NULL,
                    start_time TIME,
                    end_date DATE NOT NULL,
                    end_time TIME,
                    is_draft BOOLEAN NOT NULL DEFAULT TRUE,
                    is_active BOOLEAN NOT NULL DEFAULT FALSE,
                    impressions BIGINT NOT NULL DEFAULT 0 CHECK (impressions >= 0),
                    clicks BIGINT NOT NULL DEFAULT 0 CHECK (clicks >= 0),
                    conversions BIGINT NOT NULL DEFAULT 0 CHECK (conversions >= 0),
                    created_by BIGINT REFERENCES admins(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CHECK (end_date >= start_date)
                )
            """)

            cur.execute("ALTER TABLE ott_sponsorships ADD COLUMN IF NOT EXISTS package_tier TEXT NOT NULL DEFAULT 'silver'")
            cur.execute("ALTER TABLE ott_sponsorships ADD COLUMN IF NOT EXISTS rotation_capacity INTEGER NOT NULL DEFAULT 4")
            cur.execute("ALTER TABLE ott_sponsorships ADD COLUMN IF NOT EXISTS rotation_weight NUMERIC(10,2) NOT NULL DEFAULT 1")
            cur.execute("ALTER TABLE ott_sponsorships ADD COLUMN IF NOT EXISTS quoted_rate NUMERIC(12,2) NOT NULL DEFAULT 0")
            cur.execute("""
                UPDATE ott_sponsorships
                SET rotation_capacity = CASE LOWER(COALESCE(package_tier,'silver'))
                    WHEN 'diamond' THEN 1
                    WHEN 'platinum' THEN 2
                    WHEN 'gold' THEN 3
                    ELSE 4
                END
                WHERE rotation_capacity IS NULL OR rotation_capacity < 1 OR rotation_capacity > 4
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ott_sponsorship_movies (
                    id BIGSERIAL PRIMARY KEY,
                    sponsorship_id BIGINT NOT NULL REFERENCES ott_sponsorships(id) ON DELETE CASCADE,
                    movie_id BIGINT NOT NULL REFERENCES movies(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (sponsorship_id, movie_id)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ott_sponsorship_actors (
                    id BIGSERIAL PRIMARY KEY,
                    sponsorship_id BIGINT NOT NULL REFERENCES ott_sponsorships(id) ON DELETE CASCADE,
                    actor_id BIGINT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (sponsorship_id, actor_id)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ott_sponsorship_placements (
                    id BIGSERIAL PRIMARY KEY,
                    sponsorship_id BIGINT NOT NULL REFERENCES ott_sponsorships(id) ON DELETE CASCADE,
                    placement TEXT NOT NULL CHECK (
                        placement IN ('movie_page','movie_compare','actor_page','actor_compare')
                    ),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (sponsorship_id, placement)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ott_sponsorship_events (
                    id BIGSERIAL PRIMARY KEY,
                    sponsorship_id BIGINT NOT NULL REFERENCES ott_sponsorships(id) ON DELETE CASCADE,
                    placement TEXT NOT NULL CHECK (
                        placement IN ('movie_page','movie_compare','actor_page','actor_compare')
                    ),
                    event_type TEXT NOT NULL CHECK (
                        event_type IN ('impression','click','conversion')
                    ),
                    movie_id BIGINT REFERENCES movies(id) ON DELETE SET NULL,
                    actor_id BIGINT REFERENCES actors(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ott_sponsorship_dates
                ON ott_sponsorships (is_draft, is_active, start_date, end_date)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ott_sponsorship_movies_movie
                ON ott_sponsorship_movies (movie_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ott_sponsorship_actors_actor
                ON ott_sponsorship_actors (actor_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ott_sponsorship_placements_value
                ON ott_sponsorship_placements (placement, sponsorship_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_ott_sponsorship_events_campaign
                ON ott_sponsorship_events (sponsorship_id, created_at DESC)
            """)

        conn.commit()

    print("BOXOFFICEX OTT SPONSORSHIP SYSTEM: READY", flush=True)


def _validate_ott_campaign_data(
    start_date_value,
    end_date_value,
    fixed_fee,
    cpc_rate,
    cpa_rate,
    target_url=None,
):
    if start_date_value and end_date_value and end_date_value < start_date_value:
        raise HTTPException(status_code=400, detail="Campaign end date cannot be before start date")

    for value, label in [
        (fixed_fee, "fixed_fee"),
        (cpc_rate, "cpc_rate"),
        (cpa_rate, "cpa_rate"),
    ]:
        if value is not None and float(value) < 0:
            raise HTTPException(status_code=400, detail=f"{label} cannot be negative")

    if target_url is not None:
        url = target_url.strip()
        if not (url.startswith("https://") or url.startswith("http://")):
            raise HTTPException(
                status_code=400,
                detail="OTT target URL must begin with http:// or https://"
            )


def _validate_ott_package_values(package_tier=None, rotation_weight=None, quoted_rate=None):
    if package_tier is not None:
        _ott_clean_package_tier(package_tier)
    if rotation_weight is not None and float(rotation_weight) <= 0:
        raise HTTPException(status_code=400, detail="Rotation weight must be greater than 0")
    if quoted_rate is not None and float(quoted_rate) < 0:
        raise HTTPException(status_code=400, detail="Quoted rate cannot be negative")


def _ott_campaign_status(campaign: dict) -> str:
    if campaign.get("is_draft"):
        return "draft"
    if not campaign.get("is_active"):
        return "paused"

    tz = ZoneInfo("Asia/Kolkata")
    now_ist = datetime.now(tz)
    campaign_start = datetime.combine(
        campaign["start_date"],
        campaign.get("start_time") or time.min,
        tzinfo=tz,
    )
    campaign_end = datetime.combine(
        campaign["end_date"],
        campaign.get("end_time") or time.max,
        tzinfo=tz,
    )

    if now_ist < campaign_start:
        return "scheduled"
    if now_ist > campaign_end:
        return "ended"
    return "active"


def _validate_ott_target_ids(cur, movie_ids=None, actor_ids=None):
    if movie_ids is not None:
        clean_movie_ids = sorted(set(int(x) for x in movie_ids))
        if clean_movie_ids:
            cur.execute("SELECT id FROM movies WHERE id = ANY(%s)", (clean_movie_ids,))
            found = {r[0] for r in cur.fetchall()}
            missing = [x for x in clean_movie_ids if x not in found]
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid movie IDs: {', '.join(map(str, missing))}"
                )

    if actor_ids is not None:
        clean_actor_ids = sorted(set(int(x) for x in actor_ids))
        if clean_actor_ids:
            cur.execute("SELECT id FROM actors WHERE id = ANY(%s)", (clean_actor_ids,))
            found = {r[0] for r in cur.fetchall()}
            missing = [x for x in clean_actor_ids if x not in found]
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid actor IDs: {', '.join(map(str, missing))}"
                )


def _replace_ott_targets(cur, sponsorship_id: int, movie_ids=None, actor_ids=None, placements=None):
    _validate_ott_target_ids(cur, movie_ids, actor_ids)

    if movie_ids is not None:
        clean_movie_ids = sorted(set(int(x) for x in movie_ids))
        cur.execute("DELETE FROM ott_sponsorship_movies WHERE sponsorship_id = %s", (sponsorship_id,))
        for movie_id in clean_movie_ids:
            cur.execute(
                "INSERT INTO ott_sponsorship_movies (sponsorship_id, movie_id) VALUES (%s, %s)",
                (sponsorship_id, movie_id)
            )

    if actor_ids is not None:
        clean_actor_ids = sorted(set(int(x) for x in actor_ids))
        cur.execute("DELETE FROM ott_sponsorship_actors WHERE sponsorship_id = %s", (sponsorship_id,))
        for actor_id in clean_actor_ids:
            cur.execute(
                "INSERT INTO ott_sponsorship_actors (sponsorship_id, actor_id) VALUES (%s, %s)",
                (sponsorship_id, actor_id)
            )

    if placements is not None:
        clean_placements = set(placements)
        invalid = clean_placements - OTT_PLACEMENTS
        if invalid:
            raise HTTPException(
                status_code=400,
                detail="Invalid OTT placements: " + ", ".join(sorted(invalid))
            )

        cur.execute("DELETE FROM ott_sponsorship_placements WHERE sponsorship_id = %s", (sponsorship_id,))
        for placement in sorted(clean_placements):
            cur.execute(
                "INSERT INTO ott_sponsorship_placements (sponsorship_id, placement) VALUES (%s, %s)",
                (sponsorship_id, placement)
            )


def _get_ott_campaign(sponsorship_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id, platform_name, campaign_name, logo_url, sponsored_text,
                    cta_text, target_url, fixed_fee, cpc_rate, cpa_rate,
                    start_date, start_time, end_date, end_time,
                    is_draft, is_active, impressions, clicks, conversions,
                    created_by, created_at, updated_at,
                    package_tier, rotation_capacity, rotation_weight, quoted_rate
                FROM ott_sponsorships
                WHERE id = %s
            """, (sponsorship_id,))
            row = cur.fetchone()
            if not row:
                return None

            keys = [
                "id", "platform_name", "campaign_name", "logo_url", "sponsored_text",
                "cta_text", "target_url", "fixed_fee", "cpc_rate", "cpa_rate",
                "start_date", "start_time", "end_date", "end_time",
                "is_draft", "is_active", "impressions", "clicks", "conversions",
                "created_by", "created_at", "updated_at",
                "package_tier", "rotation_capacity", "rotation_weight", "quoted_rate",
            ]
            campaign = dict(zip(keys, row))

            cur.execute("""
                SELECT sm.movie_id, m.title, m.release_date, m.language, m.industry, m.poster
                FROM ott_sponsorship_movies sm
                JOIN movies m ON m.id = sm.movie_id
                WHERE sm.sponsorship_id = %s
                ORDER BY m.title
            """, (sponsorship_id,))
            campaign["movies"] = [
                {
                    "id": r[0], "title": r[1],
                    "release_date": str(r[2]) if r[2] else None,
                    "language": r[3], "industry": r[4],
                    "poster": safe_movie_poster(r[5]),
                }
                for r in cur.fetchall()
            ]
            campaign["movie_ids"] = [x["id"] for x in campaign["movies"]]

            cur.execute("""
                SELECT sa.actor_id, a.name, a.profession, a.photo
                FROM ott_sponsorship_actors sa
                JOIN actors a ON a.id = sa.actor_id
                WHERE sa.sponsorship_id = %s
                ORDER BY a.name
            """, (sponsorship_id,))
            campaign["actors"] = [
                {
                    "id": r[0], "name": r[1], "profession": r[2],
                    "photo": safe_actor_photo(r[3]),
                }
                for r in cur.fetchall()
            ]
            campaign["actor_ids"] = [x["id"] for x in campaign["actors"]]

            cur.execute("""
                SELECT placement
                FROM ott_sponsorship_placements
                WHERE sponsorship_id = %s
                ORDER BY placement
            """, (sponsorship_id,))
            campaign["placements"] = [r[0] for r in cur.fetchall()]

    campaign["status"] = _ott_campaign_status(campaign)
    campaign["fixed_fee"] = float(campaign["fixed_fee"] or 0)
    campaign["cpc_rate"] = float(campaign["cpc_rate"] or 0)
    campaign["cpa_rate"] = float(campaign["cpa_rate"] or 0)
    campaign["package_tier"] = (campaign.get("package_tier") or "silver").lower()
    campaign["rotation_capacity"] = int(campaign.get("rotation_capacity") or _ott_package_capacity(campaign["package_tier"]))
    campaign["rotation_weight"] = float(campaign.get("rotation_weight") or 1)
    campaign["quoted_rate"] = float(campaign.get("quoted_rate") or 0)
    campaign["package_label"] = OTT_PACKAGE_LABELS.get(campaign["package_tier"], OTT_PACKAGE_LABELS["silver"])
    campaign["estimated_cpc_revenue"] = round(campaign["clicks"] * campaign["cpc_rate"], 2)
    campaign["estimated_cpa_revenue"] = round(campaign["conversions"] * campaign["cpa_rate"], 2)
    campaign["estimated_total_revenue"] = round(
        campaign["fixed_fee"] + campaign["estimated_cpc_revenue"] + campaign["estimated_cpa_revenue"], 2
    )
    campaign["ctr"] = round(
        (campaign["clicks"] / campaign["impressions"] * 100) if campaign["impressions"] else 0,
        2,
    )
    return campaign


def _ott_public_payload(campaign: dict, placement: str, movie_id=None, actor_id=None):
    suffix = f"?placement={placement}"
    if movie_id:
        suffix += f"&movie_id={int(movie_id)}"
    if actor_id:
        suffix += f"&actor_id={int(actor_id)}"

    return {
        "id": campaign["id"],
        "platform_name": campaign["platform_name"],
        "logo_url": campaign["logo_url"],
        "sponsored_text": campaign["sponsored_text"],
        "cta_text": campaign["cta_text"],
        "placement": placement,
        "impression_url": f"/ott/sponsorship/{campaign['id']}/impression{suffix}",
        "click_url": f"/ott/sponsorship/{campaign['id']}/click{suffix}",
    }


@app.get("/admin/ott-sponsorships/search/movies", dependencies=[Depends(require_owner)])
def admin_ott_movie_search(q: str = "", limit: int = 30):
    query = (q or "").strip()
    limit = max(1, min(int(limit or 30), 50))
    contains = f"%{query}%"
    starts = f"{query}%"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, release_date, language, industry, poster
                FROM movies
                WHERE %s = '' OR title ILIKE %s
                ORDER BY
                    CASE
                        WHEN LOWER(title) = LOWER(%s) THEN 0
                        WHEN title ILIKE %s THEN 1
                        ELSE 2
                    END,
                    release_date DESC NULLS LAST,
                    title
                LIMIT %s
            """, (query, contains, query, starts, limit))
            rows = cur.fetchall()

    return {"movies": [
        {
            "id": r[0], "title": r[1],
            "release_date": str(r[2]) if r[2] else None,
            "language": r[3], "industry": r[4],
            "poster": safe_movie_poster(r[5]),
        }
        for r in rows
    ]}


@app.get("/admin/ott-sponsorships/search/actors", dependencies=[Depends(require_owner)])
def admin_ott_actor_search(q: str = "", limit: int = 30):
    query = (q or "").strip()
    limit = max(1, min(int(limit or 30), 50))
    contains = f"%{query}%"
    starts = f"{query}%"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, profession, photo
                FROM actors
                WHERE %s = '' OR name ILIKE %s
                ORDER BY
                    CASE
                        WHEN LOWER(name) = LOWER(%s) THEN 0
                        WHEN name ILIKE %s THEN 1
                        ELSE 2
                    END,
                    name
                LIMIT %s
            """, (query, contains, query, starts, limit))
            rows = cur.fetchall()

    return {"actors": [
        {"id": r[0], "name": r[1], "profession": r[2], "photo": safe_actor_photo(r[3])}
        for r in rows
    ]}



def _ott_campaign_time_window(start_date_value, start_time_value, end_date_value, end_time_value):
    return (
        datetime.combine(start_date_value, start_time_value or time.min),
        datetime.combine(end_date_value, end_time_value or time.max),
    )


def _ott_targets_intersect(cur, campaign_id: int, placement: str, movie_ids, actor_ids) -> bool:
    """
    Empty incoming list means ALL for that family.
    Existing campaign with zero target rows also means ALL.
    """
    if placement in {"movie_page", "movie_compare"}:
        cur.execute(
            "SELECT movie_id FROM ott_sponsorship_movies WHERE sponsorship_id=%s",
            (campaign_id,)
        )
        existing = {int(r[0]) for r in cur.fetchall()}
        incoming = {int(x) for x in (movie_ids or [])}
        return (not existing) or (not incoming) or bool(existing & incoming)

    cur.execute(
        "SELECT actor_id FROM ott_sponsorship_actors WHERE sponsorship_id=%s",
        (campaign_id,)
    )
    existing = {int(r[0]) for r in cur.fetchall()}
    incoming = {int(x) for x in (actor_ids or [])}
    return (not existing) or (not incoming) or bool(existing & incoming)


def _ott_overlapping_campaigns(
    cur,
    *,
    placements,
    movie_ids,
    actor_ids,
    start_date_value,
    start_time_value,
    end_date_value,
    end_time_value,
    exclude_id=None,
):
    new_start, new_end = _ott_campaign_time_window(
        start_date_value, start_time_value, end_date_value, end_time_value
    )

    cur.execute("""
        SELECT
            s.id, s.platform_name, s.campaign_name, s.package_tier,
            s.rotation_capacity, s.start_date, s.start_time, s.end_date, s.end_time
        FROM ott_sponsorships s
        WHERE s.is_draft = FALSE
          AND s.is_active = TRUE
          AND (%s IS NULL OR s.id <> %s)
          AND (s.start_date + COALESCE(s.start_time, TIME '00:00:00')) <= %s
          AND (s.end_date + COALESCE(s.end_time, TIME '23:59:59.999999')) >= %s
        ORDER BY s.id
    """, (exclude_id, exclude_id, new_end, new_start))

    rows = cur.fetchall()
    result = []

    for row in rows:
        campaign_id = int(row[0])
        cur.execute(
            "SELECT placement FROM ott_sponsorship_placements WHERE sponsorship_id=%s",
            (campaign_id,)
        )
        existing_placements = {r[0] for r in cur.fetchall()}
        shared = existing_placements & set(placements or [])
        if not shared:
            continue

        matching_placements = []
        for placement in shared:
            if _ott_targets_intersect(cur, campaign_id, placement, movie_ids, actor_ids):
                matching_placements.append(placement)

        if matching_placements:
            result.append({
                "id": campaign_id,
                "platform_name": row[1],
                "campaign_name": row[2],
                "package_tier": (row[3] or "silver").lower(),
                "rotation_capacity": int(row[4] or 4),
                "placements": sorted(matching_placements),
            })

    return result


def _ott_inventory_snapshot(
    *,
    placements,
    movie_ids,
    actor_ids,
    start_date_value,
    start_time_value,
    end_date_value,
    end_time_value,
    package_tier,
    exclude_id=None,
):
    """
    Compute inventory independently for each placement and each concrete target.

    This avoids false sold-out results when, for example:
    - one sponsor occupies movie_page
    - another sponsor occupies movie_compare

    It also avoids over-counting unrelated selected movies/actors:
    Leo-only and Jailer-only bookings are checked on their own target buckets,
    rather than being summed as if both occupied the same page.
    """
    package_tier = _ott_clean_package_tier(package_tier)
    requested_capacity = _ott_package_capacity(package_tier)

    start_dt, end_dt = _ott_campaign_time_window(
        start_date_value, start_time_value, end_date_value, end_time_value
    )

    placement_results = []

    with get_connection() as conn:
        with conn.cursor() as cur:
            for placement in list(dict.fromkeys(placements or [])):
                if placement not in OTT_PLACEMENTS:
                    continue

                is_movie = placement in {"movie_page", "movie_compare"}
                incoming_ids = {
                    int(x) for x in ((movie_ids if is_movie else actor_ids) or [])
                }

                cur.execute("""
                    SELECT
                        s.id,
                        s.platform_name,
                        s.campaign_name,
                        s.package_tier,
                        s.rotation_capacity
                    FROM ott_sponsorships s
                    JOIN ott_sponsorship_placements p
                      ON p.sponsorship_id = s.id
                    WHERE s.is_draft = FALSE
                      AND s.is_active = TRUE
                      AND p.placement = %s
                      AND (%s IS NULL OR s.id <> %s)
                      AND (s.start_date + COALESCE(s.start_time, TIME '00:00:00')) <= %s
                      AND (s.end_date + COALESCE(s.end_time, TIME '23:59:59.999999')) >= %s
                    ORDER BY s.id
                """, (placement, exclude_id, exclude_id, end_dt, start_dt))

                rows = cur.fetchall()
                campaigns = []

                for row in rows:
                    campaign_id = int(row[0])

                    if is_movie:
                        cur.execute(
                            "SELECT movie_id FROM ott_sponsorship_movies WHERE sponsorship_id=%s",
                            (campaign_id,)
                        )
                    else:
                        cur.execute(
                            "SELECT actor_id FROM ott_sponsorship_actors WHERE sponsorship_id=%s",
                            (campaign_id,)
                        )

                    target_ids = {int(r[0]) for r in cur.fetchall()}

                    campaigns.append({
                        "id": campaign_id,
                        "platform_name": row[1],
                        "campaign_name": row[2],
                        "package_tier": (row[3] or "silver").lower(),
                        "rotation_capacity": int(row[4] or 4),
                        "target_ids": target_ids,  # empty = ALL
                        "placements": [placement],
                    })

                # Build exact target buckets.
                # Selected incoming IDs: every selected target must have capacity.
                # ALL incoming: evaluate global bucket plus every specifically-booked
                # target because any one of those pages could be the bottleneck.
                if incoming_ids:
                    buckets = sorted(incoming_ids)
                else:
                    specific_ids = set()
                    for c in campaigns:
                        specific_ids.update(c["target_ids"])
                    buckets = [None] + sorted(specific_ids)

                if not buckets:
                    buckets = [None]

                bucket_results = []

                for target_id in buckets:
                    matching = []
                    for c in campaigns:
                        if not c["target_ids"] or target_id is None:
                            # Global campaign applies to every target.
                            # For the generic ALL bucket (None), only global campaigns
                            # apply; target-specific campaigns are checked in their own buckets.
                            if not c["target_ids"]:
                                matching.append(c)
                        elif target_id in c["target_ids"]:
                            matching.append(c)

                    effective_capacity = min(
                        [requested_capacity]
                        + [int(c.get("rotation_capacity") or 4) for c in matching]
                    )
                    booked = len(matching)
                    available = max(0, effective_capacity - booked)
                    can_book = booked < effective_capacity

                    bucket_results.append({
                        "target_id": target_id,
                        "effective_capacity": effective_capacity,
                        "booked": booked,
                        "available_slots": available,
                        "can_book": can_book,
                        "campaigns": matching,
                    })

                # The least-available target is the sellability bottleneck.
                bottleneck = min(
                    bucket_results,
                    key=lambda x: (
                        1 if x["can_book"] else 0,
                        x["available_slots"],
                        -x["booked"],
                    )
                )

                placement_results.append({
                    "placement": placement,
                    "effective_capacity": bottleneck["effective_capacity"],
                    "booked": bottleneck["booked"],
                    "available_slots": bottleneck["available_slots"],
                    "can_book": all(x["can_book"] for x in bucket_results),
                    "bottleneck_target_id": bottleneck["target_id"],
                    "overlapping_campaigns": [
                        {
                            "id": c["id"],
                            "platform_name": c["platform_name"],
                            "campaign_name": c["campaign_name"],
                            "package_tier": c["package_tier"],
                            "rotation_capacity": c["rotation_capacity"],
                            "placements": c["placements"],
                        }
                        for c in bottleneck["campaigns"]
                    ],
                })

    if not placement_results:
        return {
            "package_tier": package_tier,
            "package_label": OTT_PACKAGE_LABELS[package_tier],
            "requested_capacity": requested_capacity,
            "effective_capacity": requested_capacity,
            "booked": 0,
            "available_slots": requested_capacity,
            "can_book": True,
            "overlapping_campaigns": [],
            "placement_inventory": [],
        }

    can_book = all(x["can_book"] for x in placement_results)
    bottleneck = min(
        placement_results,
        key=lambda x: (
            1 if x["can_book"] else 0,
            x["available_slots"],
            -x["booked"],
        )
    )

    return {
        "package_tier": package_tier,
        "package_label": OTT_PACKAGE_LABELS[package_tier],
        "requested_capacity": requested_capacity,
        "effective_capacity": bottleneck["effective_capacity"],
        "booked": bottleneck["booked"],
        "available_slots": bottleneck["available_slots"],
        "can_book": can_book,
        "overlapping_campaigns": bottleneck["overlapping_campaigns"],
        "placement_inventory": placement_results,
    }


def _validate_ott_inventory_or_raise(
    *,
    placements,
    movie_ids,
    actor_ids,
    start_date_value,
    start_time_value,
    end_date_value,
    end_time_value,
    package_tier,
    exclude_id=None,
):
    snapshot = _ott_inventory_snapshot(
        placements=placements,
        movie_ids=movie_ids,
        actor_ids=actor_ids,
        start_date_value=start_date_value,
        start_time_value=start_time_value,
        end_date_value=end_date_value,
        end_time_value=end_time_value,
        package_tier=package_tier,
        exclude_id=exclude_id,
    )
    if not snapshot["can_book"]:
        names = ", ".join(
            f"{x['platform_name']} ({x['package_tier'].title()})"
            for x in snapshot["overlapping_campaigns"][:6]
        ) or "existing sponsorships"
        raise HTTPException(
            status_code=409,
            detail=(
                f"OTT inventory sold out for the selected target/date range. "
                f"Capacity {snapshot['effective_capacity']}, booked {snapshot['booked']}. "
                f"Overlapping campaigns: {names}"
            )
        )
    return snapshot


@app.post("/admin/ott-sponsorships/inventory/check", dependencies=[Depends(require_owner)])
def admin_check_ott_inventory(data: OTTSponsorshipCreateData):
    _validate_ott_campaign_data(
        data.start_date, data.end_date, data.fixed_fee, data.cpc_rate, data.cpa_rate, data.target_url
    )
    _validate_ott_package_values(data.package_tier, data.rotation_weight, data.quoted_rate)
    _validate_ott_package_values(data.package_tier, data.rotation_weight, data.quoted_rate)
    return {
        "inventory": _ott_inventory_snapshot(
            placements=data.placements or [],
            movie_ids=data.movie_ids or [],
            actor_ids=data.actor_ids or [],
            start_date_value=data.start_date,
            start_time_value=data.start_time,
            end_date_value=data.end_date,
            end_time_value=data.end_time,
            package_tier=data.package_tier,
        )
    }


@app.post("/admin/ott-sponsorships", dependencies=[Depends(require_owner)])
def admin_create_ott_sponsorship(data: OTTSponsorshipCreateData, request: Request):
    admin = current_admin(request)
    _validate_ott_campaign_data(
        data.start_date, data.end_date, data.fixed_fee, data.cpc_rate, data.cpa_rate, data.target_url
    )

    if not data.platform_name.strip():
        raise HTTPException(status_code=400, detail="OTT platform name is required")
    if not data.campaign_name.strip():
        raise HTTPException(status_code=400, detail="Campaign name is required")
    if not data.sponsored_text.strip():
        raise HTTPException(status_code=400, detail="Sponsored text is required")

    movie_ids = data.movie_ids or []
    actor_ids = data.actor_ids or []
    placements = data.placements or []

    if not placements:
        raise HTTPException(status_code=400, detail="Select at least one OTT placement")

    # Empty target lists intentionally mean ALL targets for the enabled family:
    # [] + movie placement(s) => all movies
    # [] + actor placement(s) => all actors

    if not data.is_draft and data.is_active:
        _validate_ott_inventory_or_raise(
            placements=placements,
            movie_ids=movie_ids,
            actor_ids=actor_ids,
            start_date_value=data.start_date,
            start_time_value=data.start_time,
            end_date_value=data.end_date,
            end_time_value=data.end_time,
            package_tier=data.package_tier,
        )

    package_tier = _ott_clean_package_tier(data.package_tier)
    rotation_capacity = _ott_package_capacity(package_tier)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ott_sponsorships (
                    platform_name, campaign_name, logo_url, sponsored_text, cta_text, target_url,
                    fixed_fee, cpc_rate, cpa_rate,
                    start_date, start_time, end_date, end_time,
                    is_draft, is_active, created_by,
                    package_tier, rotation_capacity, rotation_weight, quoted_rate
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s
                ) RETURNING id
            """, (
                data.platform_name.strip(), data.campaign_name.strip(), data.logo_url,
                data.sponsored_text.strip(), data.cta_text.strip() or "Watch Now", data.target_url.strip(),
                data.fixed_fee, data.cpc_rate, data.cpa_rate,
                data.start_date, data.start_time, data.end_date, data.end_time,
                data.is_draft, data.is_active, admin["id"],
                package_tier, rotation_capacity, data.rotation_weight, data.quoted_rate,
            ))
            sponsorship_id = cur.fetchone()[0]
            _replace_ott_targets(cur, sponsorship_id, movie_ids, actor_ids, placements)
        conn.commit()

    return {"success": True, "sponsorship": _get_ott_campaign(sponsorship_id)}


@app.get("/admin/ott-sponsorships", dependencies=[Depends(require_owner)])
def admin_list_ott_sponsorships(status: Optional[str] = None):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM ott_sponsorships ORDER BY created_at DESC")
            ids = [r[0] for r in cur.fetchall()]

    campaigns = [_get_ott_campaign(x) for x in ids]
    if status:
        wanted = status.strip().lower()
        campaigns = [x for x in campaigns if x and x.get("status") == wanted]
    return {"campaigns": campaigns}


@app.get("/admin/ott-sponsorships/{sponsorship_id}", dependencies=[Depends(require_owner)])
def admin_get_ott_sponsorship(sponsorship_id: int):
    campaign = _get_ott_campaign(sponsorship_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")
    return {"campaign": campaign}


@app.put("/admin/ott-sponsorships/{sponsorship_id}", dependencies=[Depends(require_owner)])
def admin_update_ott_sponsorship(sponsorship_id: int, data: OTTSponsorshipUpdateData):
    existing = _get_ott_campaign(sponsorship_id)
    if not existing:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")

    effective_start = data.start_date if data.start_date is not None else existing["start_date"]
    effective_end = data.end_date if data.end_date is not None else existing["end_date"]
    _validate_ott_campaign_data(
        effective_start,
        effective_end,
        data.fixed_fee if data.fixed_fee is not None else existing["fixed_fee"],
        data.cpc_rate if data.cpc_rate is not None else existing["cpc_rate"],
        data.cpa_rate if data.cpa_rate is not None else existing["cpa_rate"],
        data.target_url if data.target_url is not None else existing["target_url"],
    )

    final_movie_ids = data.movie_ids if data.movie_ids is not None else existing["movie_ids"]
    final_actor_ids = data.actor_ids if data.actor_ids is not None else existing["actor_ids"]
    final_placements = data.placements if data.placements is not None else existing["placements"]
    final_package_tier = _ott_clean_package_tier(
        data.package_tier if data.package_tier is not None else existing.get("package_tier")
    )
    final_rotation_weight = (
        data.rotation_weight if data.rotation_weight is not None else existing.get("rotation_weight", 1)
    )
    final_quoted_rate = (
        data.quoted_rate if data.quoted_rate is not None else existing.get("quoted_rate", 0)
    )
    _validate_ott_package_values(final_package_tier, final_rotation_weight, final_quoted_rate)

    if not final_placements:
        raise HTTPException(status_code=400, detail="Select at least one OTT placement")
    # Empty target lists are valid premium coverage:
    # no movie rows = all movies; no actor rows = all actors.

    final_is_draft = data.is_draft if data.is_draft is not None else existing["is_draft"]
    final_is_active = data.is_active if data.is_active is not None else existing["is_active"]

    if not final_is_draft and final_is_active:
        _validate_ott_inventory_or_raise(
            placements=final_placements,
            movie_ids=final_movie_ids,
            actor_ids=final_actor_ids,
            start_date_value=effective_start,
            start_time_value=data.start_time if data.start_time is not None else existing["start_time"],
            end_date_value=effective_end,
            end_time_value=data.end_time if data.end_time is not None else existing["end_time"],
            package_tier=final_package_tier,
            exclude_id=sponsorship_id,
        )

    fields = []
    values = []
    simple_fields = {
        "platform_name": data.platform_name,
        "campaign_name": data.campaign_name,
        "logo_url": data.logo_url,
        "sponsored_text": data.sponsored_text,
        "cta_text": data.cta_text,
        "target_url": data.target_url,
        "fixed_fee": data.fixed_fee,
        "cpc_rate": data.cpc_rate,
        "cpa_rate": data.cpa_rate,
        "start_date": data.start_date,
        "start_time": data.start_time,
        "end_date": data.end_date,
        "end_time": data.end_time,
        "is_draft": data.is_draft,
        "is_active": data.is_active,
        "package_tier": data.package_tier,
        "rotation_weight": data.rotation_weight,
        "quoted_rate": data.quoted_rate,
    }

    if data.package_tier is not None:
        fields.append("rotation_capacity = %s")
        values.append(_ott_package_capacity(final_package_tier))

    for field, value in simple_fields.items():
        if value is not None:
            if isinstance(value, str):
                value = value.strip()
                if field in {"platform_name", "campaign_name", "sponsored_text", "cta_text", "target_url"} and not value:
                    raise HTTPException(status_code=400, detail=f"{field} cannot be empty")
            fields.append(f"{field} = %s")
            values.append(value)

    with get_connection() as conn:
        with conn.cursor() as cur:
            if fields:
                fields.append("updated_at = NOW()")
                values.append(sponsorship_id)
                cur.execute(
                    f"UPDATE ott_sponsorships SET {', '.join(fields)} WHERE id = %s",
                    tuple(values)
                )

            _replace_ott_targets(
                cur,
                sponsorship_id,
                data.movie_ids,
                data.actor_ids,
                data.placements,
            )
        conn.commit()

    return {"success": True, "sponsorship": _get_ott_campaign(sponsorship_id)}


@app.delete("/admin/ott-sponsorships/{sponsorship_id}", dependencies=[Depends(require_owner)])
def admin_delete_ott_sponsorship(sponsorship_id: int):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM ott_sponsorships WHERE id = %s RETURNING id", (sponsorship_id,))
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")
    return {"success": True}


@app.patch("/admin/ott-sponsorships/{sponsorship_id}/conversions", dependencies=[Depends(require_owner)])
def admin_set_ott_conversions(sponsorship_id: int, data: OTTSponsorshipConversionData):
    if data.conversions < 0:
        raise HTTPException(status_code=400, detail="Conversions cannot be negative")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE ott_sponsorships
                SET conversions = %s, updated_at = NOW()
                WHERE id = %s
                RETURNING id
            """, (data.conversions, sponsorship_id))
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")
    return {"success": True, "sponsorship": _get_ott_campaign(sponsorship_id)}


@app.get("/admin/ott-sponsorships/{sponsorship_id}/preview", dependencies=[Depends(require_owner)])
def admin_preview_ott_sponsorship(
    sponsorship_id: int,
    placement: str,
    movie_id: Optional[int] = None,
    actor_id: Optional[int] = None,
):
    campaign = _get_ott_campaign(sponsorship_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")
    if placement not in OTT_PLACEMENTS:
        raise HTTPException(status_code=400, detail="Invalid OTT placement")
    if placement not in campaign["placements"]:
        raise HTTPException(status_code=400, detail="This campaign does not have that placement enabled")

    if placement in {"movie_page", "movie_compare"}:
        if not movie_id:
            raise HTTPException(status_code=400, detail="movie_id is required")
        if campaign["movie_ids"] and int(movie_id) not in campaign["movie_ids"]:
            raise HTTPException(status_code=400, detail="Selected movie is not targeted by this campaign")

    if placement in {"actor_page", "actor_compare"}:
        if not actor_id:
            raise HTTPException(status_code=400, detail="actor_id is required")
        if campaign["actor_ids"] and int(actor_id) not in campaign["actor_ids"]:
            raise HTTPException(status_code=400, detail="Selected actor is not targeted by this campaign")

    return {
        "preview": True,
        "campaign_status": campaign["status"],
        "sponsorship": _ott_public_payload(campaign, placement, movie_id, actor_id),
    }


def _eligible_active_ott_sponsorships(placement: str, movie_id=None, actor_id=None):
    if placement not in OTT_PLACEMENTS:
        return []

    now_ist_naive = datetime.now(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None)

    with get_connection() as conn:
        with conn.cursor() as cur:
            where = [
                "s.is_draft = FALSE",
                "s.is_active = TRUE",
                "p.placement = %s",
                "(s.start_date + COALESCE(s.start_time, TIME '00:00:00')) <= %s",
                "(s.end_date + COALESCE(s.end_time, TIME '23:59:59.999999')) >= %s",
            ]
            params = [placement, now_ist_naive, now_ist_naive]

            if placement in {"movie_page", "movie_compare"}:
                if not movie_id:
                    return []
                where.append("""
                    (
                        NOT EXISTS (
                            SELECT 1 FROM ott_sponsorship_movies sm_any
                            WHERE sm_any.sponsorship_id = s.id
                        )
                        OR EXISTS (
                            SELECT 1 FROM ott_sponsorship_movies sm_match
                            WHERE sm_match.sponsorship_id = s.id
                              AND sm_match.movie_id = %s
                        )
                    )
                """)
                params.append(int(movie_id))
            else:
                if not actor_id:
                    return []
                where.append("""
                    (
                        NOT EXISTS (
                            SELECT 1 FROM ott_sponsorship_actors sa_any
                            WHERE sa_any.sponsorship_id = s.id
                        )
                        OR EXISTS (
                            SELECT 1 FROM ott_sponsorship_actors sa_match
                            WHERE sa_match.sponsorship_id = s.id
                              AND sa_match.actor_id = %s
                        )
                    )
                """)
                params.append(int(actor_id))

            cur.execute(f"""
                SELECT s.id
                FROM ott_sponsorships s
                JOIN ott_sponsorship_placements p ON p.sponsorship_id = s.id
                WHERE {' AND '.join(where)}
                ORDER BY s.id
            """, tuple(params))
            ids = [int(r[0]) for r in cur.fetchall()]

    campaigns = [_get_ott_campaign(x) for x in ids]
    campaigns = [x for x in campaigns if x]

    # Defensive inventory enforcement: if old/manual DB data exceeds a package promise,
    # only the strictest allowed number of campaigns is eligible.
    if campaigns:
        max_live = min(int(x.get("rotation_capacity") or 4) for x in campaigns)
        campaigns = campaigns[:max_live]

    return campaigns


def _find_active_ott_sponsorship(placement: str, movie_id=None, actor_id=None):
    campaigns = _eligible_active_ott_sponsorships(placement, movie_id, actor_id)
    if not campaigns:
        return None
    if len(campaigns) == 1:
        return campaigns[0]

    import random
    weights = [max(0.01, float(x.get("rotation_weight") or 1)) for x in campaigns]
    return random.choices(campaigns, weights=weights, k=1)[0]


def _campaign_is_eligible_for_live_target(
    sponsorship_id: int,
    placement: str,
    movie_id=None,
    actor_id=None,
):
    return any(
        int(c["id"]) == int(sponsorship_id)
        for c in _eligible_active_ott_sponsorships(placement, movie_id, actor_id)
    )


def _require_live_ott_campaign_match(
    sponsorship_id: int,
    placement: str,
    movie_id=None,
    actor_id=None,
):
    if not _campaign_is_eligible_for_live_target(
        sponsorship_id=sponsorship_id,
        placement=placement,
        movie_id=movie_id,
        actor_id=actor_id,
    ):
        raise HTTPException(status_code=404, detail="Active OTT sponsorship not found for this target")
    campaign = _get_ott_campaign(sponsorship_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")
    return campaign


@app.get("/ott/sponsorship")
def public_ott_sponsorship(
    placement: str,
    movie_id: Optional[int] = None,
    actor_id: Optional[int] = None,
):
    if placement not in OTT_PLACEMENTS:
        raise HTTPException(status_code=400, detail="Invalid OTT placement")
    if placement in {"movie_page", "movie_compare"} and not movie_id:
        raise HTTPException(status_code=400, detail="movie_id is required")
    if placement in {"actor_page", "actor_compare"} and not actor_id:
        raise HTTPException(status_code=400, detail="actor_id is required")

    campaign = _find_active_ott_sponsorship(placement, movie_id, actor_id)
    if not campaign:
        return {"sponsorship": None}
    return {"sponsorship": _ott_public_payload(campaign, placement, movie_id, actor_id)}


@app.post("/ott/sponsorship/{sponsorship_id}/impression")
def track_ott_impression(
    sponsorship_id: int,
    placement: str,
    movie_id: Optional[int] = None,
    actor_id: Optional[int] = None,
):
    if placement not in OTT_PLACEMENTS:
        raise HTTPException(status_code=400, detail="Invalid placement")

    _require_live_ott_campaign_match(sponsorship_id, placement, movie_id, actor_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE ott_sponsorships
                SET impressions = impressions + 1, updated_at = NOW()
                WHERE id = %s
                RETURNING id
            """, (sponsorship_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="OTT sponsorship not found")

            cur.execute("""
                INSERT INTO ott_sponsorship_events (
                    sponsorship_id, placement, event_type, movie_id, actor_id
                ) VALUES (%s, %s, 'impression', %s, %s)
            """, (sponsorship_id, placement, movie_id, actor_id))
        conn.commit()

    return {"success": True}


@app.get("/ott/sponsorship/{sponsorship_id}/click")
def track_ott_click(
    sponsorship_id: int,
    placement: str,
    movie_id: Optional[int] = None,
    actor_id: Optional[int] = None,
):
    if placement not in OTT_PLACEMENTS:
        raise HTTPException(status_code=400, detail="Invalid placement")

    campaign = _require_live_ott_campaign_match(sponsorship_id, placement, movie_id, actor_id)
    target_url = campaign["target_url"]

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE ott_sponsorships
                SET clicks = clicks + 1, updated_at = NOW()
                WHERE id = %s
                RETURNING id
            """, (sponsorship_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="OTT sponsorship not found")

            cur.execute("""
                INSERT INTO ott_sponsorship_events (
                    sponsorship_id, placement, event_type, movie_id, actor_id
                ) VALUES (%s, %s, 'click', %s, %s)
            """, (sponsorship_id, placement, movie_id, actor_id))
        conn.commit()

    return Response(status_code=307, headers={"Location": target_url})


def _get_ott_campaign_report_data(sponsorship_id: int):
    campaign = _get_ott_campaign(sponsorship_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="OTT sponsorship not found")

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    placement,
                    COUNT(*) FILTER (WHERE event_type = 'impression') AS impressions,
                    COUNT(*) FILTER (WHERE event_type = 'click') AS clicks,
                    COUNT(*) FILTER (WHERE event_type = 'conversion') AS conversions
                FROM ott_sponsorship_events
                WHERE sponsorship_id = %s
                GROUP BY placement
                ORDER BY placement
            """, (sponsorship_id,))
            rows = cur.fetchall()

    placement_performance = []
    for placement, impressions, clicks, conversions in rows:
        impressions = int(impressions or 0)
        clicks = int(clicks or 0)
        conversions = int(conversions or 0)
        placement_performance.append({
            "placement": placement,
            "impressions": impressions,
            "clicks": clicks,
            "conversions": conversions,
            "ctr": round((clicks / impressions * 100) if impressions else 0, 2),
        })

    return {
        "campaign": campaign,
        "placement_performance": placement_performance,
    }


@app.get("/admin/ott-sponsorships/{sponsorship_id}/report", dependencies=[Depends(require_owner)])
def admin_ott_campaign_report(sponsorship_id: int):
    return _get_ott_campaign_report_data(sponsorship_id)


def _safe_report_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "campaign")).strip("-")
    return value or "campaign"


def _build_ott_report_pdf(report: dict) -> bytes:
    c = report["campaign"]
    rows = report.get("placement_performance") or []

    lines = [
        "BOXOFFICEX - OTT SPONSORSHIP CAMPAIGN REPORT",
        "",
        f"Campaign ID: {c.get('id')}",
        f"Campaign: {c.get('campaign_name') or '-'}",
        f"OTT Platform: {c.get('platform_name') or '-'}",
        f"Status: {str(c.get('status') or '-').upper()}",
        f"Package: {c.get('package_label') or '-'}",
        f"Rotation capacity: {int(c.get('rotation_capacity') or 4)}",
        f"Quoted package rate: INR {float(c.get('quoted_rate') or 0):,.2f}",
        f"Campaign period: {c.get('start_date') or '-'} to {c.get('end_date') or '-'}",
        f"Placements: {', '.join(c.get('placements') or []) or '-'}",
        "",
        "TARGETING",
        f"Movies: {'ALL' if any(str(x).startswith('movie_') for x in (c.get('placements') or [])) and not (c.get('movie_ids') or []) else len(c.get('movie_ids') or [])}",
        f"Actors: {'ALL' if any(str(x).startswith('actor_') for x in (c.get('placements') or [])) and not (c.get('actor_ids') or []) else len(c.get('actor_ids') or [])}",
        "",
        "CAMPAIGN PERFORMANCE",
        f"Impressions: {int(c.get('impressions') or 0):,}",
        f"Clicks: {int(c.get('clicks') or 0):,}",
        f"CTR: {float(c.get('ctr') or 0):.2f}%",
        f"Conversions: {int(c.get('conversions') or 0):,}",
        "",
        "COMMERCIAL SUMMARY",
        f"Fixed fee: INR {float(c.get('fixed_fee') or 0):,.2f}",
        f"CPC rate: INR {float(c.get('cpc_rate') or 0):,.2f}",
        f"CPA rate: INR {float(c.get('cpa_rate') or 0):,.2f}",
        f"Estimated CPC revenue: INR {float(c.get('estimated_cpc_revenue') or 0):,.2f}",
        f"Estimated CPA revenue: INR {float(c.get('estimated_cpa_revenue') or 0):,.2f}",
        f"Estimated total revenue: INR {float(c.get('estimated_total_revenue') or 0):,.2f}",
        "",
        "PLACEMENT PERFORMANCE",
    ]

    if rows:
        for r in rows:
            lines.append(
                f"{str(r.get('placement') or '').replace('_', ' ').title()}: "
                f"{int(r.get('impressions') or 0):,} impressions | "
                f"{int(r.get('clicks') or 0):,} clicks | "
                f"{float(r.get('ctr') or 0):.2f}% CTR | "
                f"{int(r.get('conversions') or 0):,} conversions"
            )
    else:
        lines.append("No placement events recorded yet.")

    lines += [
        "",
        "Generated by BoxOfficeX OTT Contextual Sponsorship System.",
        "Estimated revenue is based on configured fixed fee, CPC and CPA values.",
    ]

    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(str(line), width=88) or [""])

    # Multi-page minimal PDF using built-in Helvetica.
    pages = []
    page_lines = []
    for line in wrapped:
        if len(page_lines) >= 39:
            pages.append(page_lines)
            page_lines = []
        page_lines.append(line)
    if page_lines or not pages:
        pages.append(page_lines)

    objects = []
    # 1 Catalog, 2 Pages placeholder
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")  # fill after page object numbers known

    page_obj_nums = []
    content_obj_nums = []
    next_obj = 3

    for page_index, lines_for_page in enumerate(pages):
        page_obj_nums.append(next_obj)
        content_obj_nums.append(next_obj + 1)
        next_obj += 2

        content = ["BT", "/F1 15 Tf", "45 805 Td"]
        for i, line in enumerate(lines_for_page):
            if i == 0:
                content.append(f"({_pdf_escape(line)}) Tj")
                content.append("/F1 9.5 Tf")
            else:
                content.append("0 -18 Td")
                content.append(f"({_pdf_escape(line)}) Tj")
        content.append("ET")
        stream = "\n".join(content).encode("latin-1", "replace")

        page_obj = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {next_obj + (len(pages)-page_index-1)*0} 0 R >> >> "
            f"/Contents {content_obj_nums[-1]} 0 R >>"
        )
        # Font object number is fixed after all page/content objects:
        font_obj_num = 3 + len(pages) * 2
        page_obj = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {font_obj_num} 0 R >> >> "
            f"/Contents {content_obj_nums[-1]} 0 R >>"
        ).encode()

        objects.append(page_obj)
        objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")

    font_obj_num = 3 + len(pages) * 2
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    kids = " ".join(f"{n} 0 R" for n in page_obj_nums)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_obj_nums)} >>".encode()

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{i} 0 obj\n".encode())
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects)+1}\n".encode())
    pdf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode())
    pdf.extend(
        f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF".encode()
    )
    return bytes(pdf)


@app.get("/admin/ott-sponsorships/{sponsorship_id}/report.pdf", dependencies=[Depends(require_owner)])
def admin_download_ott_campaign_report_pdf(sponsorship_id: int):
    report = _get_ott_campaign_report_data(sponsorship_id)
    campaign = report["campaign"]
    pdf = _build_ott_report_pdf(report)
    filename = (
        "BoxOfficeX-OTT-Report-"
        + _safe_report_filename(campaign.get("campaign_name"))
        + f"-{sponsorship_id}.pdf"
    )
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/admin/ott-sponsorships/{sponsorship_id}/report.csv", dependencies=[Depends(require_owner)])
def admin_download_ott_campaign_report_csv(sponsorship_id: int):
    report = _get_ott_campaign_report_data(sponsorship_id)
    c = report["campaign"]
    rows = report.get("placement_performance") or []

    def csv_cell(value):
        value = "" if value is None else str(value)
        return '"' + value.replace('"', '""') + '"'

    csv_rows = [
        ["BOXOFFICEX OTT SPONSORSHIP CAMPAIGN REPORT"],
        [],
        ["Campaign ID", c.get("id")],
        ["Campaign Name", c.get("campaign_name")],
        ["OTT Platform", c.get("platform_name")],
        ["Status", c.get("status")],
        ["Package", c.get("package_label")],
        ["Rotation Capacity", c.get("rotation_capacity")],
        ["Quoted Package Rate INR", c.get("quoted_rate", 0)],
        ["Start Date", c.get("start_date")],
        ["End Date", c.get("end_date")],
        ["Placements", ", ".join(c.get("placements") or [])],
        [],
        ["Impressions", c.get("impressions", 0)],
        ["Clicks", c.get("clicks", 0)],
        ["CTR %", c.get("ctr", 0)],
        ["Conversions", c.get("conversions", 0)],
        [],
        ["Fixed Fee INR", c.get("fixed_fee", 0)],
        ["CPC Rate INR", c.get("cpc_rate", 0)],
        ["CPA Rate INR", c.get("cpa_rate", 0)],
        ["Estimated CPC Revenue INR", c.get("estimated_cpc_revenue", 0)],
        ["Estimated CPA Revenue INR", c.get("estimated_cpa_revenue", 0)],
        ["Estimated Total Revenue INR", c.get("estimated_total_revenue", 0)],
        [],
        ["Placement", "Impressions", "Clicks", "CTR %", "Conversions"],
    ]

    for r in rows:
        csv_rows.append([
            r.get("placement"),
            r.get("impressions", 0),
            r.get("clicks", 0),
            r.get("ctr", 0),
            r.get("conversions", 0),
        ])

    content = "\ufeff" + "\r\n".join(
        ",".join(csv_cell(v) for v in row)
        for row in csv_rows
    )

    filename = (
        "BoxOfficeX-OTT-Report-"
        + _safe_report_filename(c.get("campaign_name"))
        + f"-{sponsorship_id}.csv"
    )
    return Response(
        content=content.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/admin-ott-sponsorships.html", dependencies=[Depends(require_owner)])
def admin_ott_sponsorships_page():
    return FileResponse(BASE_DIR / "admin-ott-sponsorships.html")


@app.get("/admin-ott-inventory.html", dependencies=[Depends(require_owner)])
def admin_ott_inventory_page():
    return FileResponse(BASE_DIR / "admin-ott-inventory.html")
