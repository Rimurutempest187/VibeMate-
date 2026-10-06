# -*- coding: utf-8 -*-
"""
=============================================================================
 VibeMate — Telegram Matchmaking Bot (single-file production application)
=============================================================================
 Tech stack : Python 3.12+, aiogram 3.x, SQLAlchemy 2.0 (async), PostgreSQL
              (asyncpg) or SQLite (aiosqlite), optional Redis, FastAPI +
              Uvicorn admin/health server, pydantic-settings, bcrypt,
              itsdangerous (signed admin sessions / CSRF), Telegram Stars
              payments.
 Structure  : this file is organised in numbered SECTIONS (see the banners).
              Everything (config, i18n, ORM models, services, bot handlers,
              admin web app, lifecycle, tests) lives in this single module.
 Run        : python bot.py
 Tests      : python -m pytest bot.py -v        (imports are side-effect free)
 Self-test  : TEST_MODE=true python bot.py --selftest
=============================================================================
"""
from __future__ import annotations

# ===========================================================================
# SECTION 1 — STANDARD LIBRARY IMPORTS
# ===========================================================================
import asyncio
import hashlib
import hmac
import html
import json
import logging
import secrets
import string
import sys
import time
import uuid
from contextlib import suppress
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional
from zoneinfo import ZoneInfo

# ===========================================================================
# SECTION 2 — THIRD-PARTY IMPORTS
# ===========================================================================
import bcrypt
import itsdangerous
from PIL import Image
from pydantic import AliasChoices, BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from sqlalchemy import (
    BigInteger, Boolean, Date, DateTime, ForeignKey, Index, Integer, String,
    UniqueConstraint, and_, delete, event, func, or_, select, text, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncAttrs, AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, selectinload,
)

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand, CallbackQuery, ErrorEvent, InlineKeyboardButton,
    InlineKeyboardMarkup, KeyboardButton, LabeledPrice, Message, BufferedInputFile,
    PreCheckoutQuery, ReplyKeyboardMarkup, ReplyKeyboardRemove,
    TelegramObject, Update, User as TgUser,
)

from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
)
import uvicorn

# Optional Redis (FSM storage + distributed rate limiting).
# Imported lazily so the dependency stays optional in development.
try:  # pragma: no cover - environment dependent
    import redis.asyncio as aioredis
    from aiogram.fsm.storage.redis import RedisStorage
    _REDIS_AVAILABLE = True
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore[assignment]
    RedisStorage = None  # type: ignore[assignment]
    _REDIS_AVAILABLE = False

APP_NAME = "VibeMate"
APP_VERSION = "3.3.1"
OWNER_TELEGRAM_ID = 1812962224

# ===========================================================================
# SECTION 3 — CONFIGURATION (pydantic-settings, environment-driven)
# ===========================================================================

class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    Every secret and deployment-specific value comes from the environment.
    Nothing sensitive is hardcoded. `validate_production()` refuses to start
    in production when essential security configuration is missing.
    """
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore",
        case_sensitive=False,
    )

    # --- Mandatory ---
    bot_token: str = ""

    # --- Database ---
    # Production : postgresql+asyncpg://user:pass@host:5432/matchmaking
    # Development: sqlite+aiosqlite:///./matchmaking.db
    database_url: str = "sqlite+aiosqlite:///./matchmaking.db"

    # --- Redis (optional) ---
    redis_url: str = ""                      # e.g. redis://localhost:6379/0
    allow_memory_fallback: bool = True       # dev-only in-memory FSM/ratelimit

    # --- Bot serving mode ---
    bot_mode: str = "polling"                # polling | webhook
    webhook_url: str = ""                    # https://example.com/tg/webhook
    webhook_secret: str = ""                 # X-Telegram-Bot-Api-Secret-Token

    # --- Web server (FastAPI) ---
    web_server_host: str = "0.0.0.0"
    # Railway provides PORT automatically; WEB_SERVER_PORT remains available locally.
    web_server_port: int = Field(
        default=8000,
        validation_alias=AliasChoices("WEB_SERVER_PORT", "PORT"),
    )

    # --- Admin bootstrap credentials (first run creates/updates the admin) ---
    admin_username: str = "admin"
    admin_password: str = ""                 # hashed with bcrypt at startup

    # --- Crypto / sessions ---
    secret_key: str = ""                     # signs admin sessions + CSRF
    admin_session_ttl_seconds: int = 12 * 3600

    # --- Business rules ---
    timezone: str = "UTC"                    # daily-limit reset timezone
    free_daily_likes: int = 20
    premium_daily_likes: int = 100
    free_daily_super_likes: int = 1
    premium_daily_super_likes: int = 5
    premium_price_stars: int = 100           # Telegram Stars price (XTR)
    premium_duration_days: int = 30
    welcome_trial_days: int = 30            # every newly registered user gets one free month
    daily_recommendation_limit: int = 5
    referral_reward_days: int = 7
    boost_duration_hours: int = 24
    chat_rate_limit_per_minute: int = 20
    report_rate_limit_per_day: int = 10
    appeal_rate_limit_per_day: int = 2
    flood_limit_messages: int = 12           # anti-flood middleware
    flood_window_seconds: int = 8
    retention_days_messages: int = 90        # relay-message metadata retention
    # Romantic matching is adults-only; do not mix minors into this service.
    min_age: int = 18
    max_age: int = 60

    # --- Ops ---
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:8000"
    environment: str = "development"         # development | production
    test_mode: bool = False

    # --- Derived helpers -------------------------------------------------
    @property
    def tz(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.timezone)
        except Exception:
            return ZoneInfo("UTC")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def validate_production(self) -> list[str]:
        """Return a list of fatal configuration problems (empty list = OK)."""
        problems: list[str] = []
        if not self.bot_token:
            problems.append("BOT_TOKEN is required.")
        if self.bot_mode not in ("polling", "webhook"):
            problems.append("BOT_MODE must be 'polling' or 'webhook'.")
        if self.bot_mode == "webhook":
            if not self.webhook_url.startswith("https://"):
                problems.append("WEBHOOK_URL must be a valid https:// URL.")
            if not self.webhook_secret:
                problems.append("WEBHOOK_SECRET is required in webhook mode.")
        if self.is_production:
            if len(self.secret_key) < 32:
                problems.append("SECRET_KEY must be >= 32 random characters in production.")
            if not self.admin_password or len(self.admin_password) < 12:
                problems.append("ADMIN_PASSWORD (>= 12 chars) is required in production.")
            if self.is_sqlite:
                problems.append("DATABASE_URL must be PostgreSQL in production.")
        return problems


settings = Settings()

# ===========================================================================
# SECTION 4 — LOGGING (privacy-aware: never log secrets / message bodies)
# ===========================================================================
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("matchmaking")


def safe_id(value: Any) -> str:
    """Pseudonymise an identifier for logs (privacy-aware logging)."""
    digest = hashlib.sha256(str(value).encode()).hexdigest()
    return f"u_{digest[:10]}"

# ===========================================================================
# SECTION 5 — SECURITY UTILITIES
# ===========================================================================

def hash_password(plain: str) -> str:
    """Hash an admin password with bcrypt (cost 12)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


_signer: itsdangerous.URLSafeTimedSerializer | None = None


def get_signer() -> itsdangerous.URLSafeTimedSerializer:
    """Serializer used for admin session cookies and CSRF tokens."""
    global _signer
    if _signer is None:
        key = settings.secret_key or "dev-insecure-key-change-me"
        _signer = itsdangerous.URLSafeTimedSerializer(key, salt="matchmaking-admin-v2")
    return _signer


def sign_session(payload: dict) -> str:
    return get_signer().dumps(payload)


def unsign_session(token: str, max_age: int) -> dict | None:
    try:
        data = get_signer().loads(token, max_age=max_age)
        return data if isinstance(data, dict) else None
    except (itsdangerous.BadSignature, itsdangerous.SignatureExpired):
        return None


def generate_csrf(session_id: str) -> str:
    """Session-bound CSRF token for browser admin forms."""
    return hmac.new(
        (settings.secret_key or "dev").encode(), session_id.encode(), hashlib.sha256
    ).hexdigest()


def check_csrf(session_id: str, token: str) -> bool:
    return hmac.compare_digest(generate_csrf(session_id), token)


def escape(value: Any) -> str:
    """HTML-escape user-controlled content before embedding in pages."""
    return html.escape(str(value if value is not None else ""), quote=True)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def today_local() -> date:
    """Current date in the configured daily-reset timezone."""
    return utcnow().astimezone(settings.tz).date()


def as_utc(dt: datetime | None) -> datetime | None:
    """Normalize a datetime to UTC-aware (SQLite returns naive datetimes)."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

# ===========================================================================
# SECTION 6 — RATE LIMITER (Redis fixed window with in-memory fallback)
# ===========================================================================

class RateLimiter:
    """Fixed-window rate limiter. Redis-backed in multi-instance production;
    in-memory for local development (NOT safe across multiple processes)."""

    _MEMORY_BUCKET_CAP = 50_000

    def __init__(self) -> None:
        self._memory: dict[str, tuple[int, float]] = {}
        self._redis: Any = None

    def configure(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Return True if the action is allowed, False if rate-limited."""
        now = time.time()
        if self._redis is not None:
            try:
                bucket = f"rl:{key}:{int(now // window_seconds)}"
                count = await self._redis.incr(bucket)
                if count == 1:
                    await self._redis.expire(bucket, window_seconds + 1)
                return int(count) <= limit
            except Exception as exc:  # degrade to memory on Redis failure
                log.warning("Redis rate limiter degraded to memory: %s", type(exc).__name__)
        bucket_key = f"{key}:{int(now // window_seconds)}"
        count, _ = self._memory.get(bucket_key, (0, now))
        self._memory[bucket_key] = (count + 1, now)
        if len(self._memory) > self._MEMORY_BUCKET_CAP:  # bound memory usage
            cutoff = now - window_seconds * 2
            self._memory = {k: v for k, v in self._memory.items() if v[1] > cutoff}
        return count + 1 <= limit


rate_limiter = RateLimiter()

# ===========================================================================
# SECTION 7 — LOCALIZATION (centralized translation dictionary, EN + Burmese)
# ===========================================================================
LANG_EN, LANG_MY = "en", "my"
SUPPORTED_LANGS = (LANG_EN, LANG_MY)

TRANSLATIONS: dict[str, dict[str, str]] = {
    # --- generic ---
    "yes":            {"en": "✅ Yes", "my": "✅ ဟုတ်ကဲ့"},
    "no":             {"en": "❌ No", "my": "❌ မဟုတ်ပါ"},
    "cancel":         {"en": "🚫 Cancel", "my": "🚫 ဖျက်သိမ်းမည်"},
    "back":           {"en": "⬅️ Back", "my": "⬅️ နောက်သို့"},
    "cancelled":      {"en": "Cancelled. Back to the main menu.", "my": "ဖျက်သိမ်းလိုက်ပါပြီ။ ပင်မမီနူးသို့ ပြန်ရောက်ပါပြီ။"},
    "error_generic":  {"en": "⚠️ Something went wrong. Please try again.", "my": "⚠️ တစ်ခုခုမှားယွင်းသွားပါသည်။ ထပ်မံကြိုးစားပါ။"},
    "unknown_command":{"en": "❓ Unknown command. Tap /help to see what I can do.",
                       "my": "❓ မသိသော အမိန့်ပါ။ ကျွန်ုပ် လုပ်ဆောင်ပေးနိုင်သည်များကို /help ဖြင့် ကြည့်ပါ။"},
    "banned":         {"en": "⛔ Your account has been suspended. Use /appeal if you believe this is a mistake.",
                       "my": "⛔ သင့်အကောင့်ကို ဆိုင်းငံ့ထားပါသည်။ မှားယွင်းမှုရှိသည်ဟုထင်ပါက /appeal ကိုအသုံးပြုပါ။"},
    # --- registration ---
    "welcome":        {"en": "👋 Welcome to <b>VibeMate</b>! Find meaningful connections safely. Let's set up your profile.",
                       "my": "👋 <b>VibeMate</b> မှ ကြိုဆိုပါသည်! လုံခြုံစွာ ဆက်ဆံရေးအသစ်များ ရှာဖွေပါ။ သင့်ပရိုဖိုင်ကို စတင်ဖန်တီးကြရအောင်။"},
    "ask_name":       {"en": "What display name should others see? (2–40 characters)",
                       "my": "အခြားသူများမြင်ရမည့် အမည်ကို ရိုက်ထည့်ပါ။ (၂–၄၀ လုံး)"},
    "name_invalid":   {"en": "Please enter a valid name (2–40 characters, letters only).",
                       "my": "မှန်ကန်သောအမည် ရိုက်ထည့်ပါ (၂–၄၀ လုံး၊ စာလုံးများသာ)။"},
    "ask_age":        {"en": "How old are you? (Adults 18–60 only)", "my": "အသက်အရွယ် ရိုက်ထည့်ပါ။ (လူကြီး ၁၈–၆၀ နှစ်သာ)"},
    "age_invalid":    {"en": "Please enter a whole-number age from 18 to 60.", "my": "အသက်ကို ၁၈ မှ ၆၀ အတွင်း ကိန်းပြည့်ဖြင့် ရိုက်ပါ။"},
    "age_under18":    {"en": "⛔ VibeMate is an adults-only service (18+). Registration has been cancelled.",
                       "my": "⛔ VibeMate သည် အသက် ၁၈ နှစ်နှင့်အထက် လူကြီးများအတွက်သာ ဖြစ်ပါသည်။ မှတ်ပုံတင်မှုကို ရပ်ဆိုင်းလိုက်ပါသည်။"},
    "age_notice":     {"en": "ℹ️ Age is self-reported. Romantic matching is for adults only. Report suspicious profiles with /report.",
                       "my": "ℹ️ အသက်အရွယ်သည် ကိုယ်တိုင်ဖြည့်စွက်ခြင်းဖြစ်သည်။ ချစ်သူရှာဖွေမှုသည် လူကြီးများအတွက်သာ ဖြစ်သည်။ သံသယဖြစ်ဖွယ်ပရိုဖိုင်များကို /report ဖြင့် တိုင်ကြားပါ။"},
    "ask_gender":     {"en": "What is your gender?", "my": "သင့်ကျားမ အမျိုးအစားကို ရွေးချယ်ပါ။"},
    "gender_male":    {"en": "👨 Male", "my": "👨 အမျိုးသား"},
    "gender_female":  {"en": "👩 Female", "my": "👩အမျိုးသမီး"},
    "gender_other":   {"en": "🧑 Other", "my": "🧑 အခြား"},
    "profile_gender": {"en": "Gender: {gender}", "my": "ကျား/မ: {gender}"},
    "ask_pref_gender":{"en": "Who would you like to meet?", "my": "မည်သူ့ကို တွေ့ဆုံလိုပါသလဲ။"},
    "pref_everyone":  {"en": "💞 Everyone", "my": "💞 အားလုံး"},
    "ask_intent":     {"en": "What kind of connection are you looking for?", "my": "မည်သည့်ဆက်ဆံရေးမျိုးကို ရှာဖွေနေပါသလဲ။"},
    "intent_girlfriend": {"en": "👩 Girlfriend", "my": "👩 မိန်းကလေးချစ်သူ"},
    "intent_boyfriend": {"en": "👨 Boyfriend", "my": "👨 ယောကျ်ားလေးချစ်သူ"},
    "intent_game_friend": {"en": "🎮 Game-play friend", "my": "🎮 ဂိမ်းကစားဖော်"},
    "intent_just_friend": {"en": "🤝 Just friend", "my": "🤝 သူငယ်ချင်းသက်သက်"},
    "ask_game_name":  {"en": "🎮 Which game do you play?", "my": "🎮 ဘယ်ဂိမ်းကို ကစားပါသလဲ။"},
    "ask_game_rank":  {"en": "🏆 Choose your rank or level.", "my": "🏆 သင့် rank/level ကို ရွေးပါ။"},
    "game_details":   {"en": "🎮 Game: {game}\n🏆 Rank: {rank}", "my": "🎮 ဂိမ်း: {game}\n🏆 Rank: {rank}"},
    "ask_city":       {"en": "Which city do you live in?", "my": "သင်နေထိုင်ရာမြို့ကို ရိုက်ထည့်ပါ။"},
    "ask_bio":        {"en": "Write a short bio (max 300 characters). Others will see this.",
                       "my": "မိမိအကြောင်း အကျဉ်းချုပ် ရေးပါ (အများဆုံး လုံး ၃၀၀)။"},
    "bio_invalid":    {"en": "Please write at least 20 characters so people can get to know you.",
                       "my": "အခြားသူများ သင့်ကိုသိနိုင်ရန် အနည်းဆုံး စာလုံး ၂၀ ရေးပါ။"},
    "ask_photo":      {"en": "📷 Send 1–3 profile photos. Tap ✅ Done when finished.",
                       "my": "📷 ပရိုဖိုင်ဓာတ်ပုံ ၁–၃ ပုံ ပေးပို့ပါ။ ပြီးပါက ✅ ပြီးပြီ ကို နှိပ်ပါ။"},
    "photo_added":    {"en": "Photo added ({n}/3).", "my": "ဓာတ်ပုံ ထည့်ပြီးပါပြီ ({n}/3)။"},
    "photo_max":      {"en": "📷 Maximum 3 photos. Tap ✅ Done or remove one first.",
                       "my": "📷 ဓာတ်ပုံ အများဆုံး ၃ ပုံသာ။ ✅ ပြီးပြီ ကိုနှိပ်ပါ သို့မဟုတ် တစ်ပုံဖျက်ပါ။"},
    "photos_done":    {"en": "✅ Done", "my": "✅ ပြီးပြီ"},
    "ask_interests":  {"en": "Pick your interests (tap to toggle), then press ✅ Done.",
                       "my": "စိတ်ဝင်စားမှုများ ရွေးချယ်ပါ (ထပ်နှိပ်၍ ပယ်ဖျက်နိုင်)၊ ပြီးပါက ✅ ပြီးပြီ နှိပ်ပါ။"},
    "ask_age_range":  {"en": "Preferred age range? Send as: 22-35", "my": "နှစ်သက်သော အသက်အရွယ်အကွာအဝေး။ ဥပမာ: 22-35"},
    "age_range_invalid": {"en": "Invalid range. Use the format 22-35.", "my": "မမှန်ပါ။ ပုံစံ 22-35 အတိုင်း ရိုက်ပါ။"},
    "ask_pref_city":  {"en": "Match only in your city? (Yes = same city only)",
                       "my": "သင့်မြို့အတွင်းသာ ရှာဖွေလိုပါသလား။"},
    "consent_text":   {"en": "🔐 <b>Privacy & Consent</b>\n\nYour profile (name, age, city, bio, photos) will be visible to other users for matching. Messages are relayed through this bot and may be reviewed under our moderation policy. Chats are <b>not</b> end-to-end encrypted. You can deactivate or permanently delete your data anytime with /settings or /delete.\n\nDo you consent to publishing your profile?",
                       "my": "🔐 <b>ကိုယ်ရေးကိုယ်တာနှင့် သဘောတူညီချက်</b>\n\nသင့်ပရိုဖိုင် (အမည်၊ အသက်၊ မြို့၊ မိတ်ဆက်စာ၊ ဓာတ်ပုံများ) ကို တွဲဖက်ရှာဖွေရန်အတွက် အခြားအသုံးပြုသူများအား ပြသပါမည်။ မက်ဆေ့ချ်များသည် ဤbot မှတစ်ဆင့် ပို့ဆောင်ပေးခြင်းဖြစ်ပြီး စီမံခန့်ခွဲမှုမူဝါဒအရ စစ်ဆေးနိုင်သည်။ စကားဝိုင်းများသည် end-to-end encrypted <b>မဟုတ်ပါ</b>။ /settings သို့မဟုတ် /delete ဖြင့် အချိန်မရွေး ပိတ်/ဖျက်နိုင်သည်။\n\nသင့်ပရိုဖိုင်ကို ထုတ်ဖော်ပြသရန် သဘောတူပါသလား။"},
    "consent_accept": {"en": "✅ I Consent", "my": "✅ သဘောတူသည်"},
    "consent_declined": {"en": "Understood. Your profile was not published. Use /start anytime to register.",
                          "my": "နားလည်ပါပြီ။ သင့်ပရိုဖိုင်ကို ထုတ်ဖော်မပြသပါ။ /start ဖြင့် အချိန်မရွေး ပြန်စတင်နိုင်သည်။"},
    "registration_done": {"en": "🎉 Your profile is live! Use /discover to start meeting people.",
                           "my": "🎉 သင့်ပရိုဖိုင် အသက်ဝင်ပါပြီ! /discover ဖြင့် စတင်ရှာဖွေပါ။"},
    # --- main menu ---
    "menu_discover":  {"en": "🔎 Discover", "my": "🔎 ရှာဖွေရန်"},
    "menu_daily":     {"en": "✨ Daily picks", "my": "✨ ယနေ့အကြံပြုချက်"},
    "menu_likes":     {"en": "❤️ Likes", "my": "❤️နှစ်သက်မှုများ"},
    "menu_matches":   {"en": "💕 Matches", "my": "💕 တွဲဖက်များ"},
    "menu_profile":   {"en": "👤 My Profile", "my": "👤 ကျွန်ုပ်၏ပရိုဖိုင်"},
    "menu_premium":   {"en": "⭐ Premium", "my": "⭐ ပရီမီယံ"},
    "menu_settings":  {"en": "⚙️ Settings", "my": "⚙️ ဆက်တင်များ"},
    "menu_safety":    {"en": "🛡️ Safety", "my": "🛡️ လုံခြုံမှု"},
    "menu_help":      {"en": "❓ Help", "my": "❓ အကူအညီ"},
    "choose_option":  {"en": "Choose an option:", "my": "ရွေးချယ်စရာတစ်ခု ရွေးပါ:"},
    # --- profile / discover ---
    "profile_card":   {"en": "<b>Name:</b> {name}\n<b>Age:</b> {age}\n<b>Gender:</b> {gender}\n<b>Located:</b> {city}\n<b>Looking For:</b> {intent}{game_info}\n\n💬 <i>{bio}</i>\n\n✨ <b>Interests</b>\n{interests}",
                       "my": "<b>အမည်:</b> {name}\n<b>အသက်:</b> {age}\n<b>ကျား/မ:</b> {gender}\n<b>နေထိုင်ရာ:</b> {city}\n<b>ရှာဖွေနေသည်:</b> {intent}{game_info}\n\n💬 <i>{bio}</i>\n\n✨ <b>စိတ်ဝင်စားမှုများ</b>\n{interests}"},
    "profile_no_bio": {"en": "Tell people a little about yourself.", "my": "မိမိအကြောင်း အနည်းငယ် ရေးထားပါ။"},
    "profile_no_interests": {"en": "Not added yet", "my": "မထည့်ရသေးပါ"},
    "profile_actions": {"en": "Choose an action below.", "my": "အောက်တွင် လုပ်ဆောင်ချက်တစ်ခု ရွေးပါ။"},
    "btn_like":       {"en": "❤️ Like", "my": "❤️ နှစ်သက်"},
    "btn_pass":       {"en": "👎 Pass", "my": "👎 ကျော်"},
    "btn_superlike":  {"en": "⭐ Super Like", "my": "⭐ အထူးနှစ်သက်"},
    "btn_report":     {"en": "🚩 Report", "my": "🚩 တိုင်ကြား"},
    "btn_block":      {"en": "⛔ Block", "my": "⛔ ပိတ်ဆို့"},
    "btn_unmatch":    {"en": "💔 Unmatch", "my": "💔 တွဲဖက်ဖျက်"},
    "btn_chat":       {"en": "💬 Chat", "my": "💬 စကားပြော"},
    "no_profiles":    {"en": "😴 No more profiles right now. Check back later!", "my": "😴 လောလောဆယ် ပရိုဖိုင်များ မရှိသေးပါ။ နောက်မှ ပြန်စစ်ပါ!"},
    "daily_limit":    {"en": "⏳ You've reached your daily Like limit ({n}). Try again tomorrow or go ⭐ Premium with /premium.",
                       "my": "⏳ နေ့စဉ် Like အကန့်အသတ် ({n}) သို့ ရောက်ရှိပါပြီ။ မနက်ဖြန် ပြန်ကြိုးစားပါ သို့မဟုတ် /premium ဖြင့် ⭐ Premium ရယူပါ။"},
    "match_notify":   {"en": "🎉 <b>It's a match!</b> You and {name} liked each other. Use /matches to start chatting.",
                       "my": "🎉 <b>တွဲဖက်တွေ့ပါပြီ!</b> သင်နှင့် {name} အချင်းချင်းနှစ်သက်ကြပါတယ်။ /matches ဖြင့် စကားပြောနိုင်ပါပြီ။"},
    "why_match":      {"en": "✨ Match score: {score}%\n{reasons}", "my": "✨ တွဲဖက်ကိုက်ညီမှု: {score}%\n{reasons}"},
    "daily_recommendation": {"en": "✨ Today's recommendation", "my": "✨ ယနေ့အတွက် အကြံပြုထားသောပရိုဖိုင်"},
    "recommendation_limit": {"en": "You've used today's {n} recommendations. Come back tomorrow!", "my": "ယနေ့အတွက် အကြံပြုချက် {n} ခု ပြည့်သွားပါပြီ။ မနက်ဖြန် ပြန်လာပါ။"},
    "icebreaker":     {"en": "💡 Send an icebreaker", "my": "💡 စကားစရန် မေးခွန်း"},
    "icebreaker_sent": {"en": "Icebreaker sent.", "my": "စကားစမေးခွန်း ပို့ပြီးပါပြီ။"},
    "invite_text":    {"en": "🎁 Invite friends to VibeMate\n\nYour invite link:\n{link}\n\nWhen a friend completes registration, you both receive extra perks.",
                       "my": "🎁 သူငယ်ချင်းများကို VibeMate ဖိတ်ပါ\n\nသင့် invite link:\n{link}\n\nသူငယ်ချင်းက registration ပြီးစီးပါက နှစ်ဦးစလုံး အပိုအကျိုးခံစားခွင့် ရပါမည်။"},
    "trial_active":   {"en": "🎁 Your first-month Premium trial is active until {until}.", "my": "🎁 သင့်ရဲ့ ပထမလ Premium အခမဲ့စမ်းသုံးခွင့်သည် {until} အထိ အသက်ဝင်နေပါသည်။"},
    "profile_quality": {"en": "✨ <b>Profile strength: {percent}%</b>\n{items}", "my": "✨ <b>ပရိုဖိုင်ပြည့်စုံမှု: {percent}%</b>\n{items}"},
    "privacy_saved":  {"en": "Privacy mode: {status}", "my": "ကိုယ်ရေးကိုယ်တာ mode: {status}"},
    "privacy_on":     {"en": "ON — show only your city, never your username", "my": "ဖွင့်ထားသည် — မြို့သာပြပြီး username မပြပါ"},
    "privacy_off":    {"en": "OFF", "my": "ပိတ်ထားသည်"},
    "referral_reward": {"en": "🎉 Referral reward unlocked! You received a 7-day Premium extension.", "my": "🎉 Referral reward ရပါပြီ။ Premium ၇ ရက် အပိုရရှိပါသည်။"},
    "play_time":      {"en": "When do you usually play?", "my": "ပုံမှန် ဘယ်အချိန်ကစားပါသလဲ။"},
    "superlike_left": {"en": "⭐ Super Likes left today: {n}", "my": "⭐ ယနေ့ ကျန် Super Like: {n}"},
    # --- matches / chat relay ---
    "matches_empty":  {"en": "No matches yet. Keep discovering with /discover!", "my": "တွဲဖက် မရှိသေးပါ။ /discover ဖြင့် ဆက်ရှာပါ!"},
    "likes_empty":    {"en": "No one has liked you yet — or it's a Premium feature. /premium",
                       "my": "သင့်ကို နှစ်သက်သူ မရှိသေးပါ — သို့မဟုတ် Premium လုပ်ဆောင်ချက်ဖြစ်သည်။ /premium"},
    "likes_premium_only": {"en": "👀 See who liked you with ⭐ Premium. /premium", "my": "👀 မည်သူများ နှစ်သက်သည်ကို ⭐ Premium ဖြင့် ကြည့်ပါ။ /premium"},
    "chat_started":   {"en": "💬 Relay chat with {name} started. Messages pass through this bot and follow our moderation policy (not end-to-end encrypted). /stopchat to end.",
                        "my": "💬 {name} နှင့် စကားပြောခြင်း စတင်ပါပြီ။ မက်ဆေ့ချ်များကို ဤbot မှတစ်ဆင့် ပို့ဆောင်ပေးပြီး စီမံခန့်ခွဲမှုမူဝါဒအရ လုပ်ဆောင်သည် (end-to-end encrypted မဟုတ်ပါ)။ ရပ်ရန် /stopchat။"},
    "chat_stopped":   {"en": "Chat session ended.", "my": "စကားပြောခြင်း ပြီးဆုံးပါပြီ။"},
    "chat_not_active": {"en": "No active chat. Pick a match with /matches first.", "my": "စကားပြောခန်း မရှိပါ။ /matches ဖြင့် တွဲဖက်တစ်ဦး အရင်ရွေးပါ။"},
    "chat_peer_gone": {"en": "⚠️ This match is no longer available.", "my": "⚠️ ဤတွဲဖက်သည် မရရှိနိုင်တော့ပါ။"},
    "msg_rate_limited": {"en": "⏳ Slow down — you're sending messages too fast.", "my": "⏳ မက်ဆေ့ချ် အရမ်းမြန်နေပါသည် — ခဏစောင့်ပါ။"},
    "peer_blocked_bot": {"en": "⚠️ Couldn't deliver: your match has blocked the bot.", "my": "⚠️ ပို့ဆောင်မရပါ — သင့်တွဲဖက်က bot ကို ပိတ်ထားပါသည်။"},
    # --- premium / payments ---
    "premium_info":   {"en": "⭐ <b>Premium</b> — {days} days for {price} Telegram Stars\n• First month free for every new user\n• {likes} Likes/day\n• See who liked you\n• {sl} Super Likes/day\n• 1 profile boost (24h)\n• Advanced matching and recommendations",
                        "my": "⭐ <b>Premium</b> — {days} ရက်၊ Telegram Stars {price}\n• User အသစ်တိုင်း ပထမလ အခမဲ့\n• တစ်နေ့ Like {likes} ခု\n• မည်သူ နှစ်သက်သည်ကို ကြည့်နိုင်\n• တစ်နေ့ Super Like {sl} ခု\n• ပရိုဖိုင် boost ၁ ခု (၂၄ နာရီ)\n• အဆင့်မြင့်တွဲဖက်ရှာဖွေမှု"},
    "premium_active": {"en": "⭐ Premium active until {until}.", "my": "⭐ Premium — {until} အထိ အသက်ဝင်သည်။"},
    "premium_on":     {"en": "⭐ Premium active", "my": "⭐ Premium အသက်ဝင်နေပါသည်"},
    "premium_free":   {"en": "Free plan: {likes} Likes/day. Upgrade with /premium.", "my": "အခမဲ့အစီအစဉ်: တစ်နေ့ Like {likes} ခု။ /premium ဖြင့် အဆင့်မြှင့်ပါ။"},
    "payment_success":{"en": "🎉 Payment confirmed — Premium activated until {until}. Enjoy!",
                        "my": "🎉 ငွေပေးချေမှု အတည်ပြုပြီး — Premium ကို {until} အထိ ဖွင့်ပေးပါပြီ။"},
    "payment_failed": {"en": "⚠️ Payment was not completed.", "my": "⚠️ ငွေပေးချေမှု မအောင်မြင်ပါ။"},
    # --- settings / account ---
    "settings_menu":  {"en": "⚙️ Settings", "my": "⚙️ ဆက်တင်များ"},
    "btn_language":   {"en": "🌐 Language", "my": "🌐 ဘာသာစကား"},
    "btn_deactivate": {"en": "⏸️ Deactivate profile", "my": "⏸️ ပရိုဖိုင် ခဏပိတ်"},
    "btn_activate":   {"en": "▶️ Reactivate profile", "my": "▶️ ပရိုဖိုင် ပြန်ဖွင့်"},
    "btn_privacy":    {"en": "🔒 Privacy mode", "my": "🔒 ကိုယ်ရေးကိုယ်တာ mode"},
    "btn_edit":       {"en": "✏️ Edit profile", "my": "✏️ ပရိုဖိုင် ပြင်"},
    "btn_delete":     {"en": "🗑️ Delete account", "my": "🗑️ အကောင့် ဖျက်"},
    "deactivated":    {"en": "Your profile is now hidden. Reactivate anytime in /settings.", "my": "သင့်ပရိုဖိုင်ကို ဖျောက်ထားပါပြီ။ /settings တွင် ပြန်ဖွင့်နိုင်သည်။"},
    "activated":      {"en": "Welcome back! Your profile is visible again.", "my": "ပြန်လည်ကြိုဆိုပါတယ်! သင့်ပရိုဖိုင် ပြန်မြင်ရပါပြီ။"},
    "delete_confirm": {"en": "⚠️ Permanently delete your account and personal data? This cannot be undone.",
                        "my": "⚠️ သင့်အကောင့်နှင့် ကိုယ်ရေးအချက်အလက်များကို အပြီးအပိုင် ဖျက်မည်ဖြစ်ပါသည်။ ပြန်လည်ရယူ၍ မရပါ။"},
    "deleted":        {"en": "Your account and personal data have been deleted. Goodbye 👋", "my": "သင့်အကောင့်နှင့် အချက်အလက်များ ဖျက်လိုက်ပါပြီ။ နောင်တွေ့မည် 👋"},
    "language_choose":{"en": "🌐 Choose your language / ဘာသာစကားရွေးပါ", "my": "🌐 Choose your language / ဘာသာစကားရွေးပါ"},
    "language_saved": {"en": "Language set to English.", "my": "မြန်မာဘာသာသို့ ပြောင်းလဲပြီးပါပြီ။"},
    # --- safety / moderation ---
    "safety_text":    {"en": "🛡️ <b>Safety</b>\n• Never share money or financial info.\n• Meet in public places.\n• Report suspicious users with /report.\n• Block anytime from a profile card.",
                        "my": "🛡️ <b>လုံခြုံရေး</b>\n• ငွေကြေးအချက်အလက်များ မမျှဝေပါနှင့်။\n• လူများရာနေရာများတွင် တွေ့ဆုံပါ။\n• သံသယဖြစ်ဖွယ် အသုံးပြုသူများကို /report ဖြင့် တိုင်ကြားပါ။\n• ပရိုဖိုင်ကတ်မှ အချိန်မရွေး ပိတ်ဆို့နိုင်သည်။"},
    "help_text":      {"en": "❓ <b>Commands</b>\n/start · /discover · /recommend · /matches · /likes\n/profile · /edit · /settings · /premium · /subscription\n/invite · /report · /stopchat · /language · /safety · /delete · /help",
                        "my": "❓ <b>အမိန့်များ</b>\n/start · /discover · /recommend · /matches · /likes\n/profile · /edit · /settings · /premium · /subscription\n/invite · /report · /stopchat · /language · /safety · /delete · /help"},
    "report_choose":  {"en": "Why are you reporting {name}?", "my": "{name} ကို အဘယ်ကြောင့် တိုင်ကြားသည်နည်း။"},
    "report_hint":    {"en": "To report someone, open their profile card in /discover and tap 🚩 Report.",
                       "my": "တိုင်ကြားရန် /discover ထဲက ၎င်း၏ ပရိုဖိုင်ကတ်ကို ဖွင့်ပြီး 🚩 တိုင်ကြား ကို နှိပ်ပါ။"},
    "report_sent":    {"en": "✅ Report submitted. Our moderators will review it. Thank you.", "my": "✅ တိုင်ကြားချက် ပို့ပြီးပါပြီ။ စီမံခန့်ခွဲသူများက စစ်ဆေးပေးပါမည်။ ကျေးဇူးတင်ပါသည်။"},
    "blocked":        {"en": "⛔ User blocked. They can no longer see or contact you.", "my": "⛔ ပိတ်ဆို့လိုက်ပါပြီ။ ၎င်းက သင့်ကို မမြင်/မဆက်သွယ်နိုင်တော့ပါ။"},
    "unmatched":      {"en": "💔 Match removed.", "my": "💔 တွဲဖက် ဖျက်လိုက်ပါပြီ။"},
    "confirm_action": {"en": "Are you sure?", "my": "သေချာပါသလား။"},
    "edit_what":      {"en": "What would you like to edit?", "my": "မည်သည့်အရာကို ပြင်ဆင်လိုပါသလဲ။"},
    "saved":          {"en": "✅ Saved.", "my": "✅ သိမ်းဆည်းပြီးပါပြီ။"},
    # --- appeals ---
    "appeal_prompt":  {"en": "📝 Describe why the suspension should be lifted (5–500 characters).",
                       "my": "📝 ဆိုင်းငံ့မှု ပယ်ဖျက်သင့်သည့် အကြောင်းပြချက်ကို ရေးပါ (၅–၅၀၀ လုံး)။"},
    "appeal_sent":    {"en": "✅ Appeal submitted. Our moderation team will review it.",
                       "my": "✅ အယူခံ ပို့ပြီးပါပြီ။ စီမံခန့်ခွဲအဖွဲ့က စစ်ဆေးပေးပါမည်။"},
    "appeal_too_short": {"en": "Please write at least 5 characters.", "my": "အနည်းဆုံး စာလုံး ၅ လုံး ရေးပါ။"},
}

INTERESTS: list[tuple[str, str, str]] = [
    # (key, english label, burmese label)
    ("music", "🎵 Music", "🎵 ဂီတ"), ("movies", "🎬 Movies", "🎬 ရုပ်ရှင်"),
    ("sports", "⚽ Sports", "⚽ အားကစား"), ("travel", "✈️ Travel", "✈️ ခရီးသွား"),
    ("food", "🍜 Food", "🍜 အစားအသောက်"), ("reading", "📚 Reading", "📚 စာဖတ်"),
    ("gaming", "🎮 Gaming", "🎮 ဂိမ်း"), ("art", "🎨 Art", "🎨 အနုပညာ"),
    ("tech", "💻 Tech", "💻 နည်းပညာ"), ("nature", "🌿 Nature", "🌿 သဘာဝ"),
    ("fitness", "💪 Fitness", "💪 ကျန်းမာရေး"), ("photo", "📷 Photography", "📷 ဓာတ်ပုံ"),
]
INTEREST_KEYS: frozenset[str] = frozenset(k for k, _en, _my in INTERESTS)


def t(lang: str, key: str, **kwargs: Any) -> str:
    """Translate `key` into `lang` (falls back to English, then to the key)."""
    entry = TRANSLATIONS.get(key, {})
    text_ = entry.get(lang) or entry.get(LANG_EN) or key
    try:
        return text_.format(**kwargs) if kwargs else text_
    except (KeyError, IndexError, ValueError):
        return text_


def interest_label(key: str, lang: str) -> str:
    for k, en, my in INTERESTS:
        if k == key:
            return my if lang == LANG_MY else en
    return key


def intent_label(key: str, lang: str) -> str:
    for k, en, my in INTENTS:
        if k == key:
            return my if lang == LANG_MY else en
    return key


def gender_label(key: str, lang: str) -> str:
    return {
        "male": t(lang, "gender_male"),
        "female": t(lang, "gender_female"),
        "other": t(lang, "gender_other"),
    }.get(key, key)


def game_option_label(kind: str, key: str, lang: str) -> str:
    catalog = GAME_OPTIONS.get(kind, ())
    for option_key, en, my in catalog:
        if option_key == key:
            return my if lang == LANG_MY else en
    return key


def game_rank_label(game_key: str, rank_key: str, lang: str) -> str:
    for option_key, en, my in GAME_RANKS.get(game_key, GAME_RANKS["other"]):
        if option_key == rank_key:
            return my if lang == LANG_MY else en
    return rank_key


def profile_quality(profile: Profile, lang: str = LANG_EN) -> tuple[int, str]:
    """Return a meaningful profile-strength score and actionable missing items.

    A profile is not considered complete merely because a column is non-empty:
    useful bio length, multiple photos, interests and game metadata all improve
    match quality and the visual card. The default English labels preserve the
    existing pure-function tests while callers may request Burmese labels.
    """
    labels = {
        "name": ("Name", "အမည်"), "age": ("Age", "အသက်"),
        "city": ("City", "မြို့"), "bio": ("Bio (20+ chars)", "မိတ်ဆက်စာ (၂၀+ လုံး)"),
        "photos": ("2+ photos", "ဓာတ်ပုံ ၂ ပုံနှင့်အထက်"),
        "interests": ("3+ interests", "စိတ်ဝင်စားမှု ၃ ခုနှင့်အထက်"),
        "intent": ("Connection type", "ဆက်ဆံရေးအမျိုးအစား"),
        "game": ("Game details", "ဂိမ်းအချက်အလက်"),
    }
    def label(key: str, done: bool) -> str:
        text = labels[key][1 if lang == LANG_MY else 0]
        return ("✅ " if done else "⬜ ") + text

    checks = [
        (bool(profile.display_name.strip()), "name"),
        (bool(profile.age), "age"),
        (bool(profile.city.strip()), "city"),
        (len((profile.bio or "").strip()) >= 20, "bio"),
        (len(profile.photos) >= 2, "photos"),
        (len(profile.interests) >= 3, "interests"),
        (profile.intent in INTENT_KEYS, "intent"),
    ]
    if profile.intent == "game_friend":
        checks.append((bool(profile.game_name and profile.game_rank), "game"))
    done = sum(ok for ok, _key in checks)
    percent = round(done * 100 / len(checks))
    missing = " · ".join(label(key, ok) for ok, key in checks if not ok)
    return percent, (missing or ("✅ Complete" if lang != LANG_MY else "✅ ပြည့်စုံပါပြီ"))

# ===========================================================================
# SECTION 8 — DATABASE LAYER (SQLAlchemy 2.0 async ORM models)
# ===========================================================================

class Base(AsyncAttrs, DeclarativeBase):
    """Declarative base for all ORM models."""


SCHEMA_VERSION = "3.3.0"

INTENTS: tuple[tuple[str, str, str], ...] = (
    ("girlfriend", "👩 Girlfriend", "👩 မိန်းကလေးချစ်သူ"),
    ("boyfriend", "👨 Boyfriend", "👨 ယောကျ်ားလေးချစ်သူ"),
    ("game_friend", "🎮 Game-play friend", "🎮 ဂိမ်းကစားဖော်"),
    ("just_friend", "🤝 Just friend", "🤝 သူငယ်ချင်းသက်သက်"),
)
INTENT_KEYS = frozenset(k for k, _en, _my in INTENTS)

GAME_OPTIONS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "name": (
        ("pubg_mobile", "PUBG Mobile", "PUBG Mobile"),
        ("free_fire", "Free Fire", "Free Fire"),
        ("mobile_legends", "Mobile Legends", "Mobile Legends"),
        ("valorant", "Valorant", "Valorant"),
        ("dota2", "Dota 2", "Dota 2"),
        ("league", "League of Legends", "League of Legends"),
        ("fortnite", "Fortnite", "Fortnite"),
        ("minecraft", "Minecraft", "Minecraft"),
        ("other", "Other game", "အခြားဂိမ်း"),
    ),
}

GAME_RANKS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "pubg_mobile": (("bronze", "Bronze", "Bronze"), ("silver", "Silver", "Silver"), ("gold", "Gold", "Gold"), ("platinum", "Platinum", "Platinum"), ("diamond", "Diamond", "Diamond"), ("crown", "Crown", "Crown"), ("ace", "Ace", "Ace"), ("conqueror", "Conqueror", "Conqueror")),
    "free_fire": (("bronze", "Bronze", "Bronze"), ("silver", "Silver", "Silver"), ("gold", "Gold", "Gold"), ("platinum", "Platinum", "Platinum"), ("diamond", "Diamond", "Diamond"), ("heroic", "Heroic", "Heroic"), ("master", "Master", "Master"), ("grandmaster", "Grandmaster", "Grandmaster")),
    "mobile_legends": (("warrior", "Warrior", "Warrior"), ("elite", "Elite", "Elite"), ("master", "Master", "Master"), ("grandmaster", "Grandmaster", "Grandmaster"), ("epic", "Epic", "Epic"), ("legend", "Legend", "Legend"), ("mythic", "Mythic", "Mythic"), ("mythical_honor", "Mythical Honor", "Mythical Honor"), ("mythical_glory", "Mythical Glory", "Mythical Glory")),
    "valorant": (("iron", "Iron", "Iron"), ("bronze", "Bronze", "Bronze"), ("silver", "Silver", "Silver"), ("gold", "Gold", "Gold"), ("platinum", "Platinum", "Platinum"), ("diamond", "Diamond", "Diamond"), ("ascendant", "Ascendant", "Ascendant"), ("immortal", "Immortal", "Immortal"), ("radiant", "Radiant", "Radiant")),
    "dota2": (("herald", "Herald", "Herald"), ("guardian", "Guardian", "Guardian"), ("crusader", "Crusader", "Crusader"), ("archon", "Archon", "Archon"), ("legend", "Legend", "Legend"), ("ancient", "Ancient", "Ancient"), ("divine", "Divine", "Divine"), ("immortal", "Immortal", "Immortal")),
    "league": (("iron", "Iron", "Iron"), ("bronze", "Bronze", "Bronze"), ("silver", "Silver", "Silver"), ("gold", "Gold", "Gold"), ("platinum", "Platinum", "Platinum"), ("emerald", "Emerald", "Emerald"), ("diamond", "Diamond", "Diamond"), ("master", "Master", "Master"), ("grandmaster", "Grandmaster", "Grandmaster"), ("challenger", "Challenger", "Challenger")),
    "fortnite": (("bronze", "Bronze", "Bronze"), ("silver", "Silver", "Silver"), ("gold", "Gold", "Gold"), ("platinum", "Platinum", "Platinum"), ("diamond", "Diamond", "Diamond"), ("elite", "Elite", "Elite"), ("champion", "Champion", "Champion"), ("unreal", "Unreal", "Unreal")),
    "minecraft": (("survival", "Survival", "Survival"), ("pvp", "PvP", "PvP"), ("creative", "Creative", "Creative"), ("speedrun", "Speedrun", "Speedrun"), ("casual", "Casual", "Casual")),
    "other": (("casual", "Casual / Unranked", "Casual / Unranked"), ("beginner", "Beginner", "Beginner"), ("intermediate", "Intermediate", "Intermediate"), ("advanced", "Advanced", "Advanced"), ("other", "Other", "အခြား")),
}
GAME_OPTION_KEYS = {k: frozenset(x[0] for x in values) for k, values in GAME_OPTIONS.items()}
GAME_RANK_KEYS = {k: frozenset(x[0] for x in values) for k, values in GAME_RANKS.items()}

ICEBREAKERS: tuple[tuple[str, str], ...] = (
    ("🎮 What game are you playing these days?", "🎮 အခုတလော ဘယ်ဂိမ်းကစားနေပါသလဲ။"),
    ("🎵 What song do you never get tired of?", "🎵 ဘယ်သီချင်းကို မရိုးနိုင်ဘဲ နားထောင်ပါသလဲ။"),
    ("🌆 What do you usually do on weekends?", "🌆 အားလပ်ရက်မှာ ပုံမှန် ဘာလုပ်ပါသလဲ။"),
    ("🍜 What food should I try in your city?", "🍜 သင့်မြို့မှာ ဘယ်အစားအစာကို စားကြည့်သင့်လဲ။"),
)


class User(Base):
    """One row per Telegram account. `id` is the Telegram user ID."""
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # Telegram user id
    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    language: Mapped[str] = mapped_column(String(4), default=LANG_EN)
    is_registered: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)      # deactivation
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False)
    ban_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    suspended_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    consented_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    active_match_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # chat relay
    last_active_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    referral_code: Mapped[str] = mapped_column(
        String(16), default=lambda: secrets.token_urlsafe(8)[:12])
    referred_by: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    referral_rewarded: Mapped[bool] = mapped_column(Boolean, default=False)
    privacy_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    welcome_trial_used: Mapped[bool] = mapped_column(Boolean, default=False)

    profile: Mapped[Optional["Profile"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False)


class Profile(Base):
    __tablename__ = "profiles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    display_name: Mapped[str] = mapped_column(String(40))
    age: Mapped[int] = mapped_column(Integer)
    gender: Mapped[str] = mapped_column(String(16))                    # male|female|other
    intent: Mapped[str] = mapped_column(String(24), default="just_friend")
    game_name: Mapped[str] = mapped_column(String(32), default="")
    game_rank: Mapped[str] = mapped_column(String(32), default="")
    game_platform: Mapped[str] = mapped_column(String(32), default="")
    bio: Mapped[str] = mapped_column(String(300), default="")
    city: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    user: Mapped[User] = relationship(back_populates="profile")
    photos: Mapped[list["ProfilePhoto"]] = relationship(
        back_populates="profile", cascade="all, delete-orphan",
        order_by="ProfilePhoto.position")
    preference: Mapped[Optional["MatchPreference"]] = relationship(
        back_populates="profile", cascade="all, delete-orphan", uselist=False)
    interests: Mapped[list["UserInterest"]] = relationship(
        back_populates="profile", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_profiles_gender_age", "gender", "age"),
                      Index("ix_profiles_city", "city"))


class ProfilePhoto(Base):
    __tablename__ = "profile_photos"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    file_id: Mapped[str] = mapped_column(String(255))   # Telegram file_id
    position: Mapped[int] = mapped_column(Integer, default=0)
    profile: Mapped[Profile] = relationship(back_populates="photos")


class Interest(Base):
    __tablename__ = "interests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(32), unique=True)


class UserInterest(Base):
    __tablename__ = "user_interests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    interest_key: Mapped[str] = mapped_column(String(32))
    profile: Mapped[Profile] = relationship(back_populates="interests")
    __table_args__ = (UniqueConstraint("profile_id", "interest_key", name="uq_user_interest"),)


class MatchPreference(Base):
    __tablename__ = "match_preferences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"), unique=True)
    preferred_gender: Mapped[str] = mapped_column(String(16), default="everyone")  # male|female|other|everyone
    min_age: Mapped[int] = mapped_column(Integer, default=18)
    max_age: Mapped[int] = mapped_column(Integer, default=60)
    same_city_only: Mapped[bool] = mapped_column(Boolean, default=False)
    profile: Mapped[Profile] = relationship(back_populates="preference")


class Like(Base):
    """A swipe. kind: like | superlike | pass (passes kept to avoid re-showing)."""
    __tablename__ = "likes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    from_user: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    to_user: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(12), default="like")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (
        UniqueConstraint("from_user", "to_user", name="uq_like_pair"),
        Index("ix_likes_to", "to_user", "kind"),
    )


class Match(Base):
    """Mutual like. user_a < user_b (canonical order prevents duplicates)."""
    __tablename__ = "matches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_a: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    user_b: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (UniqueConstraint("user_a", "user_b", name="uq_match_pair"),)


class MessageLog(Base):
    """Relay metadata ONLY (type + sender + match). Message contents are never stored."""
    __tablename__ = "message_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    match_id: Mapped[int] = mapped_column(Integer, ForeignKey("matches.id", ondelete="CASCADE"))
    from_user: Mapped[int] = mapped_column(BigInteger)
    to_user: Mapped[int] = mapped_column(BigInteger)
    content_type: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (Index("ix_msglogs_created", "created_at"),)


class Block(Base):
    __tablename__ = "blocks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    blocker: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    blocked: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("blocker", "blocked", name="uq_block_pair"),)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reporter: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    reported: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String(32))   # spam|inappropriate|harassment|fake|underage|other
    details: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(16), default="open")    # open|resolved|dismissed
    moderator_note: Mapped[str] = mapped_column(String(500), default="")
    resolved_by: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        UniqueConstraint("reporter", "reported", "category", name="uq_report_once"),
        Index("ix_reports_status", "status"),
    )


class Appeal(Base):
    __tablename__ = "appeals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    text: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(16), default="open")    # open|resolved|dismissed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (Index("ix_appeals_status", "status"),)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    plan: Mapped[str] = mapped_column(String(16), default="premium")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|expired|cancelled
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (Index("ix_subs_user_status", "user_id", "status"),)


class Payment(Base):
    """Verified Telegram payment record (Stars/XTR). charge id is unique → idempotent."""
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(16), default="telegram_stars")
    telegram_charge_id: Mapped[str] = mapped_column(String(128), unique=True)
    provider_charge_id: Mapped[str] = mapped_column(String(128), default="")
    amount: Mapped[int] = mapped_column(Integer)      # in Stars (XTR units)
    currency: Mapped[str] = mapped_column(String(8), default="XTR")
    payload: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16), default="succeeded")  # succeeded|refunded
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Boost(Base):
    __tablename__ = "boosts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (Index("ix_boosts_expiry", "expires_at"),)


class DailyUsage(Base):
    """Per-user daily counters, keyed by the configured timezone's local date."""
    __tablename__ = "daily_usage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    day: Mapped[date] = mapped_column(Date)
    likes_used: Mapped[int] = mapped_column(Integer, default=0)
    super_likes_used: Mapped[int] = mapped_column(Integer, default=0)
    recommendations_used: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("user_id", "day", name="uq_usage_day"),)


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="moderator")  # superadmin|moderator|support
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AdminSession(Base):
    """DB-backed session records (revocable); cookie carries the signed token."""
    __tablename__ = "admin_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id: Mapped[int] = mapped_column(Integer, ForeignKey("admin_users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    admin: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (Index("ix_audit_created", "created_at"),)


class Consent(Base):
    __tablename__ = "consents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32), default="profile_publication")
    granted: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    version: Mapped[str] = mapped_column(String(16), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --- Engine / session factory -----------------------------------------------
engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=5 if not settings.is_sqlite else 1,
    max_overflow=10 if not settings.is_sqlite else 0,
    pool_pre_ping=not settings.is_sqlite,
)
SessionFactory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

if settings.is_sqlite:
    # SQLite ignores FK constraints unless explicitly enabled per connection.
    # Without this, bulk deletes could leave orphaned photo/interest rows.
    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_enable_foreign_keys(dbapi_conn: Any, _record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


async def init_db() -> None:
    """Safe startup schema initialization.

    Creates missing tables only — never drops or alters existing data.
    Records the schema version and seeds the interest catalog.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # create_all does not alter an existing table. Upgrade v2.0.0 installs
        # safely by adding the new column only when it is missing.
        def _table_columns(sync_conn: Any, table: str) -> set[str]:
            from sqlalchemy import inspect
            return {c["name"] for c in inspect(sync_conn).get_columns(table)}
        profile_columns = await conn.run_sync(_table_columns, "profiles")
        profile_migrations = {
            "gender": "VARCHAR(16) NOT NULL DEFAULT 'other'",
            "intent": "VARCHAR(24) NOT NULL DEFAULT 'just_friend'",
            "game_name": "VARCHAR(32) NOT NULL DEFAULT ''",
            "game_rank": "VARCHAR(32) NOT NULL DEFAULT ''",
            "game_platform": "VARCHAR(32) NOT NULL DEFAULT ''",
            "bio": "VARCHAR(300) NOT NULL DEFAULT ''",
            "city": "VARCHAR(80) NOT NULL DEFAULT ''",
        }
        for column, definition in profile_migrations.items():
            if column not in profile_columns:
                await conn.execute(text(
                    f"ALTER TABLE profiles ADD COLUMN {column} {definition}"))
        user_columns = await conn.run_sync(_table_columns, "users")
        user_migrations = {
            "referral_code": "VARCHAR(16) NOT NULL DEFAULT ''",
            "referred_by": "BIGINT",
            "referral_rewarded": "BOOLEAN NOT NULL DEFAULT FALSE",
            "privacy_mode": "BOOLEAN NOT NULL DEFAULT TRUE",
            "welcome_trial_used": "BOOLEAN NOT NULL DEFAULT FALSE",
        }
        for column, definition in user_migrations.items():
            if column not in user_columns:
                await conn.execute(text(
                    f"ALTER TABLE users ADD COLUMN {column} {definition}"))
        preference_columns = await conn.run_sync(_table_columns, "match_preferences")
        if "same_city_only" not in preference_columns:
            await conn.execute(text(
                "ALTER TABLE match_preferences ADD COLUMN same_city_only "
                "BOOLEAN NOT NULL DEFAULT FALSE"))
        usage_columns = await conn.run_sync(_table_columns, "daily_usage")
        if "recommendations_used" not in usage_columns:
            await conn.execute(text(
                "ALTER TABLE daily_usage ADD COLUMN recommendations_used "
                "INTEGER NOT NULL DEFAULT 0"))
    async with SessionFactory() as s:
        existing = set((await s.execute(
            select(SchemaVersion.version))).scalars().all())
        if SCHEMA_VERSION not in existing:
            s.add(SchemaVersion(version=SCHEMA_VERSION))
        # Seed interest catalog (idempotent)
        for key, _en, _my in INTERESTS:
            if not (await s.execute(select(Interest).where(Interest.key == key))).scalar_one_or_none():
                s.add(Interest(key=key))
        await s.commit()
    log.info("Database schema ready (version %s)", SCHEMA_VERSION)

# ===========================================================================
# SECTION 9 — SERVICE LAYER (pure business logic, testable without Telegram)
# ===========================================================================

class UserService:
    """Account lifecycle helpers."""

    @staticmethod
    async def get_or_create(s: AsyncSession, tg: TgUser) -> User:
        user = await s.get(User, tg.id)
        if user is None:
            user = User(id=tg.id, username=(tg.username or "")[:64])
            s.add(user)
            await s.flush()
        elif tg.username and user.username != tg.username:
            user.username = tg.username[:64]
        user.last_active_at = utcnow()
        return user

    @staticmethod
    async def is_blocked(s: AsyncSession, user: User) -> bool:
        """Deleted, banned, or currently suspended accounts are blocked."""
        if user.deleted_at is not None or user.is_banned:
            return True
        suspended = as_utc(user.suspended_until)
        return bool(suspended and suspended > utcnow())


class ProfileService:
    """Profile retrieval, editing and GDPR-style deletion."""

    @staticmethod
    async def get_with_relations(s: AsyncSession, user_id: int) -> Optional[Profile]:
        q = (select(Profile).where(Profile.user_id == user_id)
             .options(selectinload(Profile.photos),
                      selectinload(Profile.interests),
                      selectinload(Profile.preference)))
        return (await s.execute(q)).scalar_one_or_none()

    @staticmethod
    async def upsert_interests(s: AsyncSession, profile: Profile, keys: list[str]) -> None:
        keys = [k for k in keys if k in INTEREST_KEYS][: len(INTERESTS)]
        await s.execute(delete(UserInterest).where(UserInterest.profile_id == profile.id))
        for k in keys:
            s.add(UserInterest(profile_id=profile.id, interest_key=k))
        await s.flush()

    @classmethod
    async def anonymize_and_delete(cls, s: AsyncSession, user_id: int) -> None:
        """GDPR-style deletion: remove profile data, anonymize the account row.
        Payment rows are kept (financial record) but detached from identity."""
        user = await s.get(User, user_id)
        if user is None:
            return
        # End matches, remove blocks/likes/usage rows involving the user
        await s.execute(update(Match).where(
            and_(or_(Match.user_a == user_id, Match.user_b == user_id), Match.is_active)
        ).values(is_active=False, ended_at=utcnow()))
        await s.execute(delete(Like).where(or_(Like.from_user == user_id, Like.to_user == user_id)))
        await s.execute(delete(Block).where(or_(Block.blocker == user_id, Block.blocked == user_id)))
        await s.execute(delete(DailyUsage).where(DailyUsage.user_id == user_id))
        await s.execute(delete(Boost).where(Boost.user_id == user_id))
        await s.execute(delete(Subscription).where(Subscription.user_id == user_id))
        await s.execute(delete(Consent).where(Consent.user_id == user_id))
        await s.execute(delete(Appeal).where(Appeal.user_id == user_id))
        # ORM delete cascades photos / interests / preference safely on every DB
        profile = await cls.get_with_relations(s, user_id)
        if profile is not None:
            await s.delete(profile)
        # Anonymize the account row instead of deleting (keeps FK integrity of payments)
        user.username = None
        user.is_registered = False
        user.is_active = False
        user.active_match_id = None
        user.deleted_at = utcnow()
        await s.flush()


class MatchService:
    """Discovery, swiping and match lifecycle."""

    @staticmethod
    def _canonical(a: int, b: int) -> tuple[int, int]:
        return (a, b) if a < b else (b, a)

    @staticmethod
    def compatibility_score(
        my_interests: set[str], their_interests: set[str],
        my_age: int, their_age: int, their_min: int, their_max: int,
        same_city: bool, boosted: bool, hours_since_active: float,
        game_match: bool = False, rank_match: bool = False,
    ) -> float:
        """Weighted recommendation score in [0, 1]. Pure function (unit-tested)."""
        score = 0.0
        union = my_interests | their_interests
        if union:
            score += 0.40 * (len(my_interests & their_interests) / len(union))
        if their_min <= my_age <= their_max:          # mutual age-window fit
            score += 0.20
        age_gap = abs(my_age - their_age)
        score += 0.10 * max(0.0, 1.0 - age_gap / 30.0)
        if same_city:
            score += 0.15
        if boosted:
            score += 0.10
        score += 0.05 * max(0.0, 1.0 - hours_since_active / 72.0)  # recency
        if game_match:
            score += 0.08
        if rank_match:
            score += 0.07
        return round(min(score, 1.0), 4)

    @classmethod
    async def next_candidate(cls, s: AsyncSession, viewer: User) -> Optional[Profile]:
        """Best next profile for the viewer, or None. Efficient, DB-filtered."""
        me = await ProfileService.get_with_relations(s, viewer.id)
        if me is None or me.preference is None:
            return None
        pref = me.preference

        blocked_q = select(Block.blocked).where(Block.blocker == viewer.id)
        blocked_by_q = select(Block.blocker).where(Block.blocked == viewer.id)
        seen_q = select(Like.to_user).where(Like.from_user == viewer.id)
        matched_q = select(Match.user_b).where(and_(Match.user_a == viewer.id, Match.is_active)).union(
            select(Match.user_a).where(and_(Match.user_b == viewer.id, Match.is_active)))

        q = (select(Profile)
             .join(User, User.id == Profile.user_id)
             .where(
                 Profile.user_id != viewer.id,                     # never yourself
                 User.is_registered.is_(True), User.is_active.is_(True),
                 User.is_banned.is_(False), User.deleted_at.is_(None),
                 or_(User.suspended_until.is_(None), User.suspended_until < utcnow()),
                 # Defense in depth: old installations may contain 12–17
                 # profiles from the previous configuration.
                 Profile.age >= max(settings.min_age, pref.min_age),
                 Profile.age <= pref.max_age,
                 Profile.age <= settings.max_age,
                 Profile.user_id.notin_(blocked_q),
                 Profile.user_id.notin_(blocked_by_q),
                 Profile.user_id.notin_(seen_q),
                 Profile.user_id.notin_(matched_q),
             )
             .options(selectinload(Profile.photos), selectinload(Profile.interests),
                      selectinload(Profile.preference)))
        # Enforce gender preference in BOTH directions:
        if pref.preferred_gender != "everyone":
            q = q.where(Profile.gender == pref.preferred_gender)
        # Match by purpose as well as gender. Romantic intents are reciprocal:
        # someone seeking a girlfriend sees someone seeking a boyfriend.
        counterpart = {"girlfriend": "boyfriend", "boyfriend": "girlfriend"}
        wanted_intent = counterpart.get(me.intent, me.intent)
        q = q.where(Profile.intent == wanted_intent)
        # ... the candidate must also want to see the viewer's gender:
        q = q.where(Profile.preference.has(or_(
            MatchPreference.preferred_gender == "everyone",
            MatchPreference.preferred_gender == me.gender,
        )))
        # Mutual age windows: viewer's age must fit the candidate's range.
        q = q.where(Profile.preference.has(and_(
            MatchPreference.min_age <= me.age, MatchPreference.max_age >= me.age,
            MatchPreference.min_age >= settings.min_age)))
        if pref.same_city_only:
            q = q.where(func.lower(Profile.city) == me.city.lower())

        q = q.order_by(User.last_active_at.desc()).limit(30)
        candidates = list((await s.execute(q)).scalars().all())
        if not candidates:
            return None

        # Score the shortlist in Python (bounded to 30 rows — no full-table load).
        my_interests = {i.interest_key for i in me.interests}
        boosted_ids = set((await s.execute(
            select(Boost.user_id).where(Boost.expires_at > utcnow()))).scalars().all())
        owners = {u.id: u for u in (await s.execute(
            select(User).where(User.id.in_([p.user_id for p in candidates])))).scalars().all()}
        now = utcnow()

        def score(p: Profile) -> float:
            tp = p.preference
            theirs = {i.interest_key for i in p.interests}
            owner = owners.get(p.user_id)
            last_active = as_utc(owner.last_active_at) if owner else None
            hours = (max(0.0, (now - last_active).total_seconds() / 3600.0)
                     if last_active else 999.0)
            return cls.compatibility_score(
                my_interests, theirs, me.age, p.age,
                tp.min_age if tp else settings.min_age,
                tp.max_age if tp else settings.max_age,
                same_city=p.city.lower() == me.city.lower(),
                boosted=p.user_id in boosted_ids, hours_since_active=hours,
                game_match=(me.intent == "game_friend" and
                            me.game_name == p.game_name),
                rank_match=(me.intent == "game_friend" and
                            me.game_rank == p.game_rank))

        candidates.sort(key=score, reverse=True)
        return candidates[0]

    @classmethod
    async def swipe(cls, s: AsyncSession, from_id: int, to_id: int, kind: str) -> tuple[bool, str]:
        """Record a swipe atomically. Returns (matched, status).

        Race-condition safety: the uq_like_pair unique constraint rejects
        duplicate swipes; the reciprocal check + canonical match row are done
        inside the same transaction so simultaneous likes can't double-create.
        """
        if from_id == to_id:
            return False, "self"
        if kind not in ("like", "superlike", "pass"):
            return False, "bad_kind"
        existing = (await s.execute(select(Like).where(
            Like.from_user == from_id, Like.to_user == to_id))).scalar_one_or_none()
        if existing is not None:
            return False, "duplicate"
        s.add(Like(from_user=from_id, to_user=to_id, kind=kind))
        try:
            await s.flush()
        except IntegrityError:      # concurrent duplicate → treat as duplicate
            await s.rollback()
            return False, "duplicate"
        if kind == "pass":
            return False, "passed"
        reciprocal = (await s.execute(select(Like).where(
            Like.from_user == to_id, Like.to_user == from_id,
            Like.kind.in_(("like", "superlike"))))).scalar_one_or_none()
        if reciprocal is None:
            return False, "liked"
        a, b = cls._canonical(from_id, to_id)
        match = (await s.execute(select(Match).where(
            Match.user_a == a, Match.user_b == b))).scalar_one_or_none()
        if match is None:
            s.add(Match(user_a=a, user_b=b, is_active=True))
            try:
                await s.flush()
            except IntegrityError:  # the other transaction created it first
                await s.rollback()
                return True, "matched"
        elif not match.is_active:
            match.is_active = True
            match.ended_at = None
        return True, "matched"

    @staticmethod
    async def get_match(s: AsyncSession, match_id: int, user_id: int) -> Optional[Match]:
        """Return an active match only if `user_id` is a participant."""
        m = await s.get(Match, match_id)
        if m and m.is_active and user_id in (m.user_a, m.user_b):
            return m
        return None

    @staticmethod
    def peer_of(m: Match, user_id: int) -> int:
        return m.user_b if m.user_a == user_id else m.user_a

    @classmethod
    async def unmatch(cls, s: AsyncSession, match_id: int, user_id: int) -> bool:
        m = await cls.get_match(s, match_id, user_id)
        if not m:
            return False
        m.is_active = False
        m.ended_at = utcnow()
        # Clear any relay sessions pointing at this match
        await s.execute(update(User).where(
            User.id.in_((m.user_a, m.user_b)), User.active_match_id == m.id
        ).values(active_match_id=None))
        await s.flush()
        return True


class UsageService:
    """Daily like / super-like counters keyed by the configured local date."""

    @staticmethod
    async def _row(s: AsyncSession, user_id: int) -> DailyUsage:
        day = today_local()
        row = (await s.execute(select(DailyUsage).where(
            DailyUsage.user_id == user_id, DailyUsage.day == day))).scalar_one_or_none()
        if row is None:
            row = DailyUsage(user_id=user_id, day=day)
            s.add(row)
            try:
                await s.flush()
            except IntegrityError:
                await s.rollback()
                row = (await s.execute(select(DailyUsage).where(
                    DailyUsage.user_id == user_id, DailyUsage.day == day))).scalar_one()
        return row

    @classmethod
    async def try_consume(cls, s: AsyncSession, user_id: int, premium: bool,
                          field: str = "likes_used") -> tuple[bool, int]:
        """Atomically consume one unit. Returns (allowed, limit)."""
        limit = (settings.premium_daily_likes if premium else settings.free_daily_likes)
        if field == "super_likes_used":
            limit = (settings.premium_daily_super_likes if premium
                     else settings.free_daily_super_likes)
        row = await cls._row(s, user_id)
        used = getattr(row, field)
        if used >= limit:
            return False, limit
        setattr(row, field, used + 1)
        await s.flush()
        return True, limit

    @classmethod
    async def try_recommendation(cls, s: AsyncSession, user_id: int,
                                 premium: bool) -> tuple[bool, int]:
        """Consume one daily recommendation slot; premium has no practical cap."""
        row = await cls._row(s, user_id)
        limit = 10_000 if premium else settings.daily_recommendation_limit
        if row.recommendations_used >= limit:
            return False, settings.daily_recommendation_limit
        row.recommendations_used += 1
        await s.flush()
        return True, limit


class PremiumService:
    """Subscriptions and idempotent payment recording."""

    @staticmethod
    async def is_premium(s: AsyncSession, user_id: int) -> bool:
        q = select(Subscription).where(
            Subscription.user_id == user_id, Subscription.status == "active",
            Subscription.expires_at > utcnow())
        return (await s.execute(q)).scalar_one_or_none() is not None

    @staticmethod
    async def activate(s: AsyncSession, user_id: int, days: int,
                       plan: str = "premium") -> Subscription:
        """Extend an active subscription or create a new one (transactional)."""
        q = select(Subscription).where(
            Subscription.user_id == user_id, Subscription.status == "active",
            Subscription.expires_at > utcnow())
        sub = (await s.execute(q)).scalar_one_or_none()
        if sub:
            sub.expires_at = sub.expires_at + timedelta(days=days)
        else:
            sub = Subscription(user_id=user_id, plan=plan, status="active",
                               expires_at=utcnow() + timedelta(days=days))
            s.add(sub)
        await s.flush()
        return sub

    @classmethod
    async def grant_welcome_trial(cls, s: AsyncSession, user_id: int) -> Subscription | None:
        """Give exactly one free first-month trial per account, idempotently."""
        user = await s.get(User, user_id)
        if user is None or user.welcome_trial_used:
            return None
        has_subscription = (await s.execute(select(Subscription.id).where(
            Subscription.user_id == user_id))).scalar_one_or_none()
        if has_subscription is not None:
            user.welcome_trial_used = True
            return None
        user.welcome_trial_used = True
        return await cls.activate(s, user_id, settings.welcome_trial_days,
                                  plan="welcome_trial")

    @staticmethod
    async def record_payment(s: AsyncSession, user_id: int, charge_id: str,
                             provider_charge_id: str, amount: int, payload: str) -> bool:
        """Idempotent payment recording. Returns False if already processed."""
        if (await s.execute(select(Payment).where(
                Payment.telegram_charge_id == charge_id))).scalar_one_or_none():
            return False
        s.add(Payment(user_id=user_id, telegram_charge_id=charge_id,
                      provider_charge_id=provider_charge_id, amount=amount,
                      payload=payload, status="succeeded"))
        try:
            await s.flush()
        except IntegrityError:
            await s.rollback()
            return False
        return True


REPORT_CATEGORIES = ("spam", "inappropriate", "harassment", "fake", "underage", "other")


class ModerationService:
    """Blocks, reports, appeals and the admin audit trail."""

    @staticmethod
    async def block(s: AsyncSession, blocker: int, blocked: int) -> bool:
        if blocker == blocked:
            return False
        if (await s.execute(select(Block).where(
                Block.blocker == blocker, Block.blocked == blocked))).scalar_one_or_none():
            return False
        s.add(Block(blocker=blocker, blocked=blocked))
        # Auto-unmatch in both directions of contact
        a, b = MatchService._canonical(blocker, blocked)
        m = (await s.execute(select(Match).where(
            Match.user_a == a, Match.user_b == b, Match.is_active))).scalar_one_or_none()
        if m:
            m.is_active = False
            m.ended_at = utcnow()
            await s.execute(update(User).where(
                User.id.in_((a, b)), User.active_match_id == m.id).values(active_match_id=None))
        try:
            await s.flush()
        except IntegrityError:
            await s.rollback()
            return False
        return True

    @staticmethod
    async def is_blocked_either_way(s: AsyncSession, a: int, b: int) -> bool:
        """True if a block exists in either direction between two users."""
        row = (await s.execute(select(Block).where(or_(
            and_(Block.blocker == a, Block.blocked == b),
            and_(Block.blocker == b, Block.blocked == a))))).scalar_one_or_none()
        return row is not None

    @staticmethod
    async def report(s: AsyncSession, reporter: int, reported: int,
                     category: str, details: str = "") -> tuple[bool, str]:
        allowed = await rate_limiter.hit(
            f"report:{reporter}", settings.report_rate_limit_per_day, 86400)
        if not allowed:
            return False, "rate_limited"
        if category not in REPORT_CATEGORIES:
            return False, "bad_category"
        s.add(Report(reporter=reporter, reported=reported, category=category,
                     details=details[:500]))
        try:
            await s.flush()
        except IntegrityError:   # duplicate report (same category) → idempotent OK
            await s.rollback()
            return False, "duplicate"
        return True, "ok"

    @staticmethod
    async def audit(s: AsyncSession, admin: str, action: str,
                    target: str = "", detail: str = "") -> None:
        s.add(AuditLog(admin=admin[:64], action=action[:64],
                       target=target[:64], detail=detail[:255]))
        await s.flush()


async def send_card(bot: Bot, chat_id: int, profile: Profile, lang: str,
                    reply_markup: InlineKeyboardMarkup | None = None) -> None:
    """Render a polished profile card and all available photos.

    Telegram only accepts inline keyboards on a single message, so the first
    photo carries the caption and actions; remaining photos are sent directly
    after it. This keeps swipe buttons usable while showing the full profile.
    """
    interests = "  ·  ".join(
        interest_label(i.interest_key, lang) for i in profile.interests
    ) or t(lang, "profile_no_interests")
    game_info = ""
    if profile.intent == "game_friend" and profile.game_name:
        game_info = "\n\n" + t(
            lang, "game_details",
            game=escape(game_option_label("name", profile.game_name, lang)),
            rank=escape(game_rank_label(profile.game_name, profile.game_rank, lang)),
        )
    bio = escape((profile.bio or "").strip()) or t(lang, "profile_no_bio")
    caption = t(lang, "profile_card", name=escape(profile.display_name), age=profile.age,
                city=escape(profile.city),
                gender=escape(t(lang, "profile_gender",
                                gender=gender_label(profile.gender, lang))),
                intent=escape(intent_label(profile.intent, lang)),
                game_info=game_info, bio=bio, interests=interests)
    photos = sorted(profile.photos, key=lambda p: p.position)
    try:
        if photos:
            await bot.send_photo(chat_id, photos[0].file_id, caption=caption,
                                 parse_mode=ParseMode.HTML, reply_markup=reply_markup)
            for photo in photos[1:]:
                await bot.send_photo(chat_id, photo.file_id)
        else:
            await bot.send_message(chat_id, caption, parse_mode=ParseMode.HTML,
                                   reply_markup=reply_markup)
    except TelegramAPIError as exc:
        log.warning("Card delivery failed for %s: %s", safe_id(chat_id), type(exc).__name__)

# ===========================================================================
# SECTION 10 — BOT SETUP, KEYBOARDS, VALIDATION, SHARED HELPERS
# ===========================================================================
bot = Bot(token=settings.bot_token or "0:placeholder",
          default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())   # swapped for Redis in main() if configured
router = Router()
dp.include_router(router)

CB_V1 = "v1"   # callback protocol version — guards against stale buttons
MAX_PHOTOS = 3


class Reg(StatesGroup):
    name = State(); age = State(); gender = State(); pref_gender = State(); intent = State()
    game_name = State(); game_rank = State()
    city = State(); bio = State(); photos = State(); interests = State()
    age_range = State(); pref_city = State(); consent = State()


class EditState(StatesGroup):
    name = State(); city = State(); bio = State(); photos = State(); intent = State()
    game_name = State(); game_rank = State()
    interests = State(); age_range = State()


class AppealState(StatesGroup):
    text = State()


BOT_COMMANDS: list[BotCommand] = [
    BotCommand(command="start", description="Start / register"),
    BotCommand(command="discover", description="Discover profiles"),
    BotCommand(command="recommend", description="Daily recommendations"),
    BotCommand(command="invite", description="Invite friends"),
    BotCommand(command="likes", description="Who liked you"),
    BotCommand(command="matches", description="Your matches"),
    BotCommand(command="profile", description="View your profile"),
    BotCommand(command="edit", description="Edit your profile"),
    BotCommand(command="premium", description="Premium plan"),
    BotCommand(command="subscription", description="Subscription status"),
    BotCommand(command="purchases", description="Payment history"),
    BotCommand(command="settings", description="Settings"),
    BotCommand(command="language", description="Change language"),
    BotCommand(command="safety", description="Safety tips"),
    BotCommand(command="report", description="How to report a user"),
    BotCommand(command="stopchat", description="End the current chat"),
    BotCommand(command="appeal", description="Appeal a suspension"),
    BotCommand(command="delete", description="Delete your account"),
    BotCommand(command="help", description="Help & commands"),
]


async def set_bot_commands() -> None:
    """Publish the command list to Telegram (best-effort)."""
    with suppress(TelegramAPIError):
        await bot.set_my_commands(BOT_COMMANDS)


# --- Language / session helpers ---------------------------------------------

async def get_lang(s: AsyncSession, user_id: int) -> str:
    u = await s.get(User, user_id)
    return u.language if u and u.language in SUPPORTED_LANGS else LANG_EN


async def get_lang_async(user_id: int) -> str:
    async with SessionFactory() as s:
        return await get_lang(s, user_id)


async def load_user(s: AsyncSession, tg_user: TgUser) -> tuple[User | None, bool]:
    """Return (user, blocked). Creates the row on first contact."""
    user = await UserService.get_or_create(s, tg_user)
    blocked = await UserService.is_blocked(s, user)
    await s.commit()
    return user, blocked


async def _registered_user(s: AsyncSession, tg_id: int) -> tuple[User | None, str]:
    """Return (user, lang) for registered users; (None, lang) otherwise."""
    user = await s.get(User, tg_id)
    lang = user.language if user else LANG_EN
    if user is None or not user.is_registered:
        return None, lang
    return user, lang


# --- Keyboards ---------------------------------------------------------------

def language_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="English 🇬🇧", callback_data=f"{CB_V1}:lang:en"),
        InlineKeyboardButton(text="မြန်မာ 🇲🇲", callback_data=f"{CB_V1}:lang:my")]])


def main_menu_kb(lang: str) -> ReplyKeyboardMarkup:
    def row(*keys: str) -> list[KeyboardButton]:
        return [KeyboardButton(text=t(lang, k)) for k in keys]
    return ReplyKeyboardMarkup(keyboard=[
        row("menu_discover", "menu_daily", "menu_likes"),
        row("menu_matches", "menu_profile"),
        row("menu_premium", "menu_settings"),
        row("menu_safety", "menu_help"),
    ], resize_keyboard=True)


def cancel_kb(lang: str) -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=t(lang, "cancel"))]], resize_keyboard=True)


def yes_no_kb(lang: str, prefix: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t(lang, "yes"), callback_data=f"{CB_V1}:{prefix}:yes"),
        InlineKeyboardButton(text=t(lang, "no"), callback_data=f"{CB_V1}:{prefix}:no"),
    ], [InlineKeyboardButton(text=t(lang, "cancel"), callback_data=f"{CB_V1}:{prefix}:cancel")]])


def gender_kb(lang: str, prefix: str, with_everyone: bool = False) -> InlineKeyboardMarkup:
    rows = [[
        InlineKeyboardButton(text=t(lang, "gender_male"), callback_data=f"{CB_V1}:{prefix}:male"),
        InlineKeyboardButton(text=t(lang, "gender_female"), callback_data=f"{CB_V1}:{prefix}:female"),
        InlineKeyboardButton(text=t(lang, "gender_other"), callback_data=f"{CB_V1}:{prefix}:other"),
    ]]
    if with_everyone:
        rows.append([InlineKeyboardButton(
            text=t(lang, "pref_everyone"), callback_data=f"{CB_V1}:{prefix}:everyone")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def intent_kb(lang: str, prefix: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=(my if lang == LANG_MY else en),
                             callback_data=f"{CB_V1}:{prefix}:{key}")]
        for key, en, my in INTENTS])


def game_choice_kb(kind: str, lang: str, prefix: str, game_key: str | None = None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    options = GAME_RANKS.get(game_key or "other", ()) if kind == "rank" else GAME_OPTIONS[kind]
    for key, en, my in options:
        row.append(InlineKeyboardButton(
            text=(my if lang == LANG_MY else en),
            callback_data=f"{CB_V1}:{prefix}:{key}"))
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return InlineKeyboardMarkup(inline_keyboard=rows)


def icebreaker_kb(lang: str, match_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t(lang, "icebreaker"),
                             callback_data=f"{CB_V1}:ice:{match_id}:0")]])


def interests_kb(lang: str, selected: set[str], prefix: str) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for key, en, my in INTERESTS:
        label = my if lang == LANG_MY else en
        mark = "✅ " if key in selected else ""
        row.append(InlineKeyboardButton(
            text=mark + label, callback_data=f"{CB_V1}:{prefix}:{key}"))
        if len(row) == 3:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton(
        text=t(lang, "photos_done"), callback_data=f"{CB_V1}:{prefix}:done")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def swipe_kb(lang: str, target_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t(lang, "btn_like"), callback_data=f"{CB_V1}:swipe:like:{target_id}"),
         InlineKeyboardButton(text=t(lang, "btn_superlike"), callback_data=f"{CB_V1}:swipe:super:{target_id}"),
         InlineKeyboardButton(text=t(lang, "btn_pass"), callback_data=f"{CB_V1}:swipe:pass:{target_id}")],
        [InlineKeyboardButton(text=t(lang, "btn_report"), callback_data=f"{CB_V1}:report:{target_id}"),
         InlineKeyboardButton(text=t(lang, "btn_block"), callback_data=f"{CB_V1}:block:{target_id}")],
    ])


EDIT_MENU_FIELDS: tuple[tuple[str, str], ...] = (
    ("name", "✏️ Name"), ("city", "📍 City"), ("bio", "📝 Bio"),
    ("photos", "📷 Photos"), ("interests", "🏷️ Interests"),
    ("intent", "🎯 Connection type"), ("game_details", "🎮 Game details"),
    ("age_range", "🎂 Age range"),
)


def edit_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=label, callback_data=f"{CB_V1}:edit:{field}")]
        for field, label in EDIT_MENU_FIELDS])


def confirm_kb(lang: str, yes_callback: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t(lang, "yes"), callback_data=yes_callback),
        InlineKeyboardButton(text=t(lang, "no"), callback_data=f"{CB_V1}:noop")]])


def parse_cb(data: str, expect: str) -> list[str] | None:
    """Authorize + validate a callback: versioned protocol, exact action match."""
    parts = (data or "").split(":")
    if len(parts) >= 2 and parts[0] == CB_V1 and parts[1] == expect:
        return parts[2:]
    return None


# --- Input validation ---------------------------------------------------------
# Myanmar Unicode blocks: Myanmar, Extended-A, Extended-B (proper ranges).
_MYANMAR_RANGES: tuple[tuple[int, int], ...] = (
    (0x1000, 0x109F),
    (0xAA60, 0xAA7F),
    (0xA9E0, 0xA9FF),
)
_ASCII_NAME_CHARS = frozenset(string.ascii_letters + string.digits + " _-'")


def valid_name(name: str) -> bool:
    """Display names: 2–40 chars of ASCII letters/digits or Myanmar script."""
    name = name.strip()
    if not 2 <= len(name) <= 40:
        return False
    for c in name:
        if c in _ASCII_NAME_CHARS or c.isspace():
            continue
        if any(lo <= ord(c) <= hi for lo, hi in _MYANMAR_RANGES):
            continue
        return False
    return True


def valid_age(value: str) -> Optional[int]:
    """Validate an age against the configured service range.
    Returns the age, -1 for under-age (sentinel), or None for invalid input."""
    try:
        age = int(value.strip())
    except (ValueError, AttributeError):
        return None
    if age < settings.min_age:
        return -1        # under-age sentinel
    if age > settings.max_age:
        return None
    return age


def valid_age_range(value: str) -> Optional[tuple[int, int]]:
    try:
        lo_s, hi_s = value.strip().split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
    except (ValueError, AttributeError):
        return None
    if settings.min_age <= lo <= hi <= settings.max_age:
        return lo, hi
    return None


def is_cancel(text_: str | None) -> bool:
    return text_ in (t(LANG_EN, "cancel"), t(LANG_MY, "cancel"), "/cancel")


async def verify_telegram_photo(file_id: str) -> bool:
    """Best-effort photo validation: size cap + Pillow decode check.
    Transient download errors do NOT reject the photo (availability first)."""
    try:
        file = await bot.get_file(file_id)
        if file.file_size and file.file_size > 10 * 1024 * 1024:
            return False
        buf = await bot.download_file(file.file_path)
        if buf is not None:
            Image.open(buf).verify()
        return True
    except Exception as exc:
        log.debug("Photo validation soft-pass: %s", type(exc).__name__)
        return True


async def cancel_flow(message: Message, state: FSMContext) -> None:
    await state.clear()
    lang = await get_lang_async(message.from_user.id)
    await message.answer(t(lang, "cancelled"), reply_markup=main_menu_kb(lang))


# --- Anti-flood middleware + global error handler ------------------------------

class AntiFloodMiddleware(BaseMiddleware):
    """Drops updates from users who exceed the flood threshold (spam control).
    Uses the shared rate limiter (Redis-backed in production)."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user: TgUser | None = data.get("event_from_user")
        if user is not None and not user.is_bot:
            allowed = await rate_limiter.hit(
                f"flood:{user.id}",
                settings.flood_limit_messages,
                settings.flood_window_seconds)
            if not allowed:
                return None                      # silently drop floods
        return await handler(event, data)


router.message.middleware(AntiFloodMiddleware())
router.callback_query.middleware(AntiFloodMiddleware())


@router.error()
async def on_unhandled_error(event: ErrorEvent) -> bool:
    """Last-resort error handler: log with context, never crash the bot."""
    update_id = event.update.update_id if event.update else "?"
    log.exception("Unhandled error while processing update %s: %s",
                  update_id, type(event.exception).__name__)
    return True

# ===========================================================================
# SECTION 11 — TELEGRAM HANDLERS: commands, menu, registration
# ===========================================================================

async def send_language_picker(message: Message, user_id: int) -> None:
    lang = await get_lang_async(user_id)
    await message.answer(t(lang, "language_choose"), reply_markup=language_kb())


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    await cancel_flow(message, state)


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    async with SessionFactory() as s:
        user, blocked = await load_user(s, message.from_user)
        lang = user.language
        if blocked:
            await message.answer(t(lang, "banned"))
            return
        start_arg = (message.text or "").split(maxsplit=1)
        if not user.is_registered and len(start_arg) == 2 and start_arg[1].startswith("ref_"):
            code = start_arg[1][4:][:16]
            inviter = (await s.execute(select(User).where(
                User.referral_code == code,
                User.id != user.id,
                User.is_registered.is_(True),
                User.is_active.is_(True),
                User.is_banned.is_(False),
                User.deleted_at.is_(None)))).scalar_one_or_none()
            if inviter is not None:
                user.referred_by = inviter.id
                await s.commit()
        existing_trial = None
        if user.is_registered:
            existing_trial = await PremiumService.grant_welcome_trial(s, user.id)
            await s.commit()
            await message.answer(t(lang, "choose_option"), reply_markup=main_menu_kb(lang))
            if existing_trial is not None:
                until = existing_trial.expires_at.astimezone(settings.tz).strftime("%Y-%m-%d")
                await message.answer(t(lang, "trial_active", until=until))
            return
    await message.answer(t(lang, "welcome"))
    await message.answer(t(lang, "language_choose"), reply_markup=language_kb())


@router.callback_query(F.data.startswith(f"{CB_V1}:lang:"))
async def cb_language(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "lang")
    if not args or args[0] not in SUPPORTED_LANGS:
        await cb.answer("Unknown action.", show_alert=False)
        return
    lang = args[0]
    async with SessionFactory() as s:
        user, blocked = await load_user(s, cb.from_user)
        user.language = lang
        registered = user.is_registered
        await s.commit()
    await cb.answer(t(lang, "language_saved"))
    if registered:
        await cb.message.answer(t(lang, "choose_option"), reply_markup=main_menu_kb(lang))
    else:
        await state.set_state(Reg.name)
        await cb.message.answer(t(lang, "ask_name"), reply_markup=cancel_kb(lang))


@router.message(Command("language"))
async def cmd_language(message: Message) -> None:
    await send_language_picker(message, message.from_user.id)


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    lang = await get_lang_async(message.from_user.id)
    await message.answer(t(lang, "help_text"), reply_markup=main_menu_kb(lang))


@router.message(Command("invite"))
async def cmd_invite(message: Message) -> None:
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        if not user.referral_code:
            user.referral_code = secrets.token_urlsafe(8)[:12]
            await s.commit()
        code = user.referral_code
    try:
        me = await bot.get_me()
        bot_name = me.username or "VibeMateBot"
    except TelegramAPIError:
        bot_name = "VibeMateBot"
    link = f"https://t.me/{bot_name}?start=ref_{code}"
    await message.answer(t(lang, "invite_text", link=link))


@router.message(Command("safety"))
async def cmd_safety(message: Message) -> None:
    lang = await get_lang_async(message.from_user.id)
    await message.answer(t(lang, "safety_text"))


@router.message(Command("report"))
async def cmd_report(message: Message) -> None:
    lang = await get_lang_async(message.from_user.id)
    await message.answer(t(lang, "report_hint"))


# --- Registration FSM -------------------------------------------------------

@router.message(Reg.name)
async def reg_name(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    name = (message.text or "").strip()
    if not valid_name(name):
        await message.answer(t(lang, "name_invalid"))
        return
    await state.update_data(name=name)
    await state.set_state(Reg.age)
    await message.answer(t(lang, "ask_age"))


@router.message(Reg.age)
async def reg_age(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    age = valid_age(message.text or "")
    if age == -1:
        await state.clear()
        await message.answer(t(lang, "age_under18"), reply_markup=ReplyKeyboardRemove())
        return
    if age is None:
        await message.answer(t(lang, "age_invalid"))
        return
    await state.update_data(age=age)
    await state.set_state(Reg.gender)
    await message.answer(t(lang, "age_notice"))
    await message.answer(t(lang, "ask_gender"), reply_markup=gender_kb(lang, "reg_g"))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_g:"), StateFilter(Reg.gender))
async def reg_gender(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_g")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in ("male", "female", "other"):
        await cb.answer()
        return
    await state.update_data(gender=args[0])
    await state.set_state(Reg.pref_gender)
    await cb.answer()
    await cb.message.answer(t(lang, "ask_pref_gender"),
                            reply_markup=gender_kb(lang, "reg_pg", with_everyone=True))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_pg:"), StateFilter(Reg.pref_gender))
async def reg_pref_gender(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_pg")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in ("male", "female", "other", "everyone"):
        await cb.answer()
        return
    await state.update_data(pref_gender=args[0])
    await state.set_state(Reg.intent)
    await cb.answer()
    await cb.message.answer(t(lang, "ask_intent"),
                            reply_markup=intent_kb(lang, "reg_intent"))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_intent:"), StateFilter(Reg.intent))
async def reg_intent(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_intent")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in INTENT_KEYS:
        await cb.answer()
        return
    await state.update_data(intent=args[0])
    await cb.answer()
    if args[0] == "game_friend":
        await state.set_state(Reg.game_name)
        await cb.message.answer(t(lang, "ask_game_name"),
                                reply_markup=game_choice_kb("name", lang, "reg_game"))
    else:
        await state.set_state(Reg.city)
        await cb.message.answer(t(lang, "ask_city"))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_game:"), StateFilter(Reg.game_name))
async def reg_game_name(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_game")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in GAME_OPTION_KEYS["name"]:
        await cb.answer()
        return
    await state.update_data(game_name=args[0])
    await state.set_state(Reg.game_rank)
    await cb.answer()
    await cb.message.answer(t(lang, "ask_game_rank"),
                            reply_markup=game_choice_kb("rank", lang, "reg_rank", args[0]))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_rank:"), StateFilter(Reg.game_rank))
async def reg_game_rank(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_rank")
    lang = await get_lang_async(cb.from_user.id)
    data = await state.get_data()
    game_name = data.get("game_name", "other")
    if args[0] not in GAME_RANK_KEYS.get(game_name, GAME_RANK_KEYS["other"]):
        await cb.answer()
        return
    await state.update_data(game_rank=args[0])
    await state.set_state(Reg.city)
    await cb.answer()
    await cb.message.answer(t(lang, "ask_city"))


@router.message(Reg.city)
async def reg_city(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    city = (message.text or "").strip()[:80]
    if len(city) < 2:
        await message.answer(t(lang, "ask_city"))
        return
    await state.update_data(city=city)
    await state.set_state(Reg.bio)
    await message.answer(t(lang, "ask_bio"))


@router.message(Reg.bio)
async def reg_bio(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    bio = (message.text or "").strip()[:300]
    if len(bio) < 20:
        await message.answer(t(lang, "bio_invalid"))
        return
    await state.update_data(bio=bio, photos=[])
    await state.set_state(Reg.photos)
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t(lang, "photos_done"),
                             callback_data=f"{CB_V1}:photos:done")]])
    await message.answer(t(lang, "ask_photo"), reply_markup=kb)


@router.message(Reg.photos, F.photo)
async def reg_photo_add(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    data = await state.get_data()
    photos: list[str] = list(data.get("photos", []))
    if len(photos) >= MAX_PHOTOS:
        await message.answer(t(lang, "photo_max"))
        return
    file_id = message.photo[-1].file_id          # largest size
    if not await verify_telegram_photo(file_id):
        await message.answer(t(lang, "error_generic"))
        return
    photos.append(file_id)
    await state.update_data(photos=photos)
    await message.answer(t(lang, "photo_added", n=len(photos)))


@router.callback_query(F.data == f"{CB_V1}:photos:done", StateFilter(Reg.photos))
async def reg_photos_done(cb: CallbackQuery, state: FSMContext) -> None:
    lang = await get_lang_async(cb.from_user.id)
    data = await state.get_data()
    if not data.get("photos"):
        await cb.answer(t(lang, "ask_photo"), show_alert=True)
        return
    await state.update_data(interests=[])
    await state.set_state(Reg.interests)
    await cb.answer()
    await cb.message.answer(t(lang, "ask_interests"),
                            reply_markup=interests_kb(lang, set(), "reg_i"))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_i:"), StateFilter(Reg.interests))
async def reg_interests(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_i")
    lang = await get_lang_async(cb.from_user.id)
    if not args:
        await cb.answer()
        return
    data = await state.get_data()
    selected = set(data.get("interests", []))
    if args[0] == "done":
        await state.update_data(interests=sorted(selected))
        await state.set_state(Reg.age_range)
        await cb.answer()
        await cb.message.answer(t(lang, "ask_age_range"))
        return
    key = args[0]
    if key not in INTEREST_KEYS:
        await cb.answer()
        return
    selected ^= {key}                            # toggle
    await state.update_data(interests=sorted(selected))
    await cb.answer()
    with suppress(TelegramBadRequest):           # markup unchanged edge case
        await cb.message.edit_reply_markup(
            reply_markup=interests_kb(lang, selected, "reg_i"))


@router.message(Reg.age_range)
async def reg_age_range(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    parsed = valid_age_range(message.text or "")
    if parsed is None:
        await message.answer(t(lang, "age_range_invalid"))
        return
    await state.update_data(min_age=parsed[0], max_age=parsed[1])
    await state.set_state(Reg.pref_city)
    await message.answer(t(lang, "ask_pref_city"),
                         reply_markup=yes_no_kb(lang, "reg_pc"))


@router.callback_query(F.data.startswith(f"{CB_V1}:reg_pc:"), StateFilter(Reg.pref_city))
async def reg_pref_city(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "reg_pc")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in ("yes", "no"):
        await cb.answer()
        return
    await state.update_data(same_city=(args[0] == "yes"))
    await state.set_state(Reg.consent)
    await cb.answer()
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t(lang, "consent_accept"), callback_data=f"{CB_V1}:consent:yes"),
        InlineKeyboardButton(text=t(lang, "no"), callback_data=f"{CB_V1}:consent:no")]])
    await cb.message.answer(t(lang, "consent_text"), reply_markup=kb)


@router.callback_query(F.data.startswith(f"{CB_V1}:consent:"), StateFilter(Reg.consent))
async def reg_consent(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "consent")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in ("yes", "no"):
        await cb.answer()
        return
    await cb.answer()
    if args[0] == "no":
        await state.clear()
        await cb.message.answer(t(lang, "consent_declined"),
                                reply_markup=ReplyKeyboardRemove())
        return
    data = await state.get_data()
    uid = cb.from_user.id
    async with SessionFactory() as s:
        user = await s.get(User, uid)
        if user is None:
            await cb.message.answer(t(lang, "error_generic"))
            return
        # Re-registration replaces the old profile cleanly.
        old = await ProfileService.get_with_relations(s, uid)
        if old is not None:
            await s.delete(old)
        profile = Profile(user_id=uid, display_name=data["name"], age=data["age"],
                          gender=data["gender"],
                          intent=data.get("intent", "just_friend"),
                          game_name=data.get("game_name", ""),
                          game_rank=data.get("game_rank", ""),
                          bio=data.get("bio", ""),
                          city=data["city"])
        s.add(profile)
        await s.flush()
        for i, fid in enumerate(data.get("photos", [])[:MAX_PHOTOS]):
            s.add(ProfilePhoto(profile_id=profile.id, file_id=fid, position=i))
        s.add(MatchPreference(profile_id=profile.id,
                              preferred_gender=data["pref_gender"],
                              min_age=data["min_age"], max_age=data["max_age"],
                              same_city_only=bool(data.get("same_city"))))
        for k in data.get("interests", []):
            if k in INTEREST_KEYS:
                s.add(UserInterest(profile_id=profile.id, interest_key=k))
        s.add(Consent(user_id=uid, kind="profile_publication", granted=True))
        trial = await PremiumService.grant_welcome_trial(s, uid)
        referral_rewarded = False
        if user.referred_by and not user.referral_rewarded and user.referred_by != uid:
            inviter = await s.get(User, user.referred_by)
            if inviter is not None and inviter.is_active and not inviter.is_banned:
                await PremiumService.activate(s, inviter.id, settings.referral_reward_days,
                                              plan="referral_reward")
                await PremiumService.activate(s, uid, settings.referral_reward_days,
                                              plan="referral_reward")
                user.referral_rewarded = True
                referral_rewarded = True
        user.is_registered = True
        user.is_active = True
        user.consented_at = utcnow()
        await s.commit()
    await state.clear()
    await cb.message.answer(t(lang, "registration_done"),
                            reply_markup=main_menu_kb(lang))
    if trial is not None:
        until = trial.expires_at.astimezone(settings.tz).strftime("%Y-%m-%d")
        await cb.message.answer(t(lang, "trial_active", until=until))
    if referral_rewarded:
        await cb.message.answer(t(lang, "referral_reward"))


# --- Main-menu text dispatcher (registered after state handlers) ------------
_MENU_KEYS = ("menu_discover", "menu_daily", "menu_likes", "menu_matches", "menu_profile",
              "menu_premium", "menu_settings", "menu_safety", "menu_help")

MENU_TEXTS: frozenset[str] = frozenset(
    label for key in _MENU_KEYS for label in (t(LANG_EN, key), t(LANG_MY, key)))


def _is_menu_label(text: str | None) -> bool:
    """True when `text` is one of the main-menu button labels."""
    return bool(text) and text in MENU_TEXTS


def extract_command(text_: str | None) -> str:
    """Normalize /command and /command@BotName to a lowercase command name."""
    parts = (text_ or "").split(maxsplit=1)
    if not parts:
        return ""
    raw = parts[0]
    if not raw.startswith("/"):
        return ""
    return raw[1:].split("@", 1)[0].lower()


def menu_key_for(text_: str | None) -> str | None:
    if not text_:
        return None
    for k in _MENU_KEYS:
        if text_ in (t(LANG_EN, k), t(LANG_MY, k)):
            return k
    return None


@router.message(F.text.func(menu_key_for))
async def menu_dispatch(message: Message, state: FSMContext) -> None:
    if await state.get_state() is not None:
        return                                      # don't hijack FSM input
    key = menu_key_for(message.text)
    dispatch = {
        "menu_discover": cmd_discover, "menu_daily": cmd_recommend, "menu_likes": cmd_likes,
        "menu_matches": cmd_matches, "menu_profile": cmd_profile,
        "menu_premium": cmd_premium, "menu_settings": cmd_settings,
        "menu_safety": cmd_safety, "menu_help": cmd_help,
    }
    handler = dispatch.get(key) if key else None
    if handler:
        await handler(message)

# ===========================================================================
# SECTION 12 — TELEGRAM HANDLERS: discover, swipe, matches, chat relay
# ===========================================================================

async def show_next_profile(chat_id: int, user_id: int, lang: str) -> None:
    async with SessionFactory() as s:
        user = await s.get(User, user_id)
        if user is None:
            return
        cand = await MatchService.next_candidate(s, user)
        if cand is None:
            await bot.send_message(chat_id, t(lang, "no_profiles"))
            return
        await send_card(bot, chat_id, cand, lang,
                        reply_markup=swipe_kb(lang, cand.user_id))


@router.message(Command("discover"))
async def cmd_discover(message: Message) -> None:
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, message.from_user.id)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        if await UserService.is_blocked(s, user):
            await message.answer(t(lang, "banned"))
            return
    await show_next_profile(message.chat.id, message.from_user.id, lang)


@router.message(Command("recommend"))
async def cmd_recommend(message: Message) -> None:
    """Daily picks: capped for free users, uncapped for active Premium."""
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        if await UserService.is_blocked(s, user):
            await message.answer(t(lang, "banned"))
            return
        premium = await PremiumService.is_premium(s, uid)
        allowed, _limit = await UsageService.try_recommendation(s, uid, premium)
        if not allowed:
            await s.commit()
            await message.answer(t(lang, "recommendation_limit",
                                    n=settings.daily_recommendation_limit))
            return
        cand = await MatchService.next_candidate(s, user)
        await s.commit()
    if cand is None:
        await message.answer(t(lang, "no_profiles"))
        return
    await message.answer(t(lang, "daily_recommendation"))
    await send_card(bot, message.chat.id, cand, lang,
                    reply_markup=swipe_kb(lang, cand.user_id))


@router.callback_query(F.data.startswith(f"{CB_V1}:swipe:"))
async def cb_swipe(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "swipe")
    if not args or len(args) != 2 or args[0] not in ("like", "super", "pass"):
        await cb.answer("Stale or unknown action.", show_alert=False)
        return
    action, target_raw = args
    try:
        target_id = int(target_raw)
    except ValueError:
        await cb.answer()
        return
    uid = cb.from_user.id
    if target_id == uid:                       # never like yourself
        await cb.answer()
        return
    kind = {"like": "like", "super": "superlike", "pass": "pass"}[action]
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None or await UserService.is_blocked(s, user):
            await cb.answer(t(lang, "banned"), show_alert=True)
            return
        target_user = await s.get(User, target_id)
        if target_user is None or not target_user.is_registered or await UserService.is_blocked(s, target_user):
            await cb.answer(t(lang, "chat_peer_gone"), show_alert=True)
            return
        if await ModerationService.is_blocked_either_way(s, uid, target_id):
            await cb.answer(t(lang, "chat_peer_gone"), show_alert=True)
            return
        target_profile = await ProfileService.get_with_relations(s, target_id)
        if target_profile is None or target_profile.age < settings.min_age:
            await cb.answer(t(lang, "chat_peer_gone"), show_alert=True)
            return
        premium = await PremiumService.is_premium(s, uid)
        if kind in ("like", "superlike"):
            field = "super_likes_used" if kind == "superlike" else "likes_used"
            allowed, limit = await UsageService.try_consume(s, uid, premium, field)
            if not allowed:
                await s.commit()
                await cb.answer(t(lang, "daily_limit", n=limit), show_alert=True)
                return
        matched, _status = await MatchService.swipe(s, uid, target_id, kind)
        peer_profile = await ProfileService.get_with_relations(s, target_id)
        my_profile = await ProfileService.get_with_relations(s, uid)
        peer_lang = await get_lang(s, target_id)
        await s.commit()
    await cb.answer()
    if matched and peer_profile and my_profile:
        # Notify BOTH users; never expose Telegram IDs in the payload.
        with suppress(TelegramAPIError):
            await bot.send_message(uid, t(lang, "match_notify",
                                          name=escape(peer_profile.display_name)))
        with suppress(TelegramAPIError):
            await bot.send_message(target_id, t(peer_lang, "match_notify",
                                                name=escape(my_profile.display_name)))
    with suppress(TelegramBadRequest):
        await cb.message.delete()
    await show_next_profile(cb.message.chat.id, uid, lang)


@router.message(Command("likes"))
async def cmd_likes(message: Message) -> None:
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        if not await PremiumService.is_premium(s, uid):
            await message.answer(t(lang, "likes_premium_only"))
            return
        # Incoming likes the user hasn't swiped on yet.
        seen_q = select(Like.to_user).where(Like.from_user == uid)
        q = (select(Like.from_user).where(
                Like.to_user == uid, Like.kind.in_(("like", "superlike")),
                Like.from_user.notin_(seen_q))
             .order_by(Like.created_at.desc()).limit(10))
        likers = list((await s.execute(q)).scalars().all())
        if not likers:
            await message.answer(t(lang, "likes_empty"))
            return
        profile = await ProfileService.get_with_relations(s, likers[0])
    if profile:
        await send_card(bot, message.chat.id, profile, lang,
                        reply_markup=swipe_kb(lang, profile.user_id))
    else:
        await message.answer(t(lang, "likes_empty"))


@router.message(Command("matches"))
async def cmd_matches(message: Message) -> None:
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        q = select(Match).where(
            or_(Match.user_a == uid, Match.user_b == uid), Match.is_active)
        matches = list((await s.execute(q)).scalars().all())
        rows: list[list[InlineKeyboardButton]] = []
        for m in matches[:20]:
            peer_id = MatchService.peer_of(m, uid)
            p = await ProfileService.get_with_relations(s, peer_id)
            if not p:
                continue
            rows.append([
                InlineKeyboardButton(text=f"💬 {p.display_name}",
                                     callback_data=f"{CB_V1}:chat:{m.id}"),
                InlineKeyboardButton(text="💔", callback_data=f"{CB_V1}:unmatch:{m.id}")])
    if not rows:
        await message.answer(t(lang, "matches_empty"))
        return
    await message.answer(t(lang, "menu_matches"),
                         reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))


@router.callback_query(F.data.startswith(f"{CB_V1}:chat:"))
async def cb_chat(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "chat")
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    uid = cb.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        match = await MatchService.get_match(s, int(args[0]), uid)
        if user is None or match is None:
            await cb.answer(t(lang, "chat_peer_gone"), show_alert=True)
            return
        user.active_match_id = match.id
        peer_profile = await ProfileService.get_with_relations(
            s, MatchService.peer_of(match, uid))
        await s.commit()
    await cb.answer()
    await cb.message.answer(
        t(lang, "chat_started",
          name=escape(peer_profile.display_name if peer_profile else "?")),
        reply_markup=icebreaker_kb(lang, match.id))


@router.callback_query(F.data.startswith(f"{CB_V1}:ice:"))
async def cb_icebreaker(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "ice")
    uid = cb.from_user.id
    lang = await get_lang_async(uid)
    if not args or len(args) != 2 or not args[0].isdigit() or not args[1].isdigit():
        await cb.answer()
        return
    match_id, index = int(args[0]), int(args[1])
    if not 0 <= index < len(ICEBREAKERS):
        await cb.answer()
        return
    async with SessionFactory() as s:
        match = await MatchService.get_match(s, match_id, uid)
        if match is None:
            await cb.answer(t(lang, "chat_peer_gone"), show_alert=True)
            return
        peer_id = MatchService.peer_of(match, uid)
        prompt_en, prompt_my = ICEBREAKERS[index]
        prompt = prompt_my if lang == LANG_MY else prompt_en
        s.add(MessageLog(match_id=match_id, from_user=uid, to_user=peer_id,
                         content_type="icebreaker"))
        await s.commit()
    try:
        await bot.send_message(peer_id, prompt)
    except TelegramAPIError:
        await cb.answer(t(lang, "error_generic"), show_alert=True)
        return
    await cb.answer(t(lang, "icebreaker_sent"))


@router.message(Command("stopchat"))
async def cmd_stopchat(message: Message) -> None:
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None or not user.active_match_id:
            await message.answer(t(lang, "chat_not_active"))
            return
        user.active_match_id = None
        await s.commit()
    await message.answer(t(lang, "chat_stopped"))


@router.callback_query(F.data.startswith(f"{CB_V1}:unmatch:"))
async def cb_unmatch(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "unmatch")
    lang = await get_lang_async(cb.from_user.id)
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    await cb.message.answer(t(lang, "confirm_action"),
                            reply_markup=confirm_kb(lang, f"{CB_V1}:unmatchyes:{args[0]}"))
    await cb.answer()


@router.callback_query(F.data.startswith(f"{CB_V1}:unmatchyes:"))
async def cb_unmatch_yes(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "unmatchyes")
    lang = await get_lang_async(cb.from_user.id)
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    async with SessionFactory() as s:
        ok = await MatchService.unmatch(s, int(args[0]), cb.from_user.id)
        await s.commit()
    await cb.answer()
    await cb.message.answer(t(lang, "unmatched" if ok else "chat_peer_gone"))


@router.callback_query(F.data == f"{CB_V1}:noop")
async def cb_noop(cb: CallbackQuery) -> None:
    await cb.answer()


@router.callback_query(F.data.startswith(f"{CB_V1}:block:"))
async def cb_block(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "block")
    lang = await get_lang_async(cb.from_user.id)
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    await cb.message.answer(t(lang, "confirm_action"),
                            reply_markup=confirm_kb(lang, f"{CB_V1}:blockyes:{args[0]}"))
    await cb.answer()


@router.callback_query(F.data.startswith(f"{CB_V1}:blockyes:"))
async def cb_block_yes(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "blockyes")
    lang = await get_lang_async(cb.from_user.id)
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    uid, target = cb.from_user.id, int(args[0])
    async with SessionFactory() as s:
        await ModerationService.block(s, uid, target)
        # If a chat relay was open with the blocked user, close it.
        user = await s.get(User, uid)
        if user and user.active_match_id:
            user.active_match_id = None
        await s.commit()
    await cb.answer()
    await cb.message.answer(t(lang, "blocked"))
    with suppress(TelegramBadRequest):
        await cb.message.delete()


@router.callback_query(F.data.startswith(f"{CB_V1}:report:"))
async def cb_report(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "report")
    lang = await get_lang_async(cb.from_user.id)
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    target = int(args[0])
    async with SessionFactory() as s:
        target_profile = await ProfileService.get_with_relations(s, target)
    display = escape(target_profile.display_name) if target_profile else "—"
    labels = {"spam": "🚫 Spam", "inappropriate": "🔞 Inappropriate",
              "harassment": "😠 Harassment", "fake": "🎭 Fake profile",
              "underage": "🔞 Under 18", "other": "❔ Other"}
    rows = [[InlineKeyboardButton(
        text=labels[c], callback_data=f"{CB_V1}:rcat:{target}:{c}")] for c in REPORT_CATEGORIES]
    # Show the display name, never the raw Telegram ID (privacy).
    await cb.message.answer(t(lang, "report_choose", name=display),
                            reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    await cb.answer()


@router.callback_query(F.data.startswith(f"{CB_V1}:rcat:"))
async def cb_report_category(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "rcat")
    lang = await get_lang_async(cb.from_user.id)
    if not args or len(args) != 2 or not args[0].isdigit() or args[1] not in REPORT_CATEGORIES:
        await cb.answer()
        return
    ok, _why = await _submit_report(cb.from_user.id, int(args[0]), args[1])
    await cb.answer()
    await cb.message.answer(t(lang, "report_sent" if ok else "error_generic"))


async def _submit_report(reporter: int, reported: int, category: str) -> tuple[bool, str]:
    if reporter == reported:
        return False, "self"
    async with SessionFactory() as s:
        result = await ModerationService.report(s, reporter, reported, category)
        await s.commit()
        return result


# --- Telegram owner-only admin panel ---------------------------------------
def is_owner_telegram(user_id: int | None) -> bool:
    return user_id == OWNER_TELEGRAM_ID


def owner_admin_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 Statistics", callback_data=f"{CB_V1}:adm:stats"),
         InlineKeyboardButton(text="🚩 Reports", callback_data=f"{CB_V1}:adm:reports")],
        [InlineKeyboardButton(text="📝 Appeals", callback_data=f"{CB_V1}:adm:appeals"),
         InlineKeyboardButton(text="💾 Backup", callback_data=f"{CB_V1}:adm:backup")],
        [InlineKeyboardButton(text="🔄 Refresh", callback_data=f"{CB_V1}:adm:home")],
    ])


async def _owner_admin_stats() -> str:
    async with SessionFactory() as s:
        total = (await s.execute(select(func.count(User.id)).where(User.deleted_at.is_(None)))).scalar_one()
        active = (await s.execute(select(func.count(User.id)).where(
            User.is_registered.is_(True), User.is_active.is_(True), User.deleted_at.is_(None)))).scalar_one()
        banned = (await s.execute(select(func.count(User.id)).where(User.is_banned.is_(True)))).scalar_one()
        matches = (await s.execute(select(func.count(Match.id)).where(Match.is_active.is_(True)))).scalar_one()
        reports = (await s.execute(select(func.count(Report.id)).where(Report.status == "open"))).scalar_one()
        appeals = (await s.execute(select(func.count(Appeal.id)).where(Appeal.status == "open"))).scalar_one()
        premium = (await s.execute(select(func.count(func.distinct(Subscription.user_id))).where(
            Subscription.status == "active", Subscription.expires_at > utcnow()))).scalar_one()
    return ("🔐 <b>VibeMate Owner Admin</b>\n\n"
            f"👥 Total users: <b>{total}</b>\n✅ Active profiles: <b>{active}</b>\n"
            f"🚫 Banned users: <b>{banned}</b>\n💕 Active matches: <b>{matches}</b>\n"
            f"⭐ Premium users: <b>{premium}</b>\n🚩 Open reports: <b>{reports}</b>\n"
            f"📝 Open appeals: <b>{appeals}</b>")


@router.message(Command("admin"))
async def cmd_admin(message: Message) -> None:
    """Telegram admin entry point; silently ignore every non-owner."""
    if not is_owner_telegram(message.from_user.id if message.from_user else None):
        return
    await message.answer(await _owner_admin_stats(), parse_mode=ParseMode.HTML,
                         reply_markup=owner_admin_kb())


@router.callback_query(F.data.startswith(f"{CB_V1}:adm:"))
async def cb_owner_admin(cb: CallbackQuery) -> None:
    if not is_owner_telegram(cb.from_user.id):
        await cb.answer("Not available.", show_alert=False)
        return
    action = (parse_cb(cb.data, "adm") or [""])[0]
    if action in ("home", "stats"):
        await cb.message.edit_text(await _owner_admin_stats(), parse_mode=ParseMode.HTML,
                                   reply_markup=owner_admin_kb())
    elif action == "reports":
        async with SessionFactory() as s:
            rows = list((await s.execute(select(Report).where(
                Report.status == "open").order_by(Report.created_at.desc()).limit(15))).scalars().all())
        text_ = "🚩 <b>Open reports</b>\n\n" + ("No open reports." if not rows else "\n".join(
            f"#{r.id} · {escape(r.category)} · {r.reporter} → {r.reported}" for r in rows))
        await cb.message.edit_text(text_, parse_mode=ParseMode.HTML, reply_markup=owner_admin_kb())
    elif action == "appeals":
        async with SessionFactory() as s:
            rows = list((await s.execute(select(Appeal).where(
                Appeal.status == "open").order_by(Appeal.created_at.desc()).limit(15))).scalars().all())
        text_ = "📝 <b>Open appeals</b>\n\n" + ("No open appeals." if not rows else "\n".join(
            f"#{a.id} · user {a.user_id} · {escape(a.text[:100])}" for a in rows))
        await cb.message.edit_text(text_, parse_mode=ParseMode.HTML, reply_markup=owner_admin_kb())
    elif action == "backup":
        snapshot = await build_backup()
        content = json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8")
        await cb.message.answer_document(BufferedInputFile(content, filename="vibemate-backup.json"),
                                         caption="✅ Owner-only backup generated.")
    await cb.answer()


# --- Unknown commands ---------------------------------------------------------
KNOWN_COMMANDS = frozenset({
    "start", "cancel", "language", "help", "invite", "safety", "report",
    "discover", "recommend", "likes", "matches", "stopchat", "profile", "edit",
    "settings", "delete", "appeal", "premium", "subscription", "purchases", "admin",
})


def is_unknown_command(text_: str | None) -> bool:
    return bool(text_ and text_.startswith("/") and
                extract_command(text_) not in KNOWN_COMMANDS)


@router.message(StateFilter(None), F.text.startswith("/"))
async def unknown_command(message: Message, state: FSMContext) -> None:
    """Last-resort command router.

    Telegram normally handles these through aiogram's Command filter. This
    fallback also supports /command@BotName and protects deployments where a
    stale router/filter configuration made only reply-keyboard buttons work.
    """
    lang = await get_lang_async(message.from_user.id)
    command = extract_command(message.text)
    handlers = {
        "start": (cmd_start, True), "cancel": (cmd_cancel, True),
        "language": (cmd_language, False), "help": (cmd_help, False),
        "invite": (cmd_invite, False), "safety": (cmd_safety, False),
        "report": (cmd_report, False), "discover": (cmd_discover, False),
        "recommend": (cmd_recommend, False), "likes": (cmd_likes, False),
        "matches": (cmd_matches, False), "stopchat": (cmd_stopchat, False),
        "profile": (cmd_profile, False), "edit": (cmd_edit, False),
        "settings": (cmd_settings, False), "delete": (cmd_delete, False),
        "appeal": (cmd_appeal, True), "premium": (cmd_premium, False),
        "subscription": (cmd_subscription, False), "purchases": (cmd_subscription, False),
        "admin": (cmd_admin, False),
    }
    entry = handlers.get(command)
    if entry:
        handler, needs_state = entry
        if needs_state:
            await handler(message, state)
        else:
            await handler(message)
        return
    await message.answer(t(lang, "unknown_command"))


# ===========================================================================
# SECTION 13 — TELEGRAM HANDLERS: profile, edit, settings, delete, appeal
# ===========================================================================

@router.message(Command("profile"))
async def cmd_profile(message: Message) -> None:
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        profile = await ProfileService.get_with_relations(s, uid)
        premium = await PremiumService.is_premium(s, uid)
    if profile is None:
        await message.answer(t(lang, "welcome"))
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t(lang, "btn_edit"), callback_data=f"{CB_V1}:editmenu")]])
    await send_card(bot, message.chat.id, profile, lang, reply_markup=kb)
    status_line = (t(lang, "premium_on") if premium
                   else t(lang, "premium_free", likes=settings.free_daily_likes))
    percent, items = profile_quality(profile, lang)
    await message.answer(status_line + "\n\n" +
                         t(lang, "profile_quality", percent=percent, items=items))


@router.callback_query(F.data == f"{CB_V1}:editmenu")
async def cb_editmenu(cb: CallbackQuery) -> None:
    lang = await get_lang_async(cb.from_user.id)
    await cb.message.answer(t(lang, "edit_what"), reply_markup=edit_menu_kb())
    await cb.answer()


@router.message(Command("edit"))
async def cmd_edit(message: Message) -> None:
    lang = await get_lang_async(message.from_user.id)
    await message.answer(t(lang, "edit_what"), reply_markup=edit_menu_kb())


@router.callback_query(F.data.startswith(f"{CB_V1}:edit:"))
async def cb_edit_field(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "edit")
    lang = await get_lang_async(cb.from_user.id)
    if not args:
        await cb.answer()
        return
    field = args[0]
    await cb.answer()
    if field == "name":
        await state.set_state(EditState.name)
        await cb.message.answer(t(lang, "ask_name"), reply_markup=cancel_kb(lang))
    elif field == "city":
        await state.set_state(EditState.city)
        await cb.message.answer(t(lang, "ask_city"), reply_markup=cancel_kb(lang))
    elif field == "bio":
        await state.set_state(EditState.bio)
        await cb.message.answer(t(lang, "ask_bio"), reply_markup=cancel_kb(lang))
    elif field == "age_range":
        await state.set_state(EditState.age_range)
        await cb.message.answer(t(lang, "ask_age_range"), reply_markup=cancel_kb(lang))
    elif field == "intent":
        await state.set_state(EditState.intent)
        await cb.message.answer(t(lang, "ask_intent"),
                                reply_markup=intent_kb(lang, "edit_intent"))
    elif field == "game_details":
        await state.set_state(EditState.game_name)
        await cb.message.answer(t(lang, "ask_game_name"),
                                reply_markup=game_choice_kb("name", lang, "edit_game"))
    elif field == "interests":
        async with SessionFactory() as s:
            profile = await ProfileService.get_with_relations(s, cb.from_user.id)
            selected = {i.interest_key for i in profile.interests} if profile else set()
        await state.set_state(EditState.interests)
        await state.update_data(interests=sorted(selected))
        await cb.message.answer(t(lang, "ask_interests"),
                                reply_markup=interests_kb(lang, selected, "edit_i"))
    elif field == "photos":
        async with SessionFactory() as s:
            profile = await ProfileService.get_with_relations(s, cb.from_user.id)
            photos = sorted(profile.photos, key=lambda p: p.position) if profile else []
        rows: list[list[InlineKeyboardButton]] = []
        if photos:
            rows.append([InlineKeyboardButton(
                        text=f"🗑️ #{p.position + 1}",
                        callback_data=f"{CB_V1}:photo_rm:{p.id}") for p in photos])
            rows.append([InlineKeyboardButton(text="⬆️", callback_data=f"{CB_V1}:photo_mv:-1"),
                         InlineKeyboardButton(text="⬇️", callback_data=f"{CB_V1}:photo_mv:1")])
        rows.append([InlineKeyboardButton(text=t(lang, "photos_done"),
                                          callback_data=f"{CB_V1}:photo_done")])
        await state.set_state(EditState.photos)
        await state.update_data(edit_photo_ids=[p.id for p in photos],
                                new_photos=[], remove_ids=[])
        await cb.message.answer(t(lang, "ask_photo"),
                                reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
        for p in photos:
            with suppress(TelegramAPIError):
                await bot.send_photo(cb.from_user.id, p.file_id,
                                     caption=f"#{p.position + 1}")


async def _save_simple_edit(user_id: int, field: str, value: Any) -> None:
    async with SessionFactory() as s:
        profile = await ProfileService.get_with_relations(s, user_id)
        if profile is None:
            return
        if field == "age_range":
            lo, hi = value
            if profile.preference:
                profile.preference.min_age, profile.preference.max_age = lo, hi
        else:
            setattr(profile, field, value)
        profile.updated_at = utcnow()
        await s.commit()


@router.message(EditState.name)
async def edit_name(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    if not valid_name(message.text or ""):
        await message.answer(t(lang, "name_invalid"))
        return
    await _save_simple_edit(message.from_user.id, "display_name", message.text.strip())
    await state.clear()
    await message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


@router.message(EditState.city)
async def edit_city(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    city = (message.text or "").strip()[:80]
    if len(city) < 2:
        await message.answer(t(lang, "ask_city"))
        return
    await _save_simple_edit(message.from_user.id, "city", city)
    await state.clear()
    await message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


@router.message(EditState.bio)
async def edit_bio(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    bio = (message.text or "").strip()[:300]
    if len(bio) < 20:
        await message.answer(t(lang, "bio_invalid"))
        return
    await _save_simple_edit(message.from_user.id, "bio", bio)
    await state.clear()
    await message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


@router.message(EditState.age_range)
async def edit_age_range(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    if is_cancel(message.text):
        await cancel_flow(message, state)
        return
    parsed = valid_age_range(message.text or "")
    if parsed is None:
        await message.answer(t(lang, "age_range_invalid"))
        return
    await _save_simple_edit(message.from_user.id, "age_range", parsed)
    await state.clear()
    await message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


@router.callback_query(F.data.startswith(f"{CB_V1}:edit_intent:"), StateFilter(EditState.intent))
async def edit_intent(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "edit_intent")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in INTENT_KEYS:
        await cb.answer()
        return
    await _save_simple_edit(cb.from_user.id, "intent", args[0])
    await cb.answer()
    if args[0] == "game_friend":
        await state.set_state(EditState.game_name)
        await cb.message.answer(t(lang, "ask_game_name"),
                                reply_markup=game_choice_kb("name", lang, "edit_game"))
    else:
        await state.clear()
        await cb.message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


@router.callback_query(F.data.startswith(f"{CB_V1}:edit_game:"), StateFilter(EditState.game_name))
async def edit_game_name(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "edit_game")
    lang = await get_lang_async(cb.from_user.id)
    if not args or args[0] not in GAME_OPTION_KEYS["name"]:
        await cb.answer()
        return
    await _save_simple_edit(cb.from_user.id, "game_name", args[0])
    await state.update_data(game_name=args[0])
    await state.set_state(EditState.game_rank)
    await cb.answer()
    await cb.message.answer(t(lang, "ask_game_rank"),
                            reply_markup=game_choice_kb("rank", lang, "edit_rank", args[0]))


@router.callback_query(F.data.startswith(f"{CB_V1}:edit_rank:"), StateFilter(EditState.game_rank))
async def edit_game_rank(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "edit_rank")
    lang = await get_lang_async(cb.from_user.id)
    data = await state.get_data()
    game_name = data.get("game_name", "other")
    if not args or args[0] not in GAME_RANK_KEYS.get(game_name, GAME_RANK_KEYS["other"]):
        await cb.answer()
        return
    await _save_simple_edit(cb.from_user.id, "game_rank", args[0])
    await state.clear()
    await cb.answer()
    await cb.message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


@router.callback_query(F.data.startswith(f"{CB_V1}:edit_i:"), StateFilter(EditState.interests))
async def edit_interests(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "edit_i")
    lang = await get_lang_async(cb.from_user.id)
    if not args:
        await cb.answer()
        return
    data = await state.get_data()
    selected = set(data.get("interests", []))
    if args[0] == "done":
        async with SessionFactory() as s:
            profile = await ProfileService.get_with_relations(s, cb.from_user.id)
            if profile:
                await ProfileService.upsert_interests(s, profile, sorted(selected))
                await s.commit()
        await state.clear()
        await cb.answer()
        await cb.message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))
        return
    if args[0] not in INTEREST_KEYS:
        await cb.answer()
        return
    selected ^= {args[0]}
    await state.update_data(interests=sorted(selected))
    await cb.answer()
    with suppress(TelegramBadRequest):
        await cb.message.edit_reply_markup(
            reply_markup=interests_kb(lang, selected, "edit_i"))


@router.message(EditState.photos, F.photo)
async def edit_photo_add(message: Message, state: FSMContext) -> None:
    lang = await get_lang_async(message.from_user.id)
    data = await state.get_data()
    current = list(data.get("edit_photo_ids", [])) + list(data.get("new_photos", []))
    if len(current) >= MAX_PHOTOS:
        await message.answer(t(lang, "photo_max"))
        return
    fid = message.photo[-1].file_id
    if not await verify_telegram_photo(fid):
        await message.answer(t(lang, "error_generic"))
        return
    new_photos = list(data.get("new_photos", []))
    new_photos.append(fid)
    await state.update_data(new_photos=new_photos)
    await message.answer(t(lang, "photo_added", n=len(current) + 1))


@router.callback_query(F.data.startswith(f"{CB_V1}:photo_rm:"), StateFilter(EditState.photos))
async def edit_photo_remove(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "photo_rm")
    if not args or not args[0].isdigit():
        await cb.answer()
        return
    pid = int(args[0])
    data = await state.get_data()
    ids = [i for i in data.get("edit_photo_ids", []) if i != pid]
    removed = list(data.get("remove_ids", []))
    if pid not in removed:
        removed.append(pid)
    await state.update_data(edit_photo_ids=ids, remove_ids=removed)
    await cb.answer("🗑️")


@router.callback_query(F.data.startswith(f"{CB_V1}:photo_mv:"), StateFilter(EditState.photos))
async def edit_photo_move(cb: CallbackQuery, state: FSMContext) -> None:
    args = parse_cb(cb.data, "photo_mv")
    if not args:
        await cb.answer()
        return
    data = await state.get_data()
    ids = list(data.get("edit_photo_ids", []))
    if len(ids) >= 2:
        ids = ids[1:] + ids[:1] if args[0] == "-1" else ids[-1:] + ids[:-1]
        await state.update_data(edit_photo_ids=ids)
    await cb.answer("↕️")


@router.callback_query(F.data == f"{CB_V1}:photo_done", StateFilter(EditState.photos))
async def edit_photo_done(cb: CallbackQuery, state: FSMContext) -> None:
    lang = await get_lang_async(cb.from_user.id)
    data = await state.get_data()
    uid = cb.from_user.id
    async with SessionFactory() as s:
        profile = await ProfileService.get_with_relations(s, uid)
        if profile is None:
            await cb.answer()
            return
        keep_ids = [i for i in data.get("edit_photo_ids", [])
                    if i not in set(data.get("remove_ids", []))]
        existing = {p.id: p for p in profile.photos}
        for pid, photo in list(existing.items()):
            if pid not in keep_ids:
                await s.delete(photo)
        kept = 0
        for pid in keep_ids:
            if pid in existing:
                existing[pid].position = kept
                kept += 1
        for fid in data.get("new_photos", []):
            if kept < MAX_PHOTOS:
                s.add(ProfilePhoto(profile_id=profile.id, file_id=fid, position=kept))
                kept += 1
        profile.updated_at = utcnow()
        await s.commit()
    await state.clear()
    await cb.answer()
    await cb.message.answer(t(lang, "saved"), reply_markup=main_menu_kb(lang))


# --- Settings / deactivate / delete / appeal --------------------------------

@router.message(Command("settings"))
async def cmd_settings(message: Message) -> None:
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        active = user.is_active
    rows = [
        [InlineKeyboardButton(text=t(lang, "btn_language"), callback_data=f"{CB_V1}:set:lang")],
        [InlineKeyboardButton(
            text=t(lang, "btn_deactivate" if active else "btn_activate"),
            callback_data=f"{CB_V1}:set:toggle")],
        [InlineKeyboardButton(text=t(lang, "btn_privacy"),
                              callback_data=f"{CB_V1}:set:privacy")],
        [InlineKeyboardButton(text=t(lang, "btn_edit"), callback_data=f"{CB_V1}:editmenu")],
        [InlineKeyboardButton(text=t(lang, "btn_delete"), callback_data=f"{CB_V1}:delete:ask")],
    ]
    await message.answer(t(lang, "settings_menu"),
                         reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))


@router.callback_query(F.data.startswith(f"{CB_V1}:set:"))
async def cb_settings(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "set")
    lang = await get_lang_async(cb.from_user.id)
    if not args:
        await cb.answer()
        return
    if args[0] == "lang":
        await cb.answer()
        await send_language_picker(cb.message, cb.from_user.id)
        return
    if args[0] == "toggle":
        async with SessionFactory() as s:
            user = await s.get(User, cb.from_user.id)
            if user is None:
                await cb.answer()
                return
            user.is_active = not user.is_active
            now_active = user.is_active
            await s.commit()
        await cb.answer()
        await cb.message.answer(t(lang, "activated" if now_active else "deactivated"))
        return
    if args[0] == "privacy":
        async with SessionFactory() as s:
            user = await s.get(User, cb.from_user.id)
            if user is None:
                await cb.answer()
                return
            user.privacy_mode = not user.privacy_mode
            status = t(lang, "privacy_on" if user.privacy_mode else "privacy_off")
            await s.commit()
        await cb.answer()
        await cb.message.answer(t(lang, "privacy_saved", status=status))


@router.message(Command("delete"))
async def cmd_delete(message: Message) -> None:
    lang = await get_lang_async(message.from_user.id)
    await message.answer(t(lang, "delete_confirm"),
                         reply_markup=confirm_kb(lang, f"{CB_V1}:delete:yes"))


@router.callback_query(F.data.startswith(f"{CB_V1}:delete:"))
async def cb_delete(cb: CallbackQuery) -> None:
    args = parse_cb(cb.data, "delete")
    lang = await get_lang_async(cb.from_user.id)
    if not args:
        await cb.answer()
        return
    if args[0] == "ask":
        await cb.answer()
        await cb.message.answer(t(lang, "delete_confirm"),
                                reply_markup=confirm_kb(lang, f"{CB_V1}:delete:yes"))
        return
    if args[0] != "yes":
        await cb.answer()
        return
    uid = cb.from_user.id
    async with SessionFactory() as s:
        await ProfileService.anonymize_and_delete(s, uid)
        await s.commit()
    log.info("Account deleted: %s", safe_id(uid))
    await cb.answer()
    await cb.message.answer(t(lang, "deleted"), reply_markup=ReplyKeyboardRemove())


@router.message(Command("appeal"))
async def cmd_appeal(message: Message, state: FSMContext) -> None:
    async with SessionFactory() as s:
        user = await s.get(User, message.from_user.id)
        if user is None or not await UserService.is_blocked(s, user):
            return
        lang = user.language
    await state.set_state(AppealState.text)
    await message.answer(t(lang, "appeal_prompt"))


@router.message(AppealState.text)
async def appeal_text(message: Message, state: FSMContext) -> None:
    uid = message.from_user.id
    lang = await get_lang_async(uid)
    text_ = (message.text or "").strip()[:500]
    if len(text_) < 5:
        await message.answer(t(lang, "appeal_too_short"))
        return
    if not await rate_limiter.hit(f"appeal:{uid}", settings.appeal_rate_limit_per_day, 86400):
        await state.clear()
        return
    async with SessionFactory() as s:
        s.add(Appeal(user_id=uid, text=text_))
        await s.commit()
    await state.clear()
    await message.answer(t(lang, "appeal_sent"))

# ===========================================================================
# SECTION 14 — PREMIUM, TELEGRAM STARS PAYMENTS, SUBSCRIPTION STATUS
# ===========================================================================
PREMIUM_PAYLOAD = "premium_30d"


@router.message(Command("premium"))
async def cmd_premium(message: Message) -> None:
    uid = message.from_user.id
    lang = await get_lang_async(uid)
    info = t(lang, "premium_info", days=settings.premium_duration_days,
             price=settings.premium_price_stars if settings.premium_price_stars > 0 else "—",
             likes=settings.premium_daily_likes, sl=settings.premium_daily_super_likes)
    if settings.premium_price_stars <= 0:
        # Price 0 = payments disabled by configuration; nothing fake is claimed.
        await message.answer(info)
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=f"⭐ Buy — {settings.premium_price_stars} Stars",
                             callback_data=f"{CB_V1}:buy:premium")]])
    await message.answer(info, reply_markup=kb)


@router.callback_query(F.data == f"{CB_V1}:buy:premium")
async def cb_buy(cb: CallbackQuery) -> None:
    """Send a Telegram Stars (XTR) invoice. Activation happens ONLY after
    Telegram confirms the payment via pre_checkout + successful_payment."""
    if settings.premium_price_stars <= 0:
        await cb.answer()
        return
    await cb.answer()
    try:
        await bot.send_invoice(
            chat_id=cb.from_user.id,
            title=f"Premium — {settings.premium_duration_days} days",
            description=(f"{settings.premium_daily_likes} likes/day, see who liked you, "
                         f"{settings.premium_daily_super_likes} super likes/day, 1 boost"),
            payload=PREMIUM_PAYLOAD,
            currency="XTR",
            prices=[LabeledPrice(label=f"Premium {settings.premium_duration_days}d",
                                 amount=settings.premium_price_stars)],
            provider_token="",        # empty = Telegram Stars native payments
        )
    except TelegramAPIError as exc:
        log.warning("Invoice failed for %s: %s", safe_id(cb.from_user.id),
                    type(exc).__name__)


@router.pre_checkout_query()
async def on_pre_checkout(query: PreCheckoutQuery) -> None:
    """Validate the invoice payload before Telegram collects payment."""
    ok = (query.invoice_payload == PREMIUM_PAYLOAD
          and query.currency == "XTR"
          and query.total_amount == settings.premium_price_stars)
    await query.answer(ok=ok, error_message=None if ok else "Invalid invoice.")


@router.message(F.successful_payment)
async def on_payment(message: Message) -> None:
    """Verified-payment handler. Trusts ONLY Telegram's successful_payment
    update fields — never user-supplied screenshots or callbacks."""
    sp = message.successful_payment
    uid = message.from_user.id
    lang = await get_lang_async(uid)
    if (sp is None or sp.invoice_payload != PREMIUM_PAYLOAD or
            sp.currency != "XTR" or
            sp.total_amount != settings.premium_price_stars):
        await message.answer(t(lang, "payment_failed"))
        return
    charge_id = sp.telegram_payment_charge_id
    if not charge_id:
        await message.answer(t(lang, "payment_failed"))
        return
    async with SessionFactory() as s:
        recorded = await PremiumService.record_payment(
            s, uid, charge_id, sp.provider_payment_charge_id or "",
            sp.total_amount, sp.invoice_payload)
        if not recorded:                       # idempotent: duplicate update
            await s.commit()
            return
        sub = await PremiumService.activate(s, uid, settings.premium_duration_days)
        # Grant one profile boost with each purchase.
        s.add(Boost(user_id=uid,
                    expires_at=utcnow() + timedelta(hours=settings.boost_duration_hours)))
        await s.commit()
        until = sub.expires_at.astimezone(settings.tz).strftime("%Y-%m-%d")
    log.info("Payment verified for %s (amount=%s %s)", safe_id(uid),
             sp.total_amount, sp.currency)
    await message.answer(t(lang, "payment_success", until=until))


@router.message(Command("subscription"))
@router.message(Command("purchases"))
async def cmd_subscription(message: Message) -> None:
    uid = message.from_user.id
    lang = await get_lang_async(uid)
    async with SessionFactory() as s:
        q = (select(Subscription).where(Subscription.user_id == uid,
                                        Subscription.status == "active",
                                        Subscription.expires_at > utcnow()))
        sub = (await s.execute(q)).scalar_one_or_none()
        count = (await s.execute(select(func.count(Payment.id)).where(
            Payment.user_id == uid))).scalar_one()
    if sub:
        until = sub.expires_at.astimezone(settings.tz).strftime("%Y-%m-%d %H:%M")
        status = (t(lang, "trial_active", until=until)
                  if sub.plan == "welcome_trial"
                  else t(lang, "premium_active", until=until))
        await message.answer(status +
                             f"\n🧾 Payments: {count}")
    else:
        await message.answer(t(lang, "premium_free", likes=settings.free_daily_likes) +
                             f"\n🧾 Payments: {count}")

# --- Chat relay (catch-all: registered LAST so commands/FSM win) ------------
_RELAY_ALLOWED = {"text", "photo", "sticker", "voice", "video", "video_note", "document"}
_MAX_DOC_BYTES = 20 * 1024 * 1024


@router.message(StateFilter(None), ~F.text.startswith("/"),
                ~F.text.func(_is_menu_label))
async def relay_message(message: Message, state: FSMContext) -> None:
    """Catch-all relay: only plain messages with no active FSM state and no
    bot command reach this handler, so it can never swallow /commands or
    registration input."""
    if message.from_user is None or message.from_user.is_bot:
        return
    if _is_menu_label(message.text):
        return                       # never swallow menu buttons
    uid = message.from_user.id
    async with SessionFactory() as s:
        user, lang = await _registered_user(s, uid)
        if user is None:
            await message.answer(t(lang, "welcome"))
            return
        if not user.active_match_id:
            await message.answer(t(lang, "choose_option"),
                                 reply_markup=main_menu_kb(lang))
            return
        match = await MatchService.get_match(s, user.active_match_id, uid)
        if match is None:
            user.active_match_id = None
            await s.commit()
            await message.answer(t(lang, "chat_peer_gone"))
            return
        peer_id = MatchService.peer_of(match, uid)
        # Both directions of blocking stop the relay.
        if await ModerationService.is_blocked_either_way(s, uid, peer_id):
            user.active_match_id = None
            await s.commit()
            await message.answer(t(lang, "chat_peer_gone"))
            return
        ctype = message.content_type
        if ctype not in _RELAY_ALLOWED:
            await message.answer(t(lang, "error_generic"))
            return
        if ctype == "document" and message.document and \
                (message.document.file_size or 0) > _MAX_DOC_BYTES:
            await message.answer(t(lang, "error_generic"))
            return
        peer = await s.get(User, peer_id)
        if peer is None or await UserService.is_blocked(s, peer) or not peer.is_active:
            await message.answer(t(lang, "chat_peer_gone"))
            return
        s.add(MessageLog(match_id=match.id, from_user=uid, to_user=peer_id,
                         content_type=ctype))
        await s.commit()
    # Per-user rate limit (outside the DB transaction).
    if not await rate_limiter.hit(f"chat:{uid}", settings.chat_rate_limit_per_minute, 60):
        await message.answer(t(lang, "msg_rate_limited"))
        return
    try:
        await message.copy_to(peer_id)           # content is relayed, never stored
    except TelegramBadRequest as exc:
        log.info("Relay blocked for %s: %s", safe_id(uid), type(exc).__name__)
        await message.answer(t(lang, "peer_blocked_bot"))
    except TelegramAPIError as exc:
        log.warning("Relay failed for %s: %s", safe_id(uid), type(exc).__name__)
        await message.answer(t(lang, "error_generic"))

# ===========================================================================
# SECTION 15 — FASTAPI APP: health, metrics, admin auth, admin dashboard (HTML)
# ===========================================================================
app = FastAPI(title="VibeMate Admin", docs_url=None, redoc_url=None, openapi_url=None)

ROLE_RANK = {"support": 1, "moderator": 2, "superadmin": 3}


class LoginForm(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


async def current_admin(request: Request) -> tuple[AdminUser, str] | RedirectResponse:
    """Resolve the signed cookie to a live, unrevoked admin session."""
    token = request.cookies.get("admin_session")
    if not token:
        return RedirectResponse("/admin/login", status_code=303)
    payload = unsign_session(token, settings.admin_session_ttl_seconds)
    if not payload or "sid" not in payload:
        return RedirectResponse("/admin/login", status_code=303)
    async with SessionFactory() as s:
        sess = await s.get(AdminSession, payload["sid"])
        if sess is None or sess.revoked or (as_utc(sess.expires_at) or utcnow()) < utcnow():
            return RedirectResponse("/admin/login", status_code=303)
        admin = await s.get(AdminUser, sess.admin_id)
        if admin is None or not admin.is_active:
            return RedirectResponse("/admin/login", status_code=303)
        return admin, sess.id


def require_role(admin: AdminUser, minimum: str) -> None:
    if ROLE_RANK.get(admin.role, 0) < ROLE_RANK.get(minimum, 99):
        raise HTTPException(status_code=403, detail="Insufficient role")


PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VibeMate Admin</title><style>
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;background:#f6f7f9;color:#222}}
nav a{{margin-right:1rem}} table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
input,select,button,textarea{{padding:.45rem .6rem;margin:.2rem 0}}
.card{{background:#fff;padding:1rem;border-radius:8px;margin-bottom:1rem}}
.danger{{color:#a00}} .ok{{color:#080}}
</style></head><body>{body}</body></html>"""


def page(body: str, admin: AdminUser | None = None, session_id: str | None = None) -> HTMLResponse:
    nav = ""
    if admin:
        nav = (f"<nav><b>Admin</b> ({escape(admin.username)} · {escape(admin.role)}) "
               "<a href='/admin'>Dashboard</a><a href='/admin/users'>Users</a>"
               "<a href='/admin/reports'>Reports</a><a href='/admin/appeals'>Appeals</a>"
               "<a href='/admin/payments'>Payments</a><a href='/admin/broadcast'>Broadcast</a>"
               "<a href='/admin/backup'>Backup / Restore</a><a href='/admin/audit'>Audit</a>"
               f"<form method='post' action='/admin/logout' style='display:inline'>"
               f"{csrf_field(session_id) if session_id else ''}"
               "<button type='submit'>Logout</button></form></nav><hr>")
    return HTMLResponse(PAGE.format(body=nav + body))


def csrf_field(session_id: str) -> str:
    return f"<input type='hidden' name='csrf' value='{generate_csrf(session_id)}'>"


async def verify_csrf(session_id: str, form_csrf: str | None) -> None:
    if not form_csrf or not check_csrf(session_id, form_csrf):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


# --- Health / readiness / metrics (no sensitive details) ----------------------
@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": APP_VERSION}


@app.get("/ready")
async def ready() -> JSONResponse:
    db_ok = True
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return JSONResponse({"ready": db_ok, "checks": {"database": db_ok}},
                        status_code=200 if db_ok else 503)


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> PlainTextResponse:
    """Prometheus-style counters. Aggregate numbers only — no personal data."""
    async with SessionFactory() as s:
        users = (await s.execute(select(func.count(User.id)).where(
            User.deleted_at.is_(None)))).scalar_one()
        matches = (await s.execute(select(func.count(Match.id)).where(
            Match.is_active))).scalar_one()
        open_reports = (await s.execute(select(func.count(Report.id)).where(
            Report.status == "open"))).scalar_one()
    lines = (
        "# TYPE matchmaking_users_total gauge\n"
        f"matchmaking_users_total {users}\n"
        "# TYPE matchmaking_matches_active gauge\n"
        f"matchmaking_matches_active {matches}\n"
        "# TYPE matchmaking_reports_open gauge\n"
        f"matchmaking_reports_open {open_reports}\n"
    )
    return PlainTextResponse(lines)


# --- Auth ---------------------------------------------------------------------
@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_form() -> HTMLResponse:
    return page("""
    <div class=card><h2>Admin Login</h2>
    <form method=post action='/admin/login'>
      <input name=username placeholder=Username autocomplete=username><br>
      <input name=password type=password placeholder=Password autocomplete=current-password><br>
      <button type=submit>Sign in</button></form></div>""")


@app.post("/admin/login")
async def admin_login(request: Request, username: str = Form(...),
                      password: str = Form(...)) -> Response:
    ip = request.client.host if request.client else "unknown"
    if not await rate_limiter.hit(f"admin_login:{ip}", 5, 300):
        raise HTTPException(status_code=429, detail="Too many attempts")
    try:
        form = LoginForm(username=username, password=password)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid input")
    async with SessionFactory() as s:
        admin = (await s.execute(select(AdminUser).where(
            AdminUser.username == form.username))).scalar_one_or_none()
        if admin is None or not admin.is_active or \
                not verify_password(form.password, admin.password_hash):
            await asyncio.sleep(0.3)          # uniform-ish timing
            return page("<div class=card><p class=danger>Invalid credentials.</p>"
                        "<a href='/admin/login'>Back</a></div>")
        sess = AdminSession(admin_id=admin.id,
                            expires_at=utcnow() + timedelta(
                                seconds=settings.admin_session_ttl_seconds))
        s.add(sess)
        await ModerationService.audit(s, admin.username, "login")
        await s.commit()
        token = sign_session({"sid": sess.id, "uid": admin.id})
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie("admin_session", token, httponly=True, samesite="strict",
                    secure=settings.is_production,
                    max_age=settings.admin_session_ttl_seconds, path="/admin")
    return resp


@app.post("/admin/logout")
async def admin_logout(request: Request, csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    _admin, sid = auth
    await verify_csrf(sid, csrf)
    async with SessionFactory() as s:
        sess = await s.get(AdminSession, sid)
        if sess:
            sess.revoked = True
            await s.commit()
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp


# --- Dashboard ------------------------------------------------------------------
@app.get("/admin", response_class=HTMLResponse)
async def admin_home(request: Request) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    async with SessionFactory() as s:
        users = (await s.execute(select(func.count(User.id)).where(
            User.deleted_at.is_(None)))).scalar_one()
        active = (await s.execute(select(func.count(User.id)).where(
            User.is_registered.is_(True), User.is_active.is_(True),
            User.deleted_at.is_(None)))).scalar_one()
        premium = (await s.execute(select(func.count(func.distinct(Subscription.user_id))).where(
            Subscription.status == "active", Subscription.expires_at > utcnow()))).scalar_one()
        matches = (await s.execute(select(func.count(Match.id)).where(
            Match.is_active))).scalar_one()
        open_reports = (await s.execute(select(func.count(Report.id)).where(
            Report.status == "open"))).scalar_one()
        open_appeals = (await s.execute(select(func.count(Appeal.id)).where(
            Appeal.status == "open"))).scalar_one()
        payments = (await s.execute(select(func.coalesce(
            func.sum(Payment.amount), 0)).where(Payment.status == "succeeded"))).scalar_one()
    body = f"""<div class=card><h2>Analytics</h2>
    <p>👥 Total users: <b>{users}</b> · Active profiles: <b>{active}</b> · ⭐ Premium: <b>{premium}</b></p>
    <p>💕 Active matches: <b>{matches}</b> · 🚩 Open reports: <b>{open_reports}</b> · 📝 Open appeals: <b>{open_appeals}</b></p>
    <p>⭐ Revenue (Stars): <b>{payments}</b></p></div>"""
    return page(body, admin, sid)


# --- Backup / restore (superadmin only) -----------------------------------------
BACKUP_MODELS: tuple[type[Base], ...] = (
    User, Interest, Profile, ProfilePhoto, MatchPreference, UserInterest,
    Like, Match, Block, Subscription, Payment, Boost, DailyUsage,
    Report, Appeal, Consent,
)


def _backup_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


async def build_backup() -> dict[str, Any]:
    """Export user/business data only; admin credentials and sessions never leave DB."""
    snapshot: dict[str, Any] = {
        "backup_version": 1,
        "app": APP_NAME,
        "schema_version": SCHEMA_VERSION,
        "created_at": utcnow().isoformat(),
        "tables": {},
    }
    async with SessionFactory() as s:
        for model in BACKUP_MODELS:
            rows = list((await s.execute(select(model))).scalars().all())
            snapshot["tables"][model.__tablename__] = [
                {column.name: _backup_value(getattr(row, column.name))
                 for column in model.__table__.columns}
                for row in rows
            ]
    return snapshot


def _restore_value(column: Any, value: Any) -> Any:
    if value is None:
        return None
    if isinstance(column.type, DateTime) and isinstance(value, str):
        return datetime.fromisoformat(value)
    if isinstance(column.type, Date) and isinstance(value, str):
        return date.fromisoformat(value)
    return value


async def restore_backup(snapshot: dict[str, Any]) -> int:
    """Merge a validated snapshot without deleting live rows."""
    tables = snapshot.get("tables")
    if snapshot.get("backup_version") != 1 or not isinstance(tables, dict):
        raise ValueError("Unsupported backup format")
    by_table = {model.__tablename__: model for model in BACKUP_MODELS}
    restored = 0
    async with SessionFactory() as s:
        for table, rows in tables.items():
            model = by_table.get(table)
            if model is None or not isinstance(rows, list):
                continue
            columns = {column.name: column for column in model.__table__.columns}
            for raw in rows:
                if not isinstance(raw, dict):
                    continue
                values = {name: _restore_value(columns[name], value)
                          for name, value in raw.items() if name in columns}
                if values:
                    await s.merge(model(**values))
                    restored += 1
        await s.commit()
    return restored


@app.get("/admin/backup", response_class=HTMLResponse)
async def admin_backup_page(request: Request) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "superadmin")
    body = f"""<div class=card><h2>Backup / Restore</h2>
    <p>Download a JSON backup of user profiles, matches, subscriptions and moderation data.</p>
    <p class=danger>Admin passwords, sessions and audit logs are never included.</p>
    <p><a href='/admin/backup/download'><button type=button>Download backup</button></a></p>
    <hr><h3>Merge restore</h3>
    <p>Restore adds or updates records and does not delete current data. Maximum file size: 25 MB.</p>
    <form method=post action='/admin/backup/restore' enctype='multipart/form-data'>
      {csrf_field(sid)}<input type=file name=backup_file accept='.json,application/json' required><br>
      <input name=confirmation placeholder='Type RESTORE VIBEMATE' required>
      <button class=danger type=submit>Restore backup</button></form></div>"""
    return page(body, admin, sid)


@app.get("/admin/backup/download")
async def admin_backup_download(request: Request) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, _sid = auth
    require_role(admin, "superadmin")
    snapshot = await build_backup()
    content = json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(content=content, media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=vibemate-backup.json",
                             "Cache-Control": "no-store"})


@app.post("/admin/backup/restore")
async def admin_backup_restore(request: Request,
                               backup_file: UploadFile = File(...),
                               confirmation: str = Form(...),
                               csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "superadmin")
    await verify_csrf(sid, csrf)
    if confirmation.strip() != "RESTORE VIBEMATE":
        raise HTTPException(422, "Type RESTORE VIBEMATE to confirm")
    raw = await backup_file.read(25 * 1024 * 1024 + 1)
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(413, "Backup file is too large")
    try:
        snapshot = json.loads(raw.decode("utf-8"))
        restored = await restore_backup(snapshot)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(422, "Invalid VibeMate backup file") from exc
    async with SessionFactory() as s:
        await ModerationService.audit(s, admin.username, "backup_restore",
                                      str(restored), backup_file.filename or "backup.json")
        await s.commit()
    return page(f"<div class=card><p class=ok>Restored/merged {restored} records.</p>"
                "<a href='/admin/backup'>Back to Backup / Restore</a></div>", admin, sid)


# --- User management -------------------------------------------------------------
@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, q: str = "", page_no: int = 1) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "support")
    page_no = max(1, min(page_no, 10_000))
    per = 20
    async with SessionFactory() as s:
        stmt = (select(User, Profile).outerjoin(Profile, Profile.user_id == User.id)
                .where(User.deleted_at.is_(None))
                .order_by(User.created_at.desc()).limit(per).offset((page_no - 1) * per))
        if q.strip():
            qs = q.strip()
            cond = (User.username.ilike(f"%{qs}%") | Profile.display_name.ilike(f"%{qs}%"))
            if qs.isdigit():
                cond = cond | (User.id == int(qs))
            stmt = stmt.where(cond)
        rows = (await s.execute(stmt)).all()
    trs = "".join(
        f"<tr><td>{u.id}</td><td>{escape(p.display_name) if p else '—'}</td>"
        f"<td>{escape(u.username or '—')}</td>"
        f"<td>{'🚫 banned' if u.is_banned else ('⏸️ hidden' if not u.is_active else '✅')}</td>"
        f"<td><a href='/admin/users/{u.id}'>manage</a></td></tr>" for u, p in rows)
    body = f"""<div class=card><h2>Users</h2>
    <form method=get><input name=q value='{escape(q)}' placeholder='Search id / name / username'>
    <button>Search</button></form>
    <table><tr><th>ID</th><th>Name</th><th>Username</th><th>Status</th><th></th></tr>{trs}</table>
    <p><a href='/admin/users?page_no={page_no + 1}&q={escape(q)}'>Next →</a></p></div>"""
    return page(body, admin, sid)


@app.get("/admin/users/{uid}", response_class=HTMLResponse)
async def admin_user_detail(request: Request, uid: int) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "support")
    async with SessionFactory() as s:
        user = await s.get(User, uid)
        if user is None:
            raise HTTPException(404, "User not found")
        profile = await ProfileService.get_with_relations(s, uid)
        premium = await PremiumService.is_premium(s, uid)
    suspended = as_utc(user.suspended_until)
    status = ("banned" if user.is_banned else
              ("suspended" if suspended and suspended > utcnow()
               else ("deleted" if user.deleted_at else "active")))
    name_html = escape(profile.display_name) if profile else "—"
    age_html = str(profile.age) if profile else "—"
    city_html = escape(profile.city) if profile else "—"
    game_html = "—"
    if profile and profile.intent == "game_friend":
        game_html = escape(game_option_label("name", profile.game_name, LANG_EN))
        game_html += " · " + escape(game_rank_label(profile.game_name, profile.game_rank, LANG_EN))
    premium_html = "⭐" if premium else "—"
    body = f"""<div class=card><h2>User {uid}</h2>
    <p>Name: {name_html} · Age: {age_html} · City: {city_html}</p>
    <p>Connection: {escape(intent_label(profile.intent, LANG_EN) if profile else '—')} · Game: {game_html}</p>
    <p>Status: <b>{status}</b> · Premium: {premium_html}</p>
    <form method=post action='/admin/users/{uid}/ban'>{csrf_field(sid)}
      <input name=reason placeholder='Reason' required>
      <select name=days><option value=7>Suspend 7d</option>
      <option value=30>Suspend 30d</option><option value=0 class=danger>Permanent ban</option>
      </select><button class=danger>Apply</button></form>
    <form method=post action='/admin/users/{uid}/unban'>{csrf_field(sid)}
      <button>Unban / lift suspension</button></form></div>"""
    return page(body, admin, sid)


@app.post("/admin/users/{uid}/ban")
async def admin_ban(request: Request, uid: int, reason: str = Form(...),
                    days: int = Form(...), csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "moderator")
    await verify_csrf(sid, csrf)
    reason = reason.strip()[:255]
    days = max(0, min(int(days), 3650))
    async with SessionFactory() as s:
        user = await s.get(User, uid)
        if user is None:
            raise HTTPException(404, "User not found")
        if days == 0:
            user.is_banned = True
            user.suspended_until = None
        else:
            user.suspended_until = utcnow() + timedelta(days=days)
        user.ban_reason = reason
        user.active_match_id = None
        await ModerationService.audit(s, admin.username,
                                      "ban" if days == 0 else f"suspend_{days}d",
                                      safe_id(uid), reason)
        await s.commit()
    return RedirectResponse(f"/admin/users/{uid}", status_code=303)


@app.post("/admin/users/{uid}/unban")
async def admin_unban(request: Request, uid: int, csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "moderator")
    await verify_csrf(sid, csrf)
    async with SessionFactory() as s:
        user = await s.get(User, uid)
        if user is None:
            raise HTTPException(404, "User not found")
        user.is_banned = False
        user.suspended_until = None
        user.ban_reason = None
        await ModerationService.audit(s, admin.username, "unban", safe_id(uid))
        await s.commit()
    return RedirectResponse(f"/admin/users/{uid}", status_code=303)


# --- Reports / moderation ----------------------------------------------------------
@app.get("/admin/reports", response_class=HTMLResponse)
async def admin_reports(request: Request, status: str = "open",
                        page_no: int = 1) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "moderator")
    page_no = max(1, min(page_no, 10_000))
    per = 20
    async with SessionFactory() as s:
        q = (select(Report).order_by(Report.created_at.desc())
             .limit(per).offset((page_no - 1) * per))
        if status in ("open", "resolved", "dismissed"):
            q = q.where(Report.status == status)
        rows = list((await s.execute(q)).scalars().all())
        reporter_profiles: dict[int, Optional[Profile]] = {}
        reported_profiles: dict[int, Optional[Profile]] = {}
        for r in rows:
            if r.reporter not in reporter_profiles:
                reporter_profiles[r.reporter] = await ProfileService.get_with_relations(s, r.reporter)
            if r.reported not in reported_profiles:
                reported_profiles[r.reported] = await ProfileService.get_with_relations(s, r.reported)

    def nm(p: Optional[Profile]) -> str:
        return escape(p.display_name) if p else "(deleted)"

    trs = "".join(
        f"<tr><td>{r.id}</td><td>{nm(reporter_profiles.get(r.reporter))}</td>"
        f"<td>{nm(reported_profiles.get(r.reported))}</td><td>{escape(r.category)}</td>"
        f"<td>{escape(r.details[:80])}</td><td>{r.status}</td>"
        f"<td><form method=post action='/admin/reports/{r.id}/resolve'>{csrf_field(sid)}"
        f"<input name=note placeholder='Note'><select name=verdict>"
        f"<option value=resolved>Resolve</option><option value=dismissed>Dismiss</option>"
        f"</select><button>Save</button></form>"
        f"<a href='/admin/users/{r.reported}'>manage reported</a></td></tr>" for r in rows)
    status_html = escape(status)
    body = f"""<div class=card><h2>Reports ({status_html})</h2>
    <p><a href='/admin/reports?status=open'>Open</a> ·
    <a href='/admin/reports?status=resolved'>Resolved</a> ·
    <a href='/admin/reports?status=dismissed'>Dismissed</a></p>
    <table><tr><th>#</th><th>Reporter</th><th>Reported</th><th>Category</th>
    <th>Details</th><th>Status</th><th>Action</th></tr>{trs}</table>
    <p><a href='/admin/reports?status={status_html}&page_no={page_no + 1}'>Next →</a></p></div>"""
    return page(body, admin, sid)


@app.post("/admin/reports/{rid}/resolve")
async def admin_report_resolve(request: Request, rid: int, note: str = Form(""),
                               verdict: str = Form(...), csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "moderator")
    await verify_csrf(sid, csrf)
    if verdict not in ("resolved", "dismissed"):
        raise HTTPException(422, "Bad verdict")
    async with SessionFactory() as s:
        report = await s.get(Report, rid)
        if report is None:
            raise HTTPException(404, "Report not found")
        report.status = verdict
        report.moderator_note = note.strip()[:500]
        report.resolved_at = utcnow()
        report.resolved_by = admin.id
        await ModerationService.audit(s, admin.username, f"report_{verdict}",
                                      str(rid), note[:100])
        await s.commit()
    return RedirectResponse("/admin/reports", status_code=303)


# --- Appeals ----------------------------------------------------------------------
@app.get("/admin/appeals", response_class=HTMLResponse)
async def admin_appeals(request: Request, status: str = "open",
                        page_no: int = 1) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "moderator")
    page_no = max(1, min(page_no, 10_000))
    per = 20
    async with SessionFactory() as s:
        q = (select(Appeal).order_by(Appeal.created_at.desc())
             .limit(per).offset((page_no - 1) * per))
        if status in ("open", "resolved", "dismissed"):
            q = q.where(Appeal.status == status)
        rows = list((await s.execute(q)).scalars().all())
    trs = "".join(
        f"<tr><td>{a.id}</td><td>{safe_id(a.user_id)}</td>"
        f"<td>{escape(a.text[:150])}</td><td>{a.status}</td>"
        f"<td>{a.created_at:%Y-%m-%d %H:%M}</td>"
        f"<td><form method=post action='/admin/appeals/{a.id}/resolve'>{csrf_field(sid)}"
        f"<select name=verdict>"
        f"<option value=resolved>Resolve &amp; lift suspension</option>"
        f"<option value=dismissed>Dismiss</option></select><button>Save</button></form>"
        f"<a href='/admin/users/{a.user_id}'>manage user</a></td></tr>" for a in rows)
    status_html = escape(status)
    body = f"""<div class=card><h2>Appeals ({status_html})</h2>
    <p><a href='/admin/appeals?status=open'>Open</a> ·
    <a href='/admin/appeals?status=resolved'>Resolved</a> ·
    <a href='/admin/appeals?status=dismissed'>Dismissed</a></p>
    <table><tr><th>#</th><th>User</th><th>Appeal</th><th>Status</th>
    <th>Submitted</th><th>Action</th></tr>{trs}</table>
    <p><a href='/admin/appeals?status={status_html}&page_no={page_no + 1}'>Next →</a></p></div>"""
    return page(body, admin, sid)


@app.post("/admin/appeals/{aid}/resolve")
async def admin_appeal_resolve(request: Request, aid: int,
                               verdict: str = Form(...), csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "moderator")
    await verify_csrf(sid, csrf)
    if verdict not in ("resolved", "dismissed"):
        raise HTTPException(422, "Bad verdict")
    async with SessionFactory() as s:
        appeal = await s.get(Appeal, aid)
        if appeal is None:
            raise HTTPException(404, "Appeal not found")
        appeal.status = verdict
        appeal.resolved_at = utcnow()
        if verdict == "resolved":
            # A granted appeal lifts the ban/suspension in the same transaction.
            user = await s.get(User, appeal.user_id)
            if user is not None:
                user.is_banned = False
                user.suspended_until = None
                user.ban_reason = None
        await ModerationService.audit(s, admin.username, f"appeal_{verdict}",
                                      safe_id(appeal.user_id))
        await s.commit()
    return RedirectResponse("/admin/appeals", status_code=303)


# --- Payments ---------------------------------------------------------------------
@app.get("/admin/payments", response_class=HTMLResponse)
async def admin_payments(request: Request, page_no: int = 1) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "support")
    page_no = max(1, min(page_no, 10_000))
    async with SessionFactory() as s:
        rows = list((await s.execute(
            select(Payment).order_by(Payment.created_at.desc())
            .limit(20).offset((page_no - 1) * 20))).scalars().all())
    trs = "".join(
        f"<tr><td>{p.id}</td><td>{safe_id(p.user_id)}</td><td>{p.amount} {p.currency}</td>"
        f"<td>{escape(p.status)}</td><td>{p.created_at:%Y-%m-%d %H:%M}</td></tr>" for p in rows)
    return page(f"<div class=card><h2>Payments</h2><table>"
                f"<tr><th>#</th><th>User</th><th>Amount</th><th>Status</th><th>Date</th></tr>"
                f"{trs}</table></div>", admin, sid)


# --- Broadcast (superadmin only, double confirmation) -------------------------------
@app.get("/admin/broadcast", response_class=HTMLResponse)
async def admin_broadcast_form(request: Request) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "superadmin")
    body = f"""<div class=card><h2>Broadcast</h2>
    <p class=danger>Sends a message to every registered, active user. Use with care.</p>
    <form method=post action='/admin/broadcast'>{csrf_field(sid)}
      <textarea name=text rows=4 cols=60 maxlength=1000 required></textarea><br>
      <label><input type=checkbox name=confirm value=yes required>
      I confirm this broadcast</label><br>
      <button class=danger>Send broadcast</button></form></div>"""
    return page(body, admin, sid)


@app.post("/admin/broadcast")
async def admin_broadcast(request: Request, text_: str = Form("", alias="text"),
                          confirm: str = Form(""), csrf: str = Form(...)) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "superadmin")
    await verify_csrf(sid, csrf)
    if confirm != "yes" or not text_.strip():
        raise HTTPException(422, "Confirmation and text required")
    msg_text = text_.strip()[:1000]
    async with SessionFactory() as s:
        ids = list((await s.execute(select(User.id).where(
            User.is_registered.is_(True), User.is_active.is_(True),
            User.is_banned.is_(False), User.deleted_at.is_(None)))).scalars().all())
        await ModerationService.audit(s, admin.username, "broadcast",
                                      f"{len(ids)} recipients")
        await s.commit()
    asyncio.create_task(_broadcast_task(ids, msg_text))
    return page(f"<div class=card><p class=ok>Broadcast queued for "
                f"{len(ids)} users.</p><a href='/admin'>Back</a></div>", admin, sid)


async def _broadcast_task(user_ids: list[int], msg_text: str) -> None:
    sent = failed = 0
    for uid in user_ids:
        try:
            await bot.send_message(uid, escape(msg_text))
            sent += 1
        except TelegramAPIError:
            failed += 1
        await asyncio.sleep(0.05)              # ~20 msg/s, Telegram-friendly
    log.info("Broadcast finished: sent=%d failed=%d", sent, failed)


# --- Audit log --------------------------------------------------------------------
@app.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit(request: Request, page_no: int = 1) -> Response:
    auth = await current_admin(request)
    if isinstance(auth, RedirectResponse):
        return auth
    admin, sid = auth
    require_role(admin, "superadmin")
    page_no = max(1, min(page_no, 10_000))
    async with SessionFactory() as s:
        rows = list((await s.execute(
            select(AuditLog).order_by(AuditLog.created_at.desc())
            .limit(50).offset((page_no - 1) * 50))).scalars().all())
    trs = "".join(
        f"<tr><td>{a.created_at:%Y-%m-%d %H:%M}</td><td>{escape(a.admin)}</td>"
        f"<td>{escape(a.action)}</td><td>{escape(a.target)}</td>"
        f"<td>{escape(a.detail)}</td></tr>" for a in rows)
    return page(f"<div class=card><h2>Audit log</h2><table>"
                f"<tr><th>Time</th><th>Admin</th><th>Action</th><th>Target</th>"
                f"<th>Detail</th></tr>{trs}</table></div>", admin, sid)


# --- Security headers middleware + CORS ---------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Administration is intentionally Telegram-only. The legacy web dashboard
    # remains in the source for compatibility, but must not be reachable by
    # users or by anyone who discovers the HTTP endpoint.
    if request.url.path == "/admin" or request.url.path.startswith("/admin/"):
        return PlainTextResponse("Not found", status_code=404,
                                 headers={"X-Robots-Tag": "noindex, nofollow"})
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
    if request.url.path.startswith("/admin"):
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp


app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list,
                   allow_methods=["GET", "POST"], allow_headers=["content-type"])


# --- Telegram webhook endpoint --------------------------------------------------------
@app.post("/tg/webhook")
async def telegram_webhook(request: Request) -> Response:
    if settings.webhook_secret:
        token = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not hmac.compare_digest(token, settings.webhook_secret):
            raise HTTPException(403, "Forbidden")
    try:
        payload = await request.json()
        update_ = Update.model_validate(payload)
    except Exception:
        raise HTTPException(400, "Bad update")
    asyncio.create_task(dp.feed_update(bot, update_))
    return Response(status_code=200)

# ===========================================================================
# SECTION 16 — BACKGROUND TASKS, STORAGE, APPLICATION LIFECYCLE
# ===========================================================================
_BACKGROUND_INTERVALS = {"subscription_expiry": 3600, "retention": 86400,
                         "admin_sessions": 21600}


async def _periodic(name: str, interval: int, stop: asyncio.Event, job) -> None:
    """Run `job()` every `interval` seconds until `stop` is set."""
    while not stop.is_set():
        try:
            await job()
        except Exception as exc:
            log.error("Background job %s failed: %s", name, type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def _job_expire_subscriptions() -> None:
    async with SessionFactory() as s:
        res = await s.execute(update(Subscription).where(
            Subscription.status == "active",
            Subscription.expires_at < utcnow()).values(status="expired"))
        await s.commit()
        if res.rowcount:
            log.info("Expired %d subscriptions", res.rowcount)


async def _job_retention_cleanup() -> None:
    """Delete relay-message metadata older than the retention window and
    remove expired boosts. Message *contents* are never stored at all."""
    cutoff = utcnow() - timedelta(days=settings.retention_days_messages)
    async with SessionFactory() as s:
        await s.execute(delete(MessageLog).where(MessageLog.created_at < cutoff))
        await s.execute(delete(Boost).where(Boost.expires_at < utcnow()))
        await s.commit()


async def _job_session_cleanup() -> None:
    """Remove expired/revoked admin sessions so the table stays bounded."""
    async with SessionFactory() as s:
        await s.execute(delete(AdminSession).where(or_(
            AdminSession.revoked.is_(True),
            AdminSession.expires_at < utcnow())))
        await s.commit()


async def ensure_admin_account() -> None:
    """Create/update the bootstrap superadmin from environment credentials.
    The password is stored as a bcrypt hash and never logged."""
    if not settings.admin_password:
        log.warning("ADMIN_PASSWORD not set — admin dashboard login is disabled")
        return
    async with SessionFactory() as s:
        admin = (await s.execute(select(AdminUser).where(
            AdminUser.username == settings.admin_username))).scalar_one_or_none()
        pw_hash = hash_password(settings.admin_password)
        if admin is None:
            s.add(AdminUser(username=settings.admin_username[:64],
                            password_hash=pw_hash, role="superadmin"))
            log.info("Bootstrap superadmin '%s' created", settings.admin_username)
        else:
            admin.password_hash = pw_hash
            admin.is_active = True
        await s.commit()


def configure_storage() -> Any | None:
    """Return a connected Redis client and switch the dispatcher to Redis FSM
    storage. Falls back to in-memory storage when Redis is unavailable or not
    configured (development only — not safe for multi-instance production)."""
    global dp
    if not settings.redis_url:
        log.info("REDIS_URL not set — using in-memory FSM storage and rate limiting")
        return None
    if not _REDIS_AVAILABLE:
        log.error("redis package not installed; falling back to in-memory storage")
        return None
    try:
        client = aioredis.from_url(settings.redis_url)
        dp = Dispatcher(storage=RedisStorage(client))
        dp.include_router(router)
        rate_limiter.configure(client)
        log.info("Redis configured (FSM storage + rate limiting)")
        return client
    except Exception as exc:
        log.error("Redis unavailable (%s) — in-memory fallback", type(exc).__name__)
        return None


async def main() -> None:
    problems = settings.validate_production()
    for p in problems:
        log.error("Configuration error: %s", p)
    if problems and not settings.test_mode:
        log.error("Refusing to start with invalid configuration.")
        sys.exit(2)

    await init_db()
    await ensure_admin_account()
    redis_client = configure_storage()

    stop = asyncio.Event()
    bg_tasks = [
        asyncio.create_task(_periodic("subscription_expiry",
                                      _BACKGROUND_INTERVALS["subscription_expiry"],
                                      stop, _job_expire_subscriptions)),
        asyncio.create_task(_periodic("retention",
                                      _BACKGROUND_INTERVALS["retention"],
                                      stop, _job_retention_cleanup)),
        asyncio.create_task(_periodic("admin_sessions",
                                      _BACKGROUND_INTERVALS["admin_sessions"],
                                      stop, _job_session_cleanup)),
    ]

    server = uvicorn.Server(uvicorn.Config(
        app, host=settings.web_server_host, port=settings.web_server_port,
        log_level=settings.log_level.lower(), access_log=False))

    poll_task: asyncio.Task | None = None
    await set_bot_commands()
    if settings.bot_mode == "polling":
        if not settings.bot_token:
            log.error("BOT_TOKEN is required for polling mode.")
            sys.exit(2)
        await bot.delete_webhook(drop_pending_updates=True)
        poll_task = asyncio.create_task(dp.start_polling(
            bot, allowed_updates=["message", "callback_query", "pre_checkout_query"]))
        log.info("Telegram long polling started")
    else:
        await bot.set_webhook(url=settings.webhook_url,
                              secret_token=settings.webhook_secret or None,
                              allowed_updates=["message", "callback_query",
                                               "pre_checkout_query"])
        log.info("Telegram webhook registered")

    log.info("FastAPI listening on %s:%d (health: /health, ready: /ready, admin: /admin)",
             settings.web_server_host, settings.web_server_port)
    try:
        await server.serve()          # returns on SIGINT/SIGTERM
    finally:
        log.info("Shutting down...")
        stop.set()
        if poll_task is not None:
            poll_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await poll_task
        await asyncio.gather(*bg_tasks, return_exceptions=True)
        if settings.bot_mode == "webhook":
            with suppress(TelegramAPIError):
                await bot.delete_webhook()
        await bot.session.close()
        if redis_client is not None:
            with suppress(Exception):
                await redis_client.aclose()
        await engine.dispose()
        log.info("Shutdown complete.")


# ===========================================================================
# SECTION 17 — EMBEDDED TESTS (pytest) AND SELF-TEST MODE
# ===========================================================================
# Run with:   python -m pytest bot.py -v
# Self-test:  TEST_MODE=true python bot.py --selftest
# The tests exercise pure business logic against an in-memory SQLite database
# and never connect to Telegram or any payment provider.

try:
    import pytest
    _PYTEST = True
except ImportError:                     # pragma: no cover - production image
    _PYTEST = False


async def _test_session_factory():
    """Fresh in-memory database per test (isolated, fast, disposable)."""
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return eng, async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)


async def _mk_user(s: AsyncSession, uid: int, **profile_kw) -> User:
    user = User(id=uid, is_registered=True, is_active=True)
    s.add(user)
    defaults = dict(user_id=uid, display_name=f"User{uid}", age=25,
                    gender="female", bio="hi", city="Yangon")
    defaults.update(profile_kw)
    prof = Profile(**defaults)
    s.add(prof)
    await s.flush()
    s.add(MatchPreference(profile_id=prof.id, preferred_gender="everyone",
                          min_age=settings.min_age, max_age=settings.max_age))
    return user


if _PYTEST:

    @pytest.mark.asyncio
    async def test_age_validation():
        assert valid_age("17") == -1            # below minimum sentinel
        assert valid_age("18") == 18
        assert valid_age("60") == 60
        assert valid_age("abc") is None
        assert valid_age("61") is None

    @pytest.mark.asyncio
    async def test_age_range_validation():
        assert valid_age_range("22-35") == (22, 35)
        assert valid_age_range("35-22") is None
        assert valid_age_range("11-30") is None  # below minimum age
        assert valid_age_range("junk") is None

    @pytest.mark.asyncio
    async def test_name_validation():
        assert valid_name("Aung Aung")
        assert valid_name("မောင်မောင်")           # Myanmar script must pass
        assert not valid_name("a")               # too short
        assert not valid_name("x" * 41)          # too long
        assert not valid_name("<script>")        # no HTML/control chars

    @pytest.mark.asyncio
    async def test_translations_complete():
        for key, entry in TRANSLATIONS.items():
            assert entry.get(LANG_EN), f"{key} missing English"
            assert entry.get(LANG_MY), f"{key} missing Burmese"
        assert "VibeMate" in t(LANG_EN, "welcome")
        assert "VibeMate" in t(LANG_MY, "welcome")

    @pytest.mark.asyncio
    async def test_command_parser_and_gender_label():
        assert extract_command("/profile") == "profile"
        assert extract_command("/profile@VibeMateBot") == "profile"
        assert extract_command("/start ref_demo") == "start"
        assert extract_command("hello") == ""
        assert extract_command("") == ""
        assert "Male" in gender_label("male", LANG_EN)
        assert "အမျိုးသား" in gender_label("male", LANG_MY)
        assert "{gender}" in TRANSLATIONS["profile_card"][LANG_EN]
        assert not is_unknown_command("/profile")
        assert not is_unknown_command("/settings@VibeMateBot")
        assert is_unknown_command("/not_a_real_command")
        assert SCHEMA_VERSION == "3.3.0"
        assert is_owner_telegram(1812962224)
        assert not is_owner_telegram(1812962225)
        assert "admin" not in [c.command for c in BOT_COMMANDS]

    @pytest.mark.asyncio
    async def test_game_option_catalog_is_valid():
        for kind, options in GAME_OPTIONS.items():
            assert options
            keys = [key for key, _en, _my in options]
            assert len(keys) == len(set(keys))
            assert GAME_OPTION_KEYS[kind] == set(keys)
            assert all(en and my for _key, en, my in options)
        assert "platform" not in GAME_OPTIONS
        assert "conqueror" in GAME_RANK_KEYS["pubg_mobile"]
        assert "radiant" in GAME_RANK_KEYS["valorant"]
        assert "mythical_glory" in GAME_RANK_KEYS["mobile_legends"]
        assert "emerald" in GAME_RANK_KEYS["league"]
        assert "Crown" == game_rank_label("pubg_mobile", "crown", LANG_EN)
        assert "Platform" not in TRANSLATIONS["game_details"][LANG_EN]
        assert "<b>Name:</b>" in TRANSLATIONS["profile_card"][LANG_EN]
        assert "<b>Located:</b>" in TRANSLATIONS["profile_card"][LANG_EN]

    @pytest.mark.asyncio
    async def test_discovery_respects_game_intent():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            me = await _mk_user(s, 70, gender="male", intent="game_friend",
                                game_name="pubg_mobile", game_rank="gold",
                                game_platform="mobile")
            await _mk_user(s, 71, gender="female", intent="game_friend",
                           game_name="pubg_mobile", game_rank="silver",
                           game_platform="mobile")
            await _mk_user(s, 72, gender="female", intent="just_friend")
            await s.commit()
            cand = await MatchService.next_candidate(s, me)
            assert cand is not None and cand.user_id == 71
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_mutual_matching_and_duplicates():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 1)
            await _mk_user(s, 2)
            matched, status = await MatchService.swipe(s, 1, 2, "like")
            assert not matched and status == "liked"
            matched, status = await MatchService.swipe(s, 2, 1, "like")
            assert matched and status == "matched"
            matched, status = await MatchService.swipe(s, 1, 2, "like")
            assert not matched and status == "duplicate"
            matched, status = await MatchService.swipe(s, 1, 1, "like")
            assert not matched and status == "self"
            await s.commit()
            m = (await s.execute(select(Match))).scalars().all()
            assert len(m) == 1 and m[0].user_a == 1 and m[0].user_b == 2
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_match_access_control():
        """get_match must only return a match to its participants, and never
        after it has ended (this guards the chat relay authorization)."""
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 60)
            await _mk_user(s, 61)
            await _mk_user(s, 62)
            await MatchService.swipe(s, 60, 61, "like")
            matched, _ = await MatchService.swipe(s, 61, 60, "like")
            assert matched
            await s.commit()
            m = (await s.execute(select(Match))).scalars().all()[0]
            assert await MatchService.get_match(s, m.id, 60) is not None
            assert await MatchService.get_match(s, m.id, 62) is None   # outsider
            assert await MatchService.unmatch(s, m.id, 60) is True
            assert await MatchService.get_match(s, m.id, 60) is None   # ended
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_like_limits():
        eng, sf = await _test_session_factory()
        original = settings.free_daily_likes
        settings.free_daily_likes = 2
        try:
            async with sf() as s:
                await _mk_user(s, 10)
                assert (await UsageService.try_consume(s, 10, False))[0] is True
                assert (await UsageService.try_consume(s, 10, False))[0] is True
                allowed, limit = await UsageService.try_consume(s, 10, False)
                assert allowed is False and limit == 2
                # Premium has its own (higher) limit
                assert (await UsageService.try_consume(s, 10, True))[0] is True
        finally:
            settings.free_daily_likes = original
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_block_and_report():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 20)
            await _mk_user(s, 21)
            assert await ModerationService.block(s, 20, 21) is True
            assert await ModerationService.block(s, 20, 21) is False  # duplicate
            assert await ModerationService.block(s, 20, 20) is False  # self
            ok, why = await ModerationService.report(s, 20, 21, "spam")
            assert ok and why == "ok"
            ok, why = await ModerationService.report(s, 20, 21, "spam")
            assert not ok and why == "duplicate"                      # deduped
            ok, why = await ModerationService.report(s, 20, 21, "bogus")
            assert not ok and why == "bad_category"
            await s.commit()
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_payment_idempotency():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 30)
            assert await PremiumService.record_payment(
                s, 30, "charge-1", "prov-1", 100, PREMIUM_PAYLOAD) is True
            # Same Telegram charge id must never activate twice.
            assert await PremiumService.record_payment(
                s, 30, "charge-1", "prov-1", 100, PREMIUM_PAYLOAD) is False
            sub = await PremiumService.activate(s, 30, 30)
            first_expiry = sub.expires_at
            assert await PremiumService.is_premium(s, 30) is True
            sub2 = await PremiumService.activate(s, 30, 30)
            assert sub2.expires_at > first_expiry          # extension, not reset
            await s.commit()
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_account_deletion_anonymizes():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 40)
            await s.commit()
            await ProfileService.anonymize_and_delete(s, 40)
            await s.commit()
            user = await s.get(User, 40)
            assert user.deleted_at is not None and not user.is_registered
            assert (await s.execute(select(Profile).where(
                Profile.user_id == 40))).scalar_one_or_none() is None
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_admin_password_hashing():
        hashed = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", hashed)
        assert not verify_password("wrong", hashed)
        assert hashed != "correct horse battery staple"

    @pytest.mark.asyncio
    async def test_welcome_trial_is_one_time_and_premium():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 80)
            first = await PremiumService.grant_welcome_trial(s, 80)
            second = await PremiumService.grant_welcome_trial(s, 80)
            assert first is not None and first.plan == "welcome_trial"
            assert second is None
            assert await PremiumService.is_premium(s, 80)
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_profile_quality_requires_game_details_for_game_friend():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            await _mk_user(s, 81, intent="game_friend", game_name="")
            profile = await ProfileService.get_with_relations(s, 81)
            percent, missing = profile_quality(profile)
            assert percent < 100 and "Game details" in missing
        await eng.dispose()

    @pytest.mark.asyncio
    async def test_compatibility_score_bounds():
        s1 = MatchService.compatibility_score({"music", "tech"}, {"music", "tech"},
                                              25, 26, 18, 40, True, True, 1.0)
        s2 = MatchService.compatibility_score(set(), set(), 25, 70, 18, 30,
                                              False, False, 999.0)
        assert 0.0 <= s2 < s1 <= 1.0

    @pytest.mark.asyncio
    async def test_discovery_excludes_swiped_and_self():
        eng, sf = await _test_session_factory()
        async with sf() as s:
            me = await _mk_user(s, 50, gender="male", age=28)
            await _mk_user(s, 51, gender="female", age=25)
            await _mk_user(s, 52, gender="female", age=25)
            await s.commit()
            cand = await MatchService.next_candidate(s, me)
            assert cand is not None and cand.user_id in (51, 52)
            await MatchService.swipe(s, 50, cand.user_id, "pass")
            await s.commit()
            cand2 = await MatchService.next_candidate(s, me)
            assert cand2 is not None and cand2.user_id != cand.user_id
            assert cand2.user_id != 50
        await eng.dispose()


    @pytest.mark.asyncio
    async def test_burmese_strings_are_intact():
        """Regression guard for Myanmar text.

        Flags any Burmese run that starts with a dependent sign or medial
        (U+102B-U+103E) -- the signature of a dropped base consonant.
        """
        dep = {chr(c) for c in range(0x102B, 0x103F)}
        my_lo, my_hi = chr(0x1000), chr(0x109F)
        broken = []
        for key, entry in TRANSLATIONS.items():
            for lang, value in entry.items():
                run = ""
                for ch in value + " ":
                    if my_lo <= ch <= my_hi:
                        run += ch
                    else:
                        if run and run[0] in dep:
                            broken.append((key, lang, run))
                        run = ""
        assert not broken, "Burmese text missing a leading consonant: %r" % (broken,)
        female = "".join(chr(c) for c in (0x1021, 0x1019, 0x103B, 0x102D, 0x102F,
                                          0x1038, 0x101E, 0x1019, 0x102E, 0x1038))
        nhat = "".join(chr(c) for c in (0x1014, 0x103E, 0x1005, 0x103A))
        assert female in TRANSLATIONS["gender_female"]["my"]
        assert nhat in TRANSLATIONS["menu_likes"]["my"]
        assert nhat in TRANSLATIONS["match_notify"]["my"]


async def _selftest() -> int:
    """Runnable smoke test without pytest (TEST_MODE=true python bot.py --selftest)."""
    checks = {
        "age_validation": lambda: valid_age("17") == -1 and valid_age("18") == 18 and valid_age("60") == 60 and valid_age("61") is None,
        "name_validation": lambda: (valid_name("Aung Aung") and valid_name("မောင်မောင်")
                                    and not valid_name("<script>")),
        "translations": lambda: all(e.get(LANG_EN) and e.get(LANG_MY)
                                    for e in TRANSLATIONS.values()),
        "password_hash": lambda: verify_password("x", hash_password("x")),
        "score_bounds": lambda: 0.0 <= MatchService.compatibility_score(
            {"a"}, {"a"}, 25, 26, 18, 40, True, True, 1.0) <= 1.0,
    }
    failed = 0
    for name, fn in checks.items():
        try:
            ok = bool(fn())
        except Exception:
            ok = False
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        failed += 0 if ok else 1
    eng, sf = await _test_session_factory()
    async with sf() as s:
        await _mk_user(s, 1)
        await _mk_user(s, 2)
        await MatchService.swipe(s, 1, 2, "like")
        matched, _ = await MatchService.swipe(s, 2, 1, "like")
        print(f"[{'PASS' if matched else 'FAIL'}] mutual_matching")
        failed += 0 if matched else 1
    await eng.dispose()
    print("SELF-TEST:", "OK" if failed == 0 else f"{failed} FAILURES")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(asyncio.run(_selftest()))
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
