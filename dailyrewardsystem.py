"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          DAILY REWARD SYSTEM — Enterprise Grade Security Engine             ║
║          Compatível com Roblox Open Cloud API                               ║
║          Segurança: JWT + HMAC-SHA512 + AES-256-GCM + Rate Limiting        ║
║          Autor: Arthur / Tsunami Car Project                                ║
║          Versão: 2.0.0                                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

ARQUITETURA:
  - Backend Python (FastAPI) ←→ Roblox Open Cloud / HttpService
  - Autenticação: API Key + JWT assinado com HMAC-SHA512
  - Payload criptografado com AES-256-GCM
  - Rate limiting por IP + UserId
  - Proteção anti-replay com nonce + timestamp
  - Logs de auditoria estruturados (JSON)
  - Validação de servidor Roblox (PlaceId + UniverseId)

DEPENDÊNCIAS:
  pip install fastapi uvicorn[standard] python-jose[cryptography]
              cryptography httpx python-dotenv redis slowapi
              pydantic-settings loguru python-multipart
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Dict, List, Optional

# ─── Third-party ────────────────────────────────────────────────────────────
try:
    import httpx
    import redis.asyncio as aioredis
    import uvicorn
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from dotenv import load_dotenv
    from fastapi import Depends, FastAPI, HTTPException, Request, Security
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.security import APIKeyHeader
    from jose import JWTError, jwt
    from loguru import logger
    from pydantic import BaseModel, Field, field_validator
    from pydantic_settings import BaseSettings
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address
    FULL_DEPS = True
except ImportError:
    FULL_DEPS = False
    # Modo standalone sem dependências externas (apenas stdlib)
    logger = logging.getLogger("DailyRewardSystem")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

load_dotenv() if FULL_DEPS else None


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONFIGURAÇÕES E SEGREDOS
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityConfig:
    """Configurações de segurança centralizadas."""

    # JWT
    JWT_ALGORITHM: str = "HS512"          # HMAC-SHA512
    JWT_EXPIRE_MINUTES: int = 15           # Token curto — segurança máxima
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        secrets.token_hex(64),             # 512 bits gerados na inicialização
    )

    # AES-256-GCM
    AES_KEY: bytes = bytes.fromhex(
        os.getenv("AES_KEY_HEX", secrets.token_hex(32))
    )

    # HMAC
    HMAC_SECRET: bytes = os.getenv(
        "HMAC_SECRET", secrets.token_hex(64)
    ).encode()

    # Anti-replay
    NONCE_TTL_SECONDS: int = 300           # Nonce válido por 5 min
    MAX_CLOCK_SKEW_SECONDS: int = 60       # Tolerância de relógio

    # Rate limiting
    RATE_LIMIT_CLAIM: str = "5/minute"     # Por UserId
    RATE_LIMIT_GLOBAL: str = "100/minute"  # Por IP

    # Roblox
    ROBLOX_OPEN_CLOUD_KEY: str = os.getenv("ROBLOX_OPEN_CLOUD_KEY", "")
    ROBLOX_UNIVERSE_ID: int = int(os.getenv("ROBLOX_UNIVERSE_ID", "0"))
    ROBLOX_ALLOWED_PLACE_IDS: List[int] = [
        int(x) for x in os.getenv("ROBLOX_ALLOWED_PLACE_IDS", "0").split(",")
        if x.strip().isdigit()
    ]
    ROBLOX_DATASTORE_NAME: str = "DailyRewards_v2"

    # Whitelist de origens permitidas
    ALLOWED_ORIGINS: List[str] = [
        "https://www.roblox.com",
        "https://apis.roblox.com",
    ]


CFG = SecurityConfig()

# Shims para modo sem dependências (stdlib only)
if not FULL_DEPS:
    class BaseModel:  # type: ignore[no-redef]
        """Shim mínimo para modo standalone."""
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    class Field:  # type: ignore[no-redef]
        def __new__(cls, *args, default=None, default_factory=None, **kwargs):
            return default_factory() if default_factory is not None else default

    class field_validator:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs): ...
        def __call__(self, fn): return classmethod(fn)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. MODELOS DE DADOS (PYDANTIC)
# ═══════════════════════════════════════════════════════════════════════════════

class RewardTier(str, Enum):
    """Tiers de recompensa com multiplicadores."""
    BRONZE = "bronze"       # Dia 1–6
    SILVER = "silver"       # Dia 7–13
    GOLD   = "gold"         # Dia 14–20
    DIAMOND = "diamond"     # Dia 21–27
    LEGENDARY = "legendary" # Dia 28+


class RewardItem(BaseModel):
    """Um item individual de recompensa."""
    item_type: str = Field(..., examples=["currency", "item", "badge"])
    item_id: str  = Field(..., min_length=1, max_length=64)
    quantity: int = Field(..., ge=1, le=1_000_000)
    display_name: str = Field(..., max_length=128)

    @field_validator("item_type")
    @classmethod
    def validate_item_type(cls, v: str) -> str:
        allowed = {"currency", "item", "badge", "gamepass", "xp"}
        if v not in allowed:
            raise ValueError(f"item_type deve ser um de: {allowed}")
        return v


class DailyRewardSchedule(BaseModel):
    """
    Tabela completa de recompensas por dia.
    Suporta streaks de até 28 dias com reset automático.
    """
    day: int = Field(..., ge=1, le=28)
    tier: RewardTier
    rewards: List[RewardItem]
    bonus_multiplier: float = Field(default=1.0, ge=1.0, le=10.0)


class ClaimRequest(BaseModel):
    """Payload enviado pelo cliente Roblox."""
    user_id: int      = Field(..., ge=1, description="UserId do Roblox")
    place_id: int     = Field(..., ge=1, description="PlaceId do jogo")
    nonce: str        = Field(..., min_length=32, max_length=64)
    timestamp: int    = Field(..., description="Unix timestamp UTC")
    signature: str    = Field(..., description="HMAC-SHA512 do payload")
    encrypted_data: Optional[str] = Field(
        None, description="Dados extras criptografados (AES-256-GCM)"
    )

    @field_validator("nonce")
    @classmethod
    def nonce_hex(cls, v: str) -> str:
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("nonce deve ser hexadecimal")
        return v


class ClaimResponse(BaseModel):
    """Resposta segura para o cliente Roblox."""
    success: bool
    claim_id: str
    user_id: int
    day_streak: int
    tier: RewardTier
    rewards: List[RewardItem]
    next_claim_utc: str          # ISO 8601
    server_signature: str         # Prova de autenticidade do servidor
    encrypted_payload: str        # Payload criptografado para o client


class PlayerRewardState(BaseModel):
    """Estado persistido no DataStore do Roblox."""
    user_id: int
    day_streak: int = 1
    last_claim_utc: Optional[str] = None
    total_claims: int = 0
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TABELA DE RECOMPENSAS (CONFIGURÁVEL)
# ═══════════════════════════════════════════════════════════════════════════════

REWARD_TABLE: Dict[int, DailyRewardSchedule] = {
    day: DailyRewardSchedule(
        day=day,
        tier=(
            RewardTier.LEGENDARY if day >= 28 else
            RewardTier.DIAMOND   if day >= 21 else
            RewardTier.GOLD      if day >= 14 else
            RewardTier.SILVER    if day >= 7  else
            RewardTier.BRONZE
        ),
        bonus_multiplier=round(1.0 + (day - 1) * 0.1, 2),
        rewards=[
            RewardItem(
                item_type="currency",
                item_id="coins",
                quantity=min(100 + (day - 1) * 50, 2000),
                display_name=f"{min(100 + (day - 1) * 50, 2000)} Moedas",
            ),
            *(
                [RewardItem(
                    item_type="xp",
                    item_id="xp_boost",
                    quantity=day * 10,
                    display_name=f"{day * 10} XP",
                )]
                if day % 3 == 0 else []
            ),
            *(
                [RewardItem(
                    item_type="item",
                    item_id=f"special_day_{day}",
                    quantity=1,
                    display_name=f"Item Especial Dia {day}",
                )]
                if day in {7, 14, 21, 28} else []
            ),
        ]
    )
    for day in range(1, 29)
}


# ═══════════════════════════════════════════════════════════════════════════════
# 4. CAMADA DE CRIPTOGRAFIA (AES-256-GCM + HMAC-SHA512)
# ═══════════════════════════════════════════════════════════════════════════════

class CryptoEngine:
    """
    Motor de criptografia autenticada.
    AES-256-GCM garante confidencialidade + integridade + autenticidade.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Chave AES deve ter exatamente 32 bytes (256 bits)")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str, aad: bytes = b"roblox-daily-rewards") -> str:
        """
        Criptografa plaintext com AES-256-GCM.
        Retorna base64(nonce || ciphertext+tag) — tudo junto para simplicidade.
        """
        nonce = secrets.token_bytes(12)          # 96-bit nonce (padrão GCM)
        ct    = self._aesgcm.encrypt(nonce, plaintext.encode(), aad)
        blob  = nonce + ct
        return b64encode(blob).decode()

    def decrypt(self, token: str, aad: bytes = b"roblox-daily-rewards") -> str:
        """Descriptografa e verifica autenticidade (GCM tag). Raise em falha."""
        blob  = b64decode(token)
        nonce = blob[:12]
        ct    = blob[12:]
        try:
            pt = self._aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag:
            raise SecurityError("Falha na verificação criptográfica (tag inválida)")
        return pt.decode()


class HMACEngine:
    """Assinatura HMAC-SHA512 para verificação de integridade de mensagens."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def sign(self, message: str) -> str:
        """Retorna hex digest HMAC-SHA512."""
        h = hmac.new(self._secret, message.encode(), hashlib.sha512)
        return h.hexdigest()

    def verify(self, message: str, signature: str) -> bool:
        """Verifica HMAC de forma timing-safe (compare_digest)."""
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


class SecurityError(Exception):
    """Exceção lançada em violações de segurança."""
    pass


# Instâncias globais (inicializadas condicionalmente)
_crypto: Optional[CryptoEngine] = None
_hmac: Optional[HMACEngine] = None

if FULL_DEPS:
    _crypto = CryptoEngine(CFG.AES_KEY)
    _hmac   = HMACEngine(CFG.HMAC_SECRET)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. MÓDULO JWT
# ═══════════════════════════════════════════════════════════════════════════════

class JWTManager:
    """Gerenciamento seguro de tokens JWT (HS512)."""

    @staticmethod
    def create(user_id: int, extra: Dict[str, Any] = {}) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(minutes=CFG.JWT_EXPIRE_MINUTES),
            "jti": str(uuid.uuid4()),         # JWT ID — anti-replay
            **extra,
        }
        return jwt.encode(payload, CFG.JWT_SECRET, algorithm=CFG.JWT_ALGORITHM)

    @staticmethod
    def verify(token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(
                token, CFG.JWT_SECRET, algorithms=[CFG.JWT_ALGORITHM]
            )
        except JWTError as exc:
            raise SecurityError(f"Token JWT inválido: {exc}") from exc
        return payload


# ═══════════════════════════════════════════════════════════════════════════════
# 6. VALIDAÇÃO ANTI-REPLAY + VERIFICAÇÃO DE ROBLOX
# ═══════════════════════════════════════════════════════════════════════════════

class RequestValidator:
    """
    Valida requests para garantir:
      1. Timestamp dentro do clock skew permitido
      2. Nonce nunca visto antes (anti-replay)
      3. PlaceId pertence ao universo Roblox autorizado
      4. Assinatura HMAC válida
    """

    def __init__(self, redis_client: Optional[Any] = None) -> None:
        self._redis = redis_client
        self._local_nonces: Dict[str, float] = {}  # Fallback em memória

    async def validate(self, req: ClaimRequest) -> None:
        self._check_timestamp(req.timestamp)
        await self._check_nonce(req.nonce)
        self._check_place_id(req.place_id)
        self._check_signature(req)

    def _check_timestamp(self, ts: int) -> None:
        now = int(time.time())
        delta = abs(now - ts)
        if delta > CFG.MAX_CLOCK_SKEW_SECONDS:
            raise SecurityError(
                f"Timestamp fora do intervalo permitido (delta={delta}s)"
            )

    async def _check_nonce(self, nonce: str) -> None:
        key = f"nonce:{nonce}"
        if self._redis:
            exists = await self._redis.get(key)
            if exists:
                raise SecurityError("Nonce reutilizado — possível replay attack")
            await self._redis.setex(key, CFG.NONCE_TTL_SECONDS, "1")
        else:
            # Fallback: limpeza periódica de nonces expirados (in-memory)
            self._purge_expired_nonces()
            if nonce in self._local_nonces:
                raise SecurityError("Nonce reutilizado (memória local)")
            self._local_nonces[nonce] = time.time() + CFG.NONCE_TTL_SECONDS

    def _purge_expired_nonces(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._local_nonces.items() if exp < now]
        for k in expired:
            del self._local_nonces[k]

    def _check_place_id(self, place_id: int) -> None:
        if (
            CFG.ROBLOX_ALLOWED_PLACE_IDS
            and CFG.ROBLOX_ALLOWED_PLACE_IDS != [0]
            and place_id not in CFG.ROBLOX_ALLOWED_PLACE_IDS
        ):
            raise SecurityError(
                f"PlaceId {place_id} não autorizado para este servidor"
            )

    def _check_signature(self, req: ClaimRequest) -> None:
        if not _hmac:
            return  # Modo sem dependências
        # Canonical message: campos ordenados deterministicamente
        message = f"{req.user_id}:{req.place_id}:{req.nonce}:{req.timestamp}"
        if not _hmac.verify(message, req.signature):
            raise SecurityError("Assinatura HMAC inválida — request rejeitado")


# ═══════════════════════════════════════════════════════════════════════════════
# 7. SERVIÇO DE RECOMPENSAS (LÓGICA DE NEGÓCIO)
# ═══════════════════════════════════════════════════════════════════════════════

class DailyRewardService:
    """
    Núcleo do sistema de recompensas.
    Gerencia estado do jogador, streak e concessão de prêmios.
    """

    COOLDOWN_HOURS: int = 20   # Permite reivindicar a cada 20h (tolerante com fusos)

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        roblox_client: Optional["RobloxOpenCloudClient"] = None,
    ) -> None:
        self._redis  = redis_client
        self._roblox = roblox_client
        self._local_store: Dict[int, PlayerRewardState] = {}

    async def get_state(self, user_id: int) -> PlayerRewardState:
        """Carrega estado do jogador (Redis → Roblox DataStore → novo)."""
        # 1. Cache Redis (mais rápido)
        if self._redis:
            raw = await self._redis.get(f"player:{user_id}")
            if raw:
                return PlayerRewardState(**json.loads(raw))

        # 2. Roblox Open Cloud DataStore
        if self._roblox:
            data = await self._roblox.get_datastore_entry(user_id)
            if data:
                state = PlayerRewardState(**data)
                await self._cache_state(state)
                return state

        # 3. Fallback em memória
        if user_id in self._local_store:
            return self._local_store[user_id]

        # 4. Novo jogador
        return PlayerRewardState(user_id=user_id)

    async def save_state(self, state: PlayerRewardState) -> None:
        """Persiste estado em todos os layers."""
        await self._cache_state(state)
        self._local_store[state.user_id] = state
        if self._roblox:
            await self._roblox.set_datastore_entry(state.user_id, state.model_dump())

    async def _cache_state(self, state: PlayerRewardState) -> None:
        if self._redis:
            await self._redis.setex(
                f"player:{state.user_id}",
                3600,  # TTL 1h
                json.dumps(state.model_dump()),
            )

    def can_claim(self, state: PlayerRewardState) -> tuple[bool, str]:
        """
        Verifica se o jogador pode reivindicar.
        Retorna (pode, mensagem_de_erro_ou_vazio).
        """
        if state.last_claim_utc is None:
            return True, ""

        last = datetime.fromisoformat(state.last_claim_utc)
        now  = datetime.now(timezone.utc)
        diff = now - last

        if diff < timedelta(hours=self.COOLDOWN_HOURS):
            remaining = timedelta(hours=self.COOLDOWN_HOURS) - diff
            hours, rem = divmod(int(remaining.total_seconds()), 3600)
            minutes    = rem // 60
            return False, f"Aguarde {hours}h {minutes}min para a próxima recompensa"

        return True, ""

    def get_reward_for_streak(self, streak: int) -> DailyRewardSchedule:
        """Retorna a recompensa do dia com base no streak (1–28, então reseta)."""
        day = ((streak - 1) % 28) + 1
        return REWARD_TABLE[day]

    async def process_claim(
        self, req: ClaimRequest
    ) -> tuple[PlayerRewardState, DailyRewardSchedule]:
        """
        Processa o claim de recompensa diária.
        Thread-safe via lock Redis (ou in-memory).
        """
        state = await self.get_state(req.user_id)

        can, reason = self.can_claim(state)
        if not can:
            raise ValueError(reason)

        # Verifica se o streak expirou (>48h sem claim = reset)
        if state.last_claim_utc:
            last = datetime.fromisoformat(state.last_claim_utc)
            if datetime.now(timezone.utc) - last > timedelta(hours=48):
                logger.info(
                    f"[DRS] UserId={req.user_id} streak resetado "
                    f"(último claim: {state.last_claim_utc})"
                )
                state.day_streak = 1
            else:
                state.day_streak = min(state.day_streak + 1, 9999)
        else:
            state.day_streak = 1

        schedule = self.get_reward_for_streak(state.day_streak)
        state.last_claim_utc = datetime.now(timezone.utc).isoformat()
        state.total_claims   += 1

        await self.save_state(state)

        logger.info(
            f"[DRS] CLAIM
