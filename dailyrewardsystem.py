"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          DAILY REWARD SYSTEM — Enterprise Grade Security Engine              ║
║          Arquitetura Zero-Trust | FastAPI Async | Tolerância a Falhas        ║
║          Projeto: Tsunami Car Project                                        ║
║          Autor: Arthur                                                       ║
║          Versão: 3.0.0 (Ultimate Edition)                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
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
from typing import Any, Dict, List, Optional, Tuple

# ─── Dependências Críticas ──────────────────────────────────────────────────
try:
    import httpx
    import redis.asyncio as aioredis
    import uvicorn
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from dotenv import load_dotenv
    from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
    from fastapi.exceptions import RequestValidationError
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from jose import JWTError, jwt
    from loguru import logger
    from pydantic import BaseModel, Field, field_validator
    FULL_DEPS = True
except ImportError:
    FULL_DEPS = False
    logger = logging.getLogger("DailyRewardSystem")
    logging.basicConfig(level=logging.INFO)

if FULL_DEPS:
    load_dotenv()

# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONFIGURAÇÕES E SEGREDOS GLOBAIS
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityConfig:
    JWT_ALGORITHM: str = "HS512"
    JWT_EXPIRE_MINUTES: int = 15
    JWT_SECRET: str = os.getenv("JWT_SECRET", secrets.token_hex(64))
    
    AES_KEY: bytes = bytes.fromhex(os.getenv("AES_KEY_HEX", secrets.token_hex(32)))
    HMAC_SECRET: bytes = os.getenv("HMAC_SECRET", secrets.token_hex(64)).encode()
    
    NONCE_TTL_SECONDS: int = 300
    MAX_CLOCK_SKEW_SECONDS: int = 60
    
    ROBLOX_OPEN_CLOUD_KEY: str = os.getenv("ROBLOX_OPEN_CLOUD_KEY", "")
    ROBLOX_UNIVERSE_ID: int = int(os.getenv("ROBLOX_UNIVERSE_ID", "0"))
    ROBLOX_ALLOWED_PLACE_IDS: List[int] = [
        int(x) for x in os.getenv("ROBLOX_ALLOWED_PLACE_IDS", "0").split(",") if x.strip().isdigit()
    ]
    ROBLOX_DATASTORE_NAME: str = "DailyRewards_v2"

CFG = SecurityConfig()

# ═══════════════════════════════════════════════════════════════════════════════
# 2. MODELOS DE DADOS E VALIDAÇÃO ESTRITA
# ═══════════════════════════════════════════════════════════════════════════════

class RewardTier(str, Enum):
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    DIAMOND = "diamond"
    LEGENDARY = "legendary"

class RewardItem(BaseModel):
    item_type: str = Field(..., examples=["currency", "item", "xp"])
    item_id: str = Field(..., min_length=1, max_length=64)
    quantity: int = Field(..., ge=1, le=1_000_000)
    display_name: str = Field(..., max_length=128)

class DailyRewardSchedule(BaseModel):
    day: int = Field(..., ge=1, le=28)
    tier: RewardTier
    rewards: List[RewardItem]
    bonus_multiplier: float = Field(default=1.0, ge=1.0, le=10.0)

class ClaimRequest(BaseModel):
    user_id: int = Field(..., ge=1)
    place_id: int = Field(..., ge=1)
    nonce: str = Field(..., min_length=32, max_length=64)
    timestamp: int
    signature: str
    encrypted_data: Optional[str] = None

class ClaimResponse(BaseModel):
    success: bool
    claim_id: str
    user_id: int
    day_streak: int
    tier: RewardTier
    rewards: List[RewardItem]
    next_claim_utc: str
    server_signature: str

class PlayerRewardState(BaseModel):
    user_id: int
    day_streak: int = 1
    last_claim_utc: Optional[str] = None
    total_claims: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# ═══════════════════════════════════════════════════════════════════════════════
# 3. CLIENTE ROBLOX OPEN CLOUD (ASSÍNCRONO E COM TIMEOUTS)
# ═══════════════════════════════════════════════════════════════════════════════

class RobloxOpenCloudClient:
    def __init__(self):
        self.api_key = CFG.ROBLOX_OPEN_CLOUD_KEY
        self.universe_id = CFG.ROBLOX_UNIVERSE_ID
        self.base_url = f"https://apis.roblox.com/datastores/v1/universes/{self.universe_id}/standard-datastores"
        self.headers = {"x-api-key": self.api_key}
        self.timeout = httpx.Timeout(10.0) # Proteção contra travamentos da API do Roblox

    async def get_datastore_entry(self, user_id: int) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/datastore/entries/entry"
        params = {"datastoreName": CFG.ROBLOX_DATASTORE_NAME, "entryKey": f"PlayerReward_{user_id}"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self.headers, params=params)
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    return None # Jogador novo, nunca salvou dados
                else:
                    logger.warning(f"[OpenCloud] Falha ao ler dados: HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"[OpenCloud] Erro crítico de rede: {e}")
        return None

    async def set_datastore_entry(self, user_id: int, data: Dict[str, Any]) -> bool:
        url = f"{self.base_url}/datastore/entries/entry"
        params = {"datastoreName": CFG.ROBLOX_DATASTORE_NAME, "entryKey": f"PlayerReward_{user_id}"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=self.headers, params=params, json=data)
                if resp.status_code == 200:
                    return True
                logger.error(f"[OpenCloud] Falha ao salvar: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"[OpenCloud] Erro crítico ao salvar: {e}")
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# 4. LÓGICA DE NEGÓCIOS (CORE)
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityError(Exception):
    pass

class HMACEngine:
    def __init__(self, secret: bytes):
        self._secret = secret

    def verify(self, message: str, signature: str) -> bool:
        expected = hmac.new(self._secret, message.encode(), hashlib.sha512).hexdigest()
        return hmac.compare_digest(expected, signature)
        
hmac_engine = HMACEngine(CFG.HMAC_SECRET)

def gerar_recompensa(day: int) -> DailyRewardSchedule:
    tier = RewardTier.LEGENDARY if day >= 28 else RewardTier.DIAMOND if day >= 21 else RewardTier.GOLD if day >= 14 else RewardTier.SILVER if day >= 7 else RewardTier.BRONZE
    return DailyRewardSchedule(
        day=day,
        tier=tier,
        rewards=[RewardItem(item_type="currency", item_id="coins", quantity=100 * day, display_name=f"{100 * day} Moedas")]
    )

class DailyRewardService:
    COOLDOWN_HOURS = 20

    def __init__(self):
        self.roblox = RobloxOpenCloudClient()

    async def process_claim(self, req: ClaimRequest) -> Tuple[PlayerRewardState, DailyRewardSchedule]:
        # 1. Busca dados do Roblox
        raw_data = await self.roblox.get_datastore_entry(req.user_id)
        state = PlayerRewardState(**raw_data) if raw_data else PlayerRewardState(user_id=req.user_id)

        # 2. Verifica Cooldown
        if state.last_claim_utc:
            last = datetime.fromisoformat(state.last_claim_utc)
            now = datetime.now(timezone.utc)
            if (now - last) < timedelta(hours=self.COOLDOWN_HOURS):
                raise ValueError("Cooldown ativo. Recompensa já foi coletada.")
            
            # Reset de Streak se passar de 48h
            if (now - last) > timedelta(hours=48):
                state.day_streak = 1
            else:
                state.day_streak = min(state.day_streak + 1, 9999)

        # 3. Atualiza Estado
        schedule = gerar_recompensa(((state.day_streak - 1) % 28) + 1)
        state.last_claim_utc = datetime.now(timezone.utc).isoformat()
        state.total_claims += 1

        # 4. Salva no Roblox Open Cloud
        salvo = await self.roblox.set_datastore_entry(req.user_id, state.model_dump())
        if not salvo:
            raise RuntimeError("Falha ao salvar o progresso no servidor do Roblox.")

        return state, schedule

# ═══════════════════════════════════════════════════════════════════════════════
# 5. FASTAPI APP (O SERVIDOR WEB)
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="Tsunami Car API - Daily Rewards", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)

# --- Tratamento de Erros Global (Nível Google) ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"[Servidor Crítico] Falha não tratada: {exc}")
    return JSONResponse(status_code=500, content={"success": False, "message": "Erro interno no servidor."})

@app.exception_handler(ValueError)
async def validation_exception_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"success": False, "message": str(exc)})

@app.exception_handler(SecurityError)
async def security_exception_handler(request: Request, exc: SecurityError):
    logger.warning(f"[Segurança] Tentativa de invasão bloqueada: {exc}")
    return JSONResponse(status_code=403, content={"success": False, "message": "Falha de Autenticação/Segurança."})

# --- Dependência de Segurança ---
async def verify_security(req: ClaimRequest):
    # Verifica o tempo de requisição para evitar ataques de replay (Clock Skew)
    now = int(time.time())
    if abs(now - req.timestamp) > CFG.MAX_CLOCK_SKEW_SECONDS:
        raise SecurityError("Timestamp inválido ou expirado.")
    
    # Verifica a assinatura HMAC enviada pelo Roblox
    message = f"{req.user_id}:{req.place_id}:{req.nonce}:{req.timestamp}"
    if not hmac_engine.verify(message, req.signature):
        raise SecurityError("Assinatura HMAC inválida. Possível adulteração de pacote.")
    return req

# --- Endpoint Principal ---
@app.post("/check_reward", response_model=ClaimResponse)
async def claim_reward(request: ClaimRequest, valid_req: ClaimRequest = Depends(verify_security)):
    logger.info(f"[API] Recebido pedido de recompensa para o Jogador {valid_req.user_id}")
    
    service = DailyRewardService()
    state, schedule = await service.process_claim(valid_req)
    
    # Gera a assinatura de volta para o Roblox ter certeza que foi o Python que respondeu
    claim_id = str(uuid.uuid4())
    server_sig = hmac.new(CFG.HMAC_SECRET, claim_id.encode(), hashlib.sha512).hexdigest()
    
    return ClaimResponse(
        success=True,
        claim_id=claim_id,
        user_id=state.user_id,
        day_streak=state.day_streak,
        tier=schedule.tier,
        rewards=schedule.rewards,
        next_claim_utc=(datetime.now(timezone.utc) + timedelta(hours=DailyRewardService.COOLDOWN_HOURS)).isoformat(),
        server_signature=server_sig
    )

if __name__ == "__main__":
    uvicorn.run("dailyrewardsystem:app", host="0.0.0.0", port=8000, reload=True)
  
