# 🏎️ Tsunami Car Project — Daily Reward System

Sistema corporativo de recompensas diárias blindado contra trapaças, integrado ao Roblox Open Cloud utilizando Python (FastAPI).

## 🛡️ Funcionalidades
- **Resiliência:** Sincronizado estritamente com o fuso horário de Brasília (UTC-3).
- **Segurança:** Autenticação via HMAC-SHA512 e criptografia AES-256-GCM.
- **Anti-Replay:** Sistema baseado em Nonces de uso único para evitar dupes.
- **Tolerância a Falhas:** Redundância com cache e tratamento global de erros.

## 🛠️ Tecnologias Utilizadas
- Python (FastAPI, Uvicorn, Pydantic, Cryptography)
- Luau (Roblox Server Script com tipagem `--!strict`)
- Roblox Open Cloud API (Standard DataStore)
