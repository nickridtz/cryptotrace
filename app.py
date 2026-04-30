from fastapi import FastAPI, HTTPException, Depends, Request, Response, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
from jose import JWTError, jwt

# ── Blockchair ───────────────────────────────────────────────────
BLOCKCHAIR_BASE = "https://api.blockchair.com"
API_KEY = os.getenv("BLOCKCHAIR_API_KEY", "")

SUPPORTED_CHAINS = {
    "bitcoin", "litecoin", "ethereum",
    "dogecoin", "dash", "bitcoin-cash", "zcash",
}

# ── Auth config ──────────────────────────────────────────────────
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24
USERS_FILE = Path("users.json")
SECRET_KEY_FILE = Path(".secret_key")

if os.getenv("SECRET_KEY"):
    SECRET_KEY = os.getenv("SECRET_KEY")
elif SECRET_KEY_FILE.exists():
    SECRET_KEY = SECRET_KEY_FILE.read_text().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(SECRET_KEY)


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _load_users() -> dict:
    if not USERS_FILE.exists():
        default = {
            "admin": {
                "username": "admin",
                "hashed_password": _hash("admin123"),
                "role": "admin",
            }
        }
        USERS_FILE.write_text(json.dumps(default, indent=2, ensure_ascii=False))
        return default
    users = json.loads(USERS_FILE.read_text())
    # Migrate old records without role field
    changed = False
    for uname, data in users.items():
        if "role" not in data:
            data["role"] = "admin" if uname == "admin" else "user"
            changed = True
    if changed:
        USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))
    return users


def _save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))


def _verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
        users = _load_users()
        if username not in users:
            return None
        return users[username]
    except JWTError:
        return None


def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Не авторизован")
    user = _verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Токен недействителен")
    return user


def get_admin_user(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Только для администратора")
    return user


# ── App ──────────────────────────────────────────────────────────
app = FastAPI(title="Крипта")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth endpoints ───────────────────────────────────────────────
@app.post("/auth/login")
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    users = _load_users()
    user = users.get(username)
    if not user or not _verify(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    if user.get("disabled"):
        raise HTTPException(status_code=403, detail="Аккаунт заблокирован")

    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    token = jwt.encode(
        {"sub": username, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=TOKEN_EXPIRE_HOURS * 3600,
        samesite="strict",
        secure=False,  # True при HTTPS
    )
    return {"status": "ok", "username": username, "role": user.get("role", "user")}


@app.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"status": "ok"}


@app.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"username": user["username"], "role": user.get("role", "user")}


# ── User management (admin only) ─────────────────────────────────
@app.get("/auth/users")
async def list_users(admin: dict = Depends(get_admin_user)):
    users = _load_users()
    return [
        {"username": u, "role": d.get("role", "user"), "disabled": d.get("disabled", False)}
        for u, d in users.items()
    ]


class CreateUserBody(BaseModel):
    username: str
    password: str
    role: str = "user"


@app.post("/auth/users")
async def create_user(body: CreateUserBody, admin: dict = Depends(get_admin_user)):
    if len(body.username.strip()) < 2:
        raise HTTPException(400, "Логин слишком короткий (минимум 2 символа)")
    if len(body.password) < 6:
        raise HTTPException(400, "Пароль слишком короткий (минимум 6 символов)")
    if body.role not in ("admin", "user"):
        raise HTTPException(400, "Роль должна быть 'admin' или 'user'")
    users = _load_users()
    if body.username in users:
        raise HTTPException(409, f"Пользователь «{body.username}» уже существует")
    users[body.username] = {
        "username": body.username,
        "hashed_password": _hash(body.password),
        "role": body.role,
    }
    _save_users(users)
    return {"status": "ok", "username": body.username, "role": body.role}


class ChangePasswordBody(BaseModel):
    password: str


@app.post("/auth/users/{username}/password")
async def change_password(
    username: str,
    body: ChangePasswordBody,
    admin: dict = Depends(get_admin_user),
):
    if len(body.password) < 6:
        raise HTTPException(400, "Пароль слишком короткий (минимум 6 символов)")
    users = _load_users()
    if username not in users:
        raise HTTPException(404, "Пользователь не найден")
    users[username]["hashed_password"] = _hash(body.password)
    _save_users(users)
    return {"status": "ok"}


@app.delete("/auth/users/{username}")
async def delete_user(username: str, admin: dict = Depends(get_admin_user)):
    if username == admin["username"]:
        raise HTTPException(400, "Нельзя удалить самого себя")
    users = _load_users()
    if username not in users:
        raise HTTPException(404, "Пользователь не найден")
    del users[username]
    _save_users(users)
    return {"status": "ok"}


@app.post("/auth/users/{username}/toggle-block")
async def toggle_block(username: str, admin: dict = Depends(get_admin_user)):
    if username == admin["username"]:
        raise HTTPException(400, "Нельзя заблокировать самого себя")
    users = _load_users()
    if username not in users:
        raise HTTPException(404, "Пользователь не найден")
    users[username]["disabled"] = not users[username].get("disabled", False)
    _save_users(users)
    return {"status": "ok", "disabled": users[username]["disabled"]}


# ── Blockchair proxy ─────────────────────────────────────────────
async def blockchair(path: str, **params) -> dict:
    if API_KEY:
        params["key"] = API_KEY
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{BLOCKCHAIR_BASE}/{path}", params=params)
        if r.status_code == 200:
            return r.json()
        try:
            detail = r.json().get("context", {}).get("error", "Blockchair API error")
        except Exception:
            detail = r.text or "Blockchair API error"
        raise HTTPException(status_code=r.status_code, detail=detail)


def validate_chain(chain: str):
    if chain not in SUPPORTED_CHAINS:
        raise HTTPException(400, f"Unsupported chain: {chain}")


@app.get("/api/{chain}/address/{address}")
async def get_address(
    chain: str, address: str,
    limit: int = 50, offset: int = 0,
    _: dict = Depends(get_current_user),
):
    validate_chain(chain)
    return await blockchair(
        f"{chain}/dashboards/address/{address}",
        transaction_details="true",
        limit=limit,
        offset=offset,
    )


@app.get("/api/{chain}/tx/{txhash}")
async def get_transaction(chain: str, txhash: str, _: dict = Depends(get_current_user)):
    validate_chain(chain)
    return await blockchair(f"{chain}/dashboards/transaction/{txhash}")


@app.get("/api/{chain}/txs/{hashes}")
async def get_transactions_batch(chain: str, hashes: str, _: dict = Depends(get_current_user)):
    validate_chain(chain)
    batch = ",".join(h.strip() for h in hashes.split(",")[:10])
    return await blockchair(f"{chain}/dashboards/transactions/{batch}")


@app.get("/api/{chain}/stats")
async def get_stats(chain: str, _: dict = Depends(get_current_user)):
    validate_chain(chain)
    return await blockchair(f"{chain}/stats")


@app.get("/api/{chain}/transactions-range")
async def get_transactions_range(
    chain: str,
    date_from: str,
    date_to: str,
    limit: int = 100,
    offset: int = 0,
    _: dict = Depends(get_current_user),
):
    validate_chain(chain)
    return await blockchair(
        f"{chain}/transactions",
        q=f"time({date_from}..{date_to}),is_coinbase(false)",
        limit=min(limit, 100),
        offset=offset,
        s="id(desc)",
    )


app.mount("/", StaticFiles(directory="static", html=True), name="static")
