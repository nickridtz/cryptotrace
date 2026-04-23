from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os

BLOCKCHAIR_BASE = "https://api.blockchair.com"
API_KEY = os.getenv("BLOCKCHAIR_API_KEY", "")

SUPPORTED_CHAINS = {
    "bitcoin", "litecoin", "ethereum",
    "dogecoin", "dash", "bitcoin-cash", "zcash",
}

app = FastAPI(title="CryptoTrace")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
async def get_address(chain: str, address: str, limit: int = 50, offset: int = 0):
    validate_chain(chain)
    return await blockchair(
        f"{chain}/dashboards/address/{address}",
        transaction_details="true",
        limit=limit,
        offset=offset,
    )


@app.get("/api/{chain}/tx/{txhash}")
async def get_transaction(chain: str, txhash: str):
    validate_chain(chain)
    return await blockchair(f"{chain}/dashboards/transaction/{txhash}")


@app.get("/api/{chain}/txs/{hashes}")
async def get_transactions_batch(chain: str, hashes: str):
    validate_chain(chain)
    batch = ",".join(h.strip() for h in hashes.split(",")[:10])
    return await blockchair(f"{chain}/dashboards/transactions/{batch}")


@app.get("/api/{chain}/stats")
async def get_stats(chain: str):
    validate_chain(chain)
    return await blockchair(f"{chain}/stats")


app.mount("/", StaticFiles(directory="static", html=True), name="static")
