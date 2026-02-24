import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import base58
import httpx

from app.config import settings

logger = logging.getLogger("rugpull_detection_api.solana_rpc")

TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
METAPLEX_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"


@dataclass
class MintInfo:
    mint_address: str
    decimals: int
    supply: int
    mint_authority: Optional[str]
    freeze_authority: Optional[str]
    is_initialized: bool


@dataclass
class TokenMetadata:
    name: Optional[str]
    symbol: Optional[str]
    uri: Optional[str]
    update_authority: Optional[str]


@dataclass
class TokenAccount:
    address: str
    owner: str
    mint: str
    amount: int


class SolanaRPCService:
    def __init__(self):
        self.rpc_url = settings.solana_rpc_url
        self.helius_api_key = settings.helius_api_key

    def _get_rpc_url(self) -> str:
        if self.helius_api_key:
            return f"https://mainnet.helius-rpc.com/?api-key={self.helius_api_key}"
        return self.rpc_url

    async def _rpc_call(self, method: str, params: List[Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                self._get_rpc_url(),
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": method,
                    "params": params,
                },
            )
            response.raise_for_status()
            result = response.json()
            if "error" in result:
                raise Exception(f"RPC error: {result['error']}")
            return result.get("result")

    async def get_mint_info(self, mint_address: str) -> Optional[MintInfo]:
        result = await self._rpc_call(
            "getAccountInfo",
            [
                mint_address,
                {"encoding": "jsonParsed"},
            ],
        )

        if not result or not result.get("value"):
            return None

        account_data = result["value"]["data"]
        if isinstance(account_data, dict) and "parsed" in account_data:
            parsed = account_data["parsed"]
            if parsed.get("type") == "mint":
                info = parsed["info"]
                return MintInfo(
                    mint_address=mint_address,
                    decimals=info.get("decimals", 0),
                    supply=int(info.get("supply", "0")),
                    mint_authority=info.get("mintAuthority"),
                    freeze_authority=info.get("freezeAuthority"),
                    is_initialized=info.get("isInitialized", False),
                )
        return None

    async def get_token_metadata(self, mint_address: str) -> Optional[TokenMetadata]:
        pda = self._derive_metadata_pda(mint_address)
        if not pda:
            return None

        result = await self._rpc_call(
            "getAccountInfo",
            [
                pda,
                {"encoding": "base64"},
            ],
        )

        if not result or not result.get("value"):
            return None

        data = result["value"]["data"]
        if isinstance(data, list) and len(data) >= 1:
            import base64
            raw_data = base64.b64decode(data[0])
            return self._parse_metadata(raw_data)
        return None

    def _derive_metadata_pda(self, mint_address: str) -> Optional[str]:
        import hashlib

        seed_prefix = b"metadata"
        program_id_bytes = base58.b58decode(METAPLEX_PROGRAM_ID)
        mint_bytes = base58.b58decode(mint_address)

        seeds = [seed_prefix, program_id_bytes, mint_bytes]

        for nonce in range(255, -1, -1):
            seed_with_nonce = b"".join(seeds) + bytes([nonce])
            hash_result = hashlib.sha256(seed_with_nonce + program_id_bytes + b"ProgramDerivedAddress").digest()

            if hash_result[-1] < 128:
                continue

            on_curve = False
            if not on_curve:
                return base58.b58encode(hash_result).decode()

        return None

    def _parse_metadata(self, data: bytes) -> Optional[TokenMetadata]:
        if len(data) < 100:
            return None

        offset = 1 + 32 + 32

        def read_string(data: bytes, offset: int) -> tuple[str, int]:
            if offset + 4 > len(data):
                return "", offset
            length = int.from_bytes(data[offset:offset + 4], "little")
            offset += 4
            if offset + length > len(data):
                return "", offset
            string_bytes = data[offset:offset + length]
            offset += length
            try:
                return string_bytes.decode("utf-8").rstrip("\x00"), offset
            except (UnicodeDecodeError, ValueError):
                return "", offset

        name, offset = read_string(data, offset)
        symbol, offset = read_string(data, offset)
        uri, offset = read_string(data, offset)

        update_authority = None
        if len(data) >= 1 + 32:
            update_authority = base58.b58encode(data[1:33]).decode()

        return TokenMetadata(
            name=name if name else None,
            symbol=symbol if symbol else None,
            uri=uri if uri else None,
            update_authority=update_authority,
        )

    async def get_token_largest_accounts(self, mint_address: str, limit: int = 20) -> List[TokenAccount]:
        try:
            result = await self._rpc_call(
                "getTokenLargestAccounts",
                [mint_address],
            )

            if not result or not result.get("value"):
                return []

            raw_accounts = result["value"][:limit]

            # PARALLEL owner lookups instead of sequential
            async def get_owner_safe(address: str) -> Optional[str]:
                try:
                    return await self._get_token_account_owner(address)
                except Exception:
                    return None

            owner_tasks = [get_owner_safe(acc["address"]) for acc in raw_accounts]
            owners = await asyncio.gather(*owner_tasks)

            accounts = []
            for account, owner in zip(raw_accounts, owners):
                accounts.append(
                    TokenAccount(
                        address=account["address"],
                        owner=owner or account["address"],
                        mint=mint_address,
                        amount=int(account.get("amount", "0")),
                    )
                )
            return accounts
        except Exception as e:
            logger.warning(f"Failed to get largest accounts for {mint_address}: {e}")
            return []

    async def _get_token_account_owner(self, token_account: str) -> Optional[str]:
        result = await self._rpc_call(
            "getAccountInfo",
            [
                token_account,
                {"encoding": "jsonParsed"},
            ],
        )

        if not result or not result.get("value"):
            return None

        data = result["value"]["data"]
        if isinstance(data, dict) and "parsed" in data:
            return data["parsed"].get("info", {}).get("owner")
        return None

    async def get_token_supply(self, mint_address: str) -> Optional[Dict[str, Any]]:
        result = await self._rpc_call(
            "getTokenSupply",
            [mint_address],
        )

        if not result or not result.get("value"):
            return None

        return {
            "amount": result["value"].get("amount", "0"),
            "decimals": result["value"].get("decimals", 0),
            "ui_amount": result["value"].get("uiAmount"),
        }

    async def get_signatures_for_address(self, address: str, limit: int = 10) -> List[Dict[str, Any]]:
        try:
            result = await self._rpc_call(
                "getSignaturesForAddress",
                [
                    address,
                    {"limit": min(limit, 100)},
                ],
            )
            return result or []
        except Exception as e:
            logger.warning(f"Failed to get signatures for {address}: {e}")
            return []

    async def get_account_creation_time(self, address: str) -> Optional[int]:
        signatures = await self.get_signatures_for_address(address, limit=100)
        if signatures:
            oldest = signatures[-1]
            return oldest.get("blockTime")
        return None


solana_rpc = SolanaRPCService()
