import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import base58
import httpx

from app.services.solana_rpc import solana_rpc, MintInfo, TokenMetadata, TokenAccount

logger = logging.getLogger("rugpull_detection_api.token_analyzer")


ALLOWED_EXTERNAL_HOSTS = frozenset([
    "api.dexscreener.com",
    "price.jup.ag",
    "public-api.birdeye.so",
])

SOLANA_ADDRESS_PATTERN = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def validate_mint_address_for_url(mint_address: str) -> str:
    """
    Validates and sanitizes a mint address for use in external API URLs.
    Prevents SSRF attacks by ensuring the address is a valid Solana address.

    Returns the sanitized address or raises ValueError if invalid.
    """
    if not mint_address or not isinstance(mint_address, str):
        raise ValueError("Invalid mint address: empty or wrong type")

    mint_address = mint_address.strip()

    if not SOLANA_ADDRESS_PATTERN.match(mint_address):
        raise ValueError(f"Invalid mint address format: {mint_address[:20]}...")

    try:
        decoded = base58.b58decode(mint_address)
        if len(decoded) != 32:
            raise ValueError(f"Invalid mint address length: expected 32 bytes, got {len(decoded)}")
    except Exception as e:
        raise ValueError(f"Invalid base58 encoding: {e}")

    return quote(mint_address, safe="")


@dataclass
class MarketData:
    price_usd: Optional[float]
    market_cap_usd: Optional[float]
    volume_24h_usd: Optional[float]
    price_change_24h_pct: Optional[float]
    liquidity_usd: Optional[float]


@dataclass
class LiquidityData:
    has_liquidity: bool
    total_liquidity_usd: Optional[float]
    lp_burned: bool
    lp_locked: bool
    lp_lock_duration_days: Optional[int]
    main_pool: Optional[str]


@dataclass
class TokenAnalysis:
    mint_info: MintInfo
    metadata: Optional[TokenMetadata]
    largest_holders: List[TokenAccount]
    market_data: Optional[MarketData]
    liquidity_data: Optional[LiquidityData]
    token_age_days: Optional[int]
    creator_address: Optional[str]


class TokenAnalyzerService:
    def __init__(self):
        self.dexscreener_base = "https://api.dexscreener.com/latest/dex"
        self.jupiter_price_api = "https://price.jup.ag/v6/price"
        self.birdeye_base = "https://public-api.birdeye.so"

    async def analyze_token(self, mint_address: str) -> Optional[TokenAnalysis]:
        mint_info = await solana_rpc.get_mint_info(mint_address)
        if not mint_info:
            return None

        metadata = None
        try:
            metadata = await solana_rpc.get_token_metadata(mint_address)
        except Exception as e:
            logger.warning(f"Failed to get metadata for {mint_address}: {e}")

        largest_holders = []
        try:
            largest_holders = await solana_rpc.get_token_largest_accounts(mint_address, limit=20)
        except Exception as e:
            logger.warning(f"Failed to get largest holders for {mint_address}: {e}")

        market_data = None
        try:
            market_data = await self._fetch_market_data(mint_address)
        except Exception as e:
            logger.warning(f"Failed to get market data for {mint_address}: {e}")

        liquidity_data = None
        try:
            liquidity_data = await self._fetch_liquidity_data(mint_address)
        except Exception as e:
            logger.warning(f"Failed to get liquidity data for {mint_address}: {e}")

        token_age_days = None
        try:
            token_age_days = await self._get_token_age(mint_address)
        except Exception as e:
            logger.warning(f"Failed to get token age for {mint_address}: {e}")

        creator_address = None
        try:
            creator_address = await self._identify_creator(mint_address, largest_holders)
        except Exception as e:
            logger.warning(f"Failed to identify creator for {mint_address}: {e}")

        return TokenAnalysis(
            mint_info=mint_info,
            metadata=metadata,
            largest_holders=largest_holders,
            market_data=market_data,
            liquidity_data=liquidity_data,
            token_age_days=token_age_days,
            creator_address=creator_address,
        )

    async def _fetch_market_data(self, mint_address: str) -> Optional[MarketData]:
        safe_address = validate_mint_address_for_url(mint_address)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{self.dexscreener_base}/tokens/{safe_address}"
            )

            if response.status_code != 200:
                return None

            data = response.json()
            pairs = data.get("pairs", [])
            if not pairs:
                return None

            main_pair = pairs[0]
            return MarketData(
                price_usd=float(main_pair.get("priceUsd", 0)) if main_pair.get("priceUsd") else None,
                market_cap_usd=float(main_pair.get("marketCap", 0)) if main_pair.get("marketCap") else None,
                volume_24h_usd=float(main_pair.get("volume", {}).get("h24", 0)),
                price_change_24h_pct=float(main_pair.get("priceChange", {}).get("h24", 0)),
                liquidity_usd=float(main_pair.get("liquidity", {}).get("usd", 0)),
            )

    async def _fetch_liquidity_data(self, mint_address: str) -> Optional[LiquidityData]:
        safe_address = validate_mint_address_for_url(mint_address)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{self.dexscreener_base}/tokens/{safe_address}"
            )

            if response.status_code != 200:
                return LiquidityData(
                    has_liquidity=False,
                    total_liquidity_usd=None,
                    lp_burned=False,
                    lp_locked=False,
                    lp_lock_duration_days=None,
                    main_pool=None,
                )

            data = response.json()
            pairs = data.get("pairs", [])

            if not pairs:
                return LiquidityData(
                    has_liquidity=False,
                    total_liquidity_usd=None,
                    lp_burned=False,
                    lp_locked=False,
                    lp_lock_duration_days=None,
                    main_pool=None,
                )

            total_liquidity = sum(
                float(p.get("liquidity", {}).get("usd", 0)) for p in pairs
            )

            main_pair = pairs[0]
            main_pool = main_pair.get("pairAddress")

            lp_info = main_pair.get("info", {})
            lp_burned = False
            lp_locked = False
            lock_duration = None

            if "socials" in lp_info:
                for social in lp_info.get("socials", []):
                    label = social.get("label", "").lower()
                    if "burn" in label:
                        lp_burned = True
                    if "lock" in label:
                        lp_locked = True

            return LiquidityData(
                has_liquidity=total_liquidity > 0,
                total_liquidity_usd=total_liquidity if total_liquidity > 0 else None,
                lp_burned=lp_burned,
                lp_locked=lp_locked,
                lp_lock_duration_days=lock_duration,
                main_pool=main_pool,
            )

    async def _get_token_age(self, mint_address: str) -> Optional[int]:
        creation_time = await solana_rpc.get_account_creation_time(mint_address)
        if creation_time:
            created_dt = datetime.fromtimestamp(creation_time, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            return (now - created_dt).days
        return None

    async def _identify_creator(
        self, mint_address: str, holders: List[TokenAccount]
    ) -> Optional[str]:
        signatures = await solana_rpc.get_signatures_for_address(mint_address, limit=100)
        if signatures:
            oldest_sig = signatures[-1]
            return oldest_sig.get("memo") or None
        return None

    def calculate_holder_concentration(
        self, holders: List[TokenAccount], total_supply: int
    ) -> Dict[str, Any]:
        if not holders or total_supply == 0:
            return {
                "top_10_percentage": 0,
                "top_10_holders": [],
            }

        sorted_holders = sorted(holders, key=lambda h: h.amount, reverse=True)[:10]
        top_10_total = sum(h.amount for h in sorted_holders)
        top_10_percentage = (top_10_total / total_supply) * 100

        top_10_holders = [
            {
                "address": h.owner,
                "balance": str(h.amount),
                "percentage": round((h.amount / total_supply) * 100, 4),
            }
            for h in sorted_holders
        ]

        return {
            "top_10_percentage": round(top_10_percentage, 2),
            "top_10_holders": top_10_holders,
        }

    def calculate_creator_percentage(
        self, holders: List[TokenAccount], creator_address: Optional[str], total_supply: int
    ) -> Optional[float]:
        if not creator_address or total_supply == 0:
            return None

        for holder in holders:
            if holder.owner == creator_address:
                return round((holder.amount / total_supply) * 100, 4)
        return 0.0


token_analyzer = TokenAnalyzerService()
