import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
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

    async def analyze_token(self, mint_address: str, timeout: float = 8.0) -> Optional[TokenAnalysis]:
        """Analyze token with PARALLEL API calls for faster response.

        Args:
            mint_address: Solana token mint address
            timeout: Maximum time for analysis (default 8 seconds for APIX compatibility)
        """
        try:
            return await asyncio.wait_for(
                self._analyze_token_impl(mint_address),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Token analysis timed out for {mint_address}")
            # Return partial data with mint info only
            mint_info = await solana_rpc.get_mint_info(mint_address)
            if mint_info:
                return TokenAnalysis(
                    mint_info=mint_info,
                    metadata=None,
                    largest_holders=[],
                    market_data=None,
                    liquidity_data=None,
                    token_age_days=None,
                    creator_address=None,
                )
            return None

    async def _analyze_token_impl(self, mint_address: str) -> Optional[TokenAnalysis]:
        """Internal implementation of token analysis."""
        # First get mint info (required)
        mint_info = await solana_rpc.get_mint_info(mint_address)
        if not mint_info:
            return None

        # Run all other calls in PARALLEL for speed
        async def safe_call(coro, default=None, name=""):
            try:
                return await coro
            except Exception as e:
                logger.warning(f"Failed {name} for {mint_address}: {e}")
                return default

        # Parallel execution of all independent calls
        results = await asyncio.gather(
            safe_call(solana_rpc.get_token_metadata(mint_address), None, "metadata"),
            safe_call(solana_rpc.get_token_largest_accounts(mint_address, limit=20), [], "holders"),
            safe_call(self._fetch_dexscreener_data(mint_address), None, "dexscreener"),
            safe_call(self._get_token_age(mint_address), None, "token_age"),
            safe_call(solana_rpc.get_signatures_for_address(mint_address, limit=10), [], "signatures"),
            return_exceptions=True
        )

        metadata = results[0] if not isinstance(results[0], Exception) else None
        largest_holders = results[1] if not isinstance(results[1], Exception) else []
        dex_data = results[2] if not isinstance(results[2], Exception) else None
        token_age_days = results[3] if not isinstance(results[3], Exception) else None
        signatures = results[4] if not isinstance(results[4], Exception) else []

        # Extract market and liquidity data from single DexScreener call
        market_data, liquidity_data = self._parse_dexscreener_data(dex_data)

        # Identify creator from signatures
        creator_address = None
        if signatures:
            oldest_sig = signatures[-1]
            creator_address = oldest_sig.get("memo") or None

        return TokenAnalysis(
            mint_info=mint_info,
            metadata=metadata,
            largest_holders=largest_holders,
            market_data=market_data,
            liquidity_data=liquidity_data,
            token_age_days=token_age_days,
            creator_address=creator_address,
        )

    async def _fetch_dexscreener_data(self, mint_address: str) -> Optional[Dict]:
        """Single DexScreener API call (previously called twice)."""
        safe_address = validate_mint_address_for_url(mint_address)
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{self.dexscreener_base}/tokens/{safe_address}"
            )
            if response.status_code != 200:
                return None
            return response.json()

    def _parse_dexscreener_data(self, data: Optional[Dict]) -> Tuple[Optional[MarketData], Optional[LiquidityData]]:
        """Parse DexScreener response into market and liquidity data."""
        if not data:
            return None, LiquidityData(
                has_liquidity=False,
                total_liquidity_usd=None,
                lp_burned=False,
                lp_locked=False,
                lp_lock_duration_days=None,
                main_pool=None,
            )

        pairs = data.get("pairs", [])
        if not pairs:
            return None, LiquidityData(
                has_liquidity=False,
                total_liquidity_usd=None,
                lp_burned=False,
                lp_locked=False,
                lp_lock_duration_days=None,
                main_pool=None,
            )

        main_pair = pairs[0]

        # Market data
        market_data = MarketData(
            price_usd=float(main_pair.get("priceUsd", 0)) if main_pair.get("priceUsd") else None,
            market_cap_usd=float(main_pair.get("marketCap", 0)) if main_pair.get("marketCap") else None,
            volume_24h_usd=float(main_pair.get("volume", {}).get("h24", 0)),
            price_change_24h_pct=float(main_pair.get("priceChange", {}).get("h24", 0)),
            liquidity_usd=float(main_pair.get("liquidity", {}).get("usd", 0)),
        )

        # Liquidity data
        total_liquidity = sum(float(p.get("liquidity", {}).get("usd", 0)) for p in pairs)
        main_pool = main_pair.get("pairAddress")

        lp_info = main_pair.get("info", {})
        lp_burned = False
        lp_locked = False

        if "socials" in lp_info:
            for social in lp_info.get("socials", []):
                label = social.get("label", "").lower()
                if "burn" in label:
                    lp_burned = True
                if "lock" in label:
                    lp_locked = True

        liquidity_data = LiquidityData(
            has_liquidity=total_liquidity > 0,
            total_liquidity_usd=total_liquidity if total_liquidity > 0 else None,
            lp_burned=lp_burned,
            lp_locked=lp_locked,
            lp_lock_duration_days=None,
            main_pool=main_pool,
        )

        return market_data, liquidity_data

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
