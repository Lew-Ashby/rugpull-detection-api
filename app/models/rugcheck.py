from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class AuthorityInfo(BaseModel):
    mint_authority: Optional[str] = Field(description="Address with mint authority, null if revoked")
    freeze_authority: Optional[str] = Field(description="Address with freeze authority, null if revoked")
    update_authority: Optional[str] = Field(description="Address with metadata update authority, null if revoked")
    mint_authority_revoked: bool = Field(description="True if mint authority is revoked (safer)")
    freeze_authority_revoked: bool = Field(description="True if freeze authority is revoked (safer)")


class TokenMetrics(BaseModel):
    total_supply: str = Field(description="Total token supply in raw units")
    decimals: int = Field(description="Token decimals")
    circulating_supply: Optional[str] = Field(description="Circulating supply if available")


class HolderInfo(BaseModel):
    address: str
    balance: str
    percentage: float


class HolderDistribution(BaseModel):
    total_holders: int = Field(description="Total number of token holders")
    top_10_percentage: float = Field(description="Percentage held by top 10 wallets")
    top_10_holders: List[HolderInfo] = Field(description="Top 10 holder details")
    creator_percentage: Optional[float] = Field(description="Percentage held by token creator")


class LiquidityInfo(BaseModel):
    has_liquidity: bool = Field(description="Whether token has DEX liquidity")
    total_liquidity_usd: Optional[float] = Field(description="Total liquidity in USD")
    lp_burned: bool = Field(description="Whether LP tokens are burned")
    lp_locked: bool = Field(description="Whether LP tokens are locked")
    lp_lock_duration_days: Optional[int] = Field(description="Days until LP unlock, null if not locked")
    main_pool: Optional[str] = Field(description="Main liquidity pool address")


class MarketData(BaseModel):
    price_usd: Optional[float]
    market_cap_usd: Optional[float]
    volume_24h_usd: Optional[float]
    price_change_24h_pct: Optional[float]
    liquidity_usd: Optional[float]


class RiskFactor(BaseModel):
    name: str = Field(description="Risk factor name")
    risk_level: str = Field(description="low, medium, high, critical")
    score: int = Field(ge=0, le=100, description="Risk contribution score")
    description: str = Field(description="Explanation of the risk")
    details: Optional[str] = Field(description="Additional details")


class RugcheckResponse(BaseModel):
    contract: str = Field(description="Token mint address")
    name: Optional[str] = Field(description="Token name")
    symbol: Optional[str] = Field(description="Token symbol")
    timestamp: datetime = Field(description="Analysis timestamp")

    risk_score: int = Field(ge=0, le=100, description="Overall rugpull risk score (0=safe, 100=danger)")
    risk_level: str = Field(description="SAFE, CAUTION, RISKY, or DANGER")

    authorities: AuthorityInfo
    token_metrics: TokenMetrics
    holder_distribution: Optional[HolderDistribution]
    liquidity: Optional[LiquidityInfo]
    market_data: Optional[MarketData]

    risk_factors: List[RiskFactor] = Field(description="Individual risk factor analysis")
    summary: str = Field(description="Human-readable risk summary")
