from dataclasses import dataclass
from typing import List, Optional

from app.services.token_analyzer import TokenAnalysis


@dataclass
class RiskFactor:
    name: str
    risk_level: str
    score: int
    description: str
    details: Optional[str] = None


@dataclass
class RiskAssessment:
    total_score: int
    risk_level: str
    factors: List[RiskFactor]
    summary: str


class RiskScorerService:
    RISK_WEIGHTS = {
        "mint_authority": 25,
        "freeze_authority": 20,
        "update_authority": 10,
        "holder_concentration": 15,
        "creator_holdings": 10,
        "liquidity_lock": 10,
        "token_age": 5,
        "market_metrics": 5,
    }

    def calculate_risk(self, analysis: TokenAnalysis) -> RiskAssessment:
        assessors = [
            self._assess_mint_authority,
            self._assess_freeze_authority,
            self._assess_update_authority,
            self._assess_holder_concentration,
            self._assess_creator_holdings,
            self._assess_liquidity,
            self._assess_token_age,
            self._assess_market_metrics,
        ]

        factors = [assessor(analysis) for assessor in assessors]
        total_score = min(sum(f.score for f in factors), 100)
        risk_level = self._score_to_level(total_score)
        summary = self._generate_summary(factors, total_score, risk_level, analysis)

        return RiskAssessment(
            total_score=total_score,
            risk_level=risk_level,
            factors=factors,
            summary=summary,
        )

    def _assess_mint_authority(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["mint_authority"]

        if analysis.mint_info.mint_authority is None:
            return RiskFactor(
                name="Mint Authority",
                risk_level="low",
                score=0,
                description="Mint authority is revoked - no new tokens can be created",
                details="This is the ideal state for a token",
            )

        return RiskFactor(
            name="Mint Authority",
            risk_level="critical",
            score=max_score,
            description="Mint authority is ACTIVE - unlimited tokens can be minted",
            details=f"Authority held by: {analysis.mint_info.mint_authority}",
        )

    def _assess_freeze_authority(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["freeze_authority"]

        if analysis.mint_info.freeze_authority is None:
            return RiskFactor(
                name="Freeze Authority",
                risk_level="low",
                score=0,
                description="Freeze authority is revoked - accounts cannot be frozen",
                details="This is the ideal state for a token",
            )

        return RiskFactor(
            name="Freeze Authority",
            risk_level="critical",
            score=max_score,
            description="Freeze authority is ACTIVE - your tokens can be frozen",
            details=f"Authority held by: {analysis.mint_info.freeze_authority}",
        )

    def _assess_update_authority(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["update_authority"]

        if not analysis.metadata or analysis.metadata.update_authority is None:
            return RiskFactor(
                name="Update Authority",
                risk_level="low",
                score=0,
                description="No metadata update authority - token info is immutable",
                details="Token name/symbol cannot be changed",
            )

        return RiskFactor(
            name="Update Authority",
            risk_level="medium",
            score=int(max_score * 0.6),
            description="Update authority exists - token metadata can be changed",
            details=f"Authority held by: {analysis.metadata.update_authority}",
        )

    def _assess_holder_concentration(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["holder_concentration"]

        if not analysis.largest_holders:
            return RiskFactor(
                name="Holder Concentration",
                risk_level="high",
                score=int(max_score * 0.8),
                description="Unable to analyze holder distribution",
                details="No holder data available",
            )

        total_supply = analysis.mint_info.supply
        if total_supply == 0:
            return RiskFactor(
                name="Holder Concentration",
                risk_level="critical",
                score=max_score,
                description="Token has zero supply",
            )

        top_10_total = sum(h.amount for h in analysis.largest_holders[:10])
        top_10_pct = (top_10_total / total_supply) * 100

        if top_10_pct >= 90:
            return RiskFactor(
                name="Holder Concentration",
                risk_level="critical",
                score=max_score,
                description=f"Extreme concentration: Top 10 hold {top_10_pct:.1f}%",
                details="Very high rugpull risk from whale manipulation",
            )
        elif top_10_pct >= 70:
            return RiskFactor(
                name="Holder Concentration",
                risk_level="high",
                score=int(max_score * 0.75),
                description=f"High concentration: Top 10 hold {top_10_pct:.1f}%",
                details="Significant price manipulation risk",
            )
        elif top_10_pct >= 50:
            return RiskFactor(
                name="Holder Concentration",
                risk_level="medium",
                score=int(max_score * 0.4),
                description=f"Moderate concentration: Top 10 hold {top_10_pct:.1f}%",
                details="Some whale risk present",
            )

        return RiskFactor(
            name="Holder Concentration",
            risk_level="low",
            score=0,
            description=f"Healthy distribution: Top 10 hold {top_10_pct:.1f}%",
            details="Good decentralization",
        )

    def _assess_creator_holdings(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["creator_holdings"]

        if not analysis.creator_address or not analysis.largest_holders:
            return RiskFactor(
                name="Creator Holdings",
                risk_level="medium",
                score=int(max_score * 0.3),
                description="Unable to identify creator wallet",
                details="Creator holdings unknown",
            )

        total_supply = analysis.mint_info.supply
        creator_amount = 0
        for holder in analysis.largest_holders:
            if holder.owner == analysis.creator_address:
                creator_amount = holder.amount
                break

        if total_supply == 0:
            return RiskFactor(
                name="Creator Holdings",
                risk_level="critical",
                score=max_score,
                description="Token has zero supply",
            )

        creator_pct = (creator_amount / total_supply) * 100

        if creator_pct >= 50:
            return RiskFactor(
                name="Creator Holdings",
                risk_level="critical",
                score=max_score,
                description=f"Creator holds {creator_pct:.1f}% of supply",
                details="Extremely high insider risk",
            )
        elif creator_pct >= 20:
            return RiskFactor(
                name="Creator Holdings",
                risk_level="high",
                score=int(max_score * 0.7),
                description=f"Creator holds {creator_pct:.1f}% of supply",
                details="High insider risk",
            )
        elif creator_pct >= 5:
            return RiskFactor(
                name="Creator Holdings",
                risk_level="medium",
                score=int(max_score * 0.3),
                description=f"Creator holds {creator_pct:.1f}% of supply",
                details="Moderate insider presence",
            )

        return RiskFactor(
            name="Creator Holdings",
            risk_level="low",
            score=0,
            description=f"Creator holds {creator_pct:.1f}% of supply",
            details="Low insider risk",
        )

    def _assess_liquidity(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["liquidity_lock"]

        if not analysis.liquidity_data:
            return RiskFactor(
                name="Liquidity",
                risk_level="high",
                score=int(max_score * 0.8),
                description="No liquidity data available",
                details="Unable to verify liquidity status",
            )

        if not analysis.liquidity_data.has_liquidity:
            return RiskFactor(
                name="Liquidity",
                risk_level="critical",
                score=max_score,
                description="No DEX liquidity found",
                details="Token cannot be traded on DEXes",
            )

        if analysis.liquidity_data.lp_burned:
            return RiskFactor(
                name="Liquidity",
                risk_level="low",
                score=0,
                description="LP tokens are BURNED - liquidity is permanent",
                details=f"Total liquidity: ${analysis.liquidity_data.total_liquidity_usd:,.0f}" if analysis.liquidity_data.total_liquidity_usd else None,
            )

        if analysis.liquidity_data.lp_locked:
            lock_days = analysis.liquidity_data.lp_lock_duration_days
            if lock_days and lock_days >= 365:
                return RiskFactor(
                    name="Liquidity",
                    risk_level="low",
                    score=int(max_score * 0.1),
                    description=f"LP locked for {lock_days} days",
                    details="Long-term lock provides good security",
                )
            elif lock_days and lock_days >= 90:
                return RiskFactor(
                    name="Liquidity",
                    risk_level="medium",
                    score=int(max_score * 0.3),
                    description=f"LP locked for {lock_days} days",
                    details="Medium-term lock",
                )
            return RiskFactor(
                name="Liquidity",
                risk_level="medium",
                score=int(max_score * 0.4),
                description="LP tokens are locked",
                details="Lock duration unknown",
            )

        return RiskFactor(
            name="Liquidity",
            risk_level="high",
            score=int(max_score * 0.8),
            description="LP tokens are NOT locked or burned",
            details="Liquidity can be removed at any time (rugpull risk)",
        )

    def _assess_token_age(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["token_age"]

        if analysis.token_age_days is None:
            return RiskFactor(
                name="Token Age",
                risk_level="medium",
                score=int(max_score * 0.5),
                description="Unable to determine token age",
            )

        age = analysis.token_age_days

        if age < 1:
            return RiskFactor(
                name="Token Age",
                risk_level="critical",
                score=max_score,
                description="Token is less than 1 day old",
                details="Extremely new tokens carry highest risk",
            )
        elif age < 7:
            return RiskFactor(
                name="Token Age",
                risk_level="high",
                score=int(max_score * 0.8),
                description=f"Token is {age} days old",
                details="Very new token - proceed with caution",
            )
        elif age < 30:
            return RiskFactor(
                name="Token Age",
                risk_level="medium",
                score=int(max_score * 0.4),
                description=f"Token is {age} days old",
                details="Relatively new token",
            )
        elif age < 90:
            return RiskFactor(
                name="Token Age",
                risk_level="low",
                score=int(max_score * 0.1),
                description=f"Token is {age} days old",
                details="Established token",
            )

        return RiskFactor(
            name="Token Age",
            risk_level="low",
            score=0,
            description=f"Token is {age} days old",
            details="Well-established token",
        )

    def _assess_market_metrics(self, analysis: TokenAnalysis) -> RiskFactor:
        max_score = self.RISK_WEIGHTS["market_metrics"]

        if not analysis.market_data:
            return RiskFactor(
                name="Market Metrics",
                risk_level="medium",
                score=int(max_score * 0.5),
                description="No market data available",
            )

        volume = analysis.market_data.volume_24h_usd or 0
        liquidity = analysis.market_data.liquidity_usd or 0

        if volume < 100 and liquidity < 1000:
            return RiskFactor(
                name="Market Metrics",
                risk_level="critical",
                score=max_score,
                description="Extremely low volume and liquidity",
                details=f"24h Volume: ${volume:,.0f}, Liquidity: ${liquidity:,.0f}",
            )
        elif volume < 1000 or liquidity < 10000:
            return RiskFactor(
                name="Market Metrics",
                risk_level="high",
                score=int(max_score * 0.7),
                description="Low trading activity",
                details=f"24h Volume: ${volume:,.0f}, Liquidity: ${liquidity:,.0f}",
            )
        elif volume < 10000 or liquidity < 50000:
            return RiskFactor(
                name="Market Metrics",
                risk_level="medium",
                score=int(max_score * 0.3),
                description="Moderate trading activity",
                details=f"24h Volume: ${volume:,.0f}, Liquidity: ${liquidity:,.0f}",
            )

        return RiskFactor(
            name="Market Metrics",
            risk_level="low",
            score=0,
            description="Healthy trading activity",
            details=f"24h Volume: ${volume:,.0f}, Liquidity: ${liquidity:,.0f}",
        )

    def _score_to_level(self, score: int) -> str:
        if score >= 76:
            return "DANGER"
        elif score >= 51:
            return "RISKY"
        elif score >= 26:
            return "CAUTION"
        return "SAFE"

    def _generate_summary(
        self, factors: List[RiskFactor], score: int, level: str, analysis: TokenAnalysis
    ) -> str:
        critical_factors = [f for f in factors if f.risk_level == "critical"]
        high_factors = [f for f in factors if f.risk_level == "high"]

        token_name = analysis.metadata.name if analysis.metadata and analysis.metadata.name else "This token"

        if level == "DANGER":
            issues = ", ".join([f.name.lower() for f in critical_factors])
            return f"{token_name} has CRITICAL risks ({score}/100). Major red flags: {issues}. HIGH RUGPULL PROBABILITY - avoid this token."

        if level == "RISKY":
            issues = ", ".join([f.name.lower() for f in (critical_factors + high_factors)[:3]])
            return f"{token_name} shows significant risk ({score}/100). Concerns: {issues}. Exercise extreme caution."

        if level == "CAUTION":
            return f"{token_name} has moderate risk ({score}/100). Some risk factors present but not critical. Research thoroughly before investing."

        return f"{token_name} appears relatively safe ({score}/100). Low risk indicators detected. Always DYOR and invest responsibly."


risk_scorer = RiskScorerService()
