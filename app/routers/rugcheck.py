import logging
from datetime import datetime, timezone
from typing import Literal, Union

import base58
from cachetools import TTLCache
from fastapi import APIRouter, HTTPException, Query, Request, Body
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.middleware.security import limiter
from app.models.rugcheck import (
    AuthorityInfo,
    HolderDistribution,
    HolderInfo,
    LiquidityInfo,
    MarketData,
    RiskFactor,
    RugcheckResponse,
    TokenMetrics,
)
from app.services.risk_scorer import risk_scorer
from app.services.token_analyzer import token_analyzer

logger = logging.getLogger("rugpull_detection_api.rugcheck")

router = APIRouter()


class RugcheckRequest(BaseModel):
    """Request model for APIX tool calls"""
    mint_address: str = Field(..., description="Solana token mint address to analyze")

_cache: TTLCache = TTLCache(maxsize=settings.cache_max_size, ttl=settings.cache_ttl_seconds)


def validate_solana_address(address: str) -> bool:
    try:
        decoded = base58.b58decode(address)
        return len(decoded) == 32
    except (ValueError, Exception):
        return False


def check_apix_configuration(request: Request) -> dict | None:
    """
    Check APIX JWT to diagnose configuration issues.
    Returns diagnostic info if x-iao-auth header is present.
    """
    import base64
    import json

    auth_header = request.headers.get("x-iao-auth")
    if not auth_header:
        return None

    try:
        parts = auth_header.split(".")
        if len(parts) != 3:
            return None

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)

        # Log the APIX configuration for debugging
        aud = payload.get("aud", "")
        token_addr = payload.get("tokenAddress", "")
        logger.warning(f"APIX CONFIG ISSUE - aud (endpoint): {aud}")
        logger.warning(f"APIX CONFIG ISSUE - tokenAddress in JWT: {token_addr} (this is payment token, NOT analysis target)")

        return {
            "endpoint_registered": aud,
            "jwt_token_address": token_addr,
            "issue": "APIX is not passing the 'contract' query parameter"
        }
    except Exception as e:
        logger.warning(f"Failed to check APIX config: {e}")
        return None


async def _generate_rugcheck(
    contract: str,
    format: str,
) -> Union[RugcheckResponse, PlainTextResponse]:
    contract = contract.strip()

    if not validate_solana_address(contract):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Solana address format: {contract}",
        )

    cache_key = f"rugcheck:{contract}"
    cached_response = _cache.get(cache_key)
    if cached_response and format == "json":
        logger.info(f"Cache hit for {contract}")
        return cached_response

    analysis = await token_analyzer.analyze_token(contract)

    if not analysis:
        raise HTTPException(
            status_code=404,
            detail=f"Token not found or unable to fetch data for: {contract}",
        )

    risk_assessment = risk_scorer.calculate_risk(analysis)

    authority_info = AuthorityInfo(
        mint_authority=analysis.mint_info.mint_authority,
        freeze_authority=analysis.mint_info.freeze_authority,
        update_authority=analysis.metadata.update_authority if analysis.metadata else None,
        mint_authority_revoked=analysis.mint_info.mint_authority is None,
        freeze_authority_revoked=analysis.mint_info.freeze_authority is None,
    )

    token_metrics = TokenMetrics(
        total_supply=str(analysis.mint_info.supply),
        decimals=analysis.mint_info.decimals,
        circulating_supply=None,
    )

    holder_distribution = None
    if analysis.largest_holders:
        total_supply = analysis.mint_info.supply
        holder_data = token_analyzer.calculate_holder_concentration(
            analysis.largest_holders, total_supply
        )
        creator_pct = token_analyzer.calculate_creator_percentage(
            analysis.largest_holders, analysis.creator_address, total_supply
        )

        holder_distribution = HolderDistribution(
            total_holders=len(analysis.largest_holders),
            top_10_percentage=holder_data["top_10_percentage"],
            top_10_holders=[
                HolderInfo(
                    address=h["address"],
                    balance=h["balance"],
                    percentage=h["percentage"],
                )
                for h in holder_data["top_10_holders"]
            ],
            creator_percentage=creator_pct,
        )

    liquidity_info = None
    if analysis.liquidity_data:
        liquidity_info = LiquidityInfo(
            has_liquidity=analysis.liquidity_data.has_liquidity,
            total_liquidity_usd=analysis.liquidity_data.total_liquidity_usd,
            lp_burned=analysis.liquidity_data.lp_burned,
            lp_locked=analysis.liquidity_data.lp_locked,
            lp_lock_duration_days=analysis.liquidity_data.lp_lock_duration_days,
            main_pool=analysis.liquidity_data.main_pool,
        )

    market_data = None
    if analysis.market_data:
        market_data = MarketData(
            price_usd=analysis.market_data.price_usd,
            market_cap_usd=analysis.market_data.market_cap_usd,
            volume_24h_usd=analysis.market_data.volume_24h_usd,
            price_change_24h_pct=analysis.market_data.price_change_24h_pct,
            liquidity_usd=analysis.market_data.liquidity_usd,
        )

    risk_factors = [
        RiskFactor(
            name=f.name,
            risk_level=f.risk_level,
            score=f.score,
            description=f.description,
            details=f.details,
        )
        for f in risk_assessment.factors
    ]

    response = RugcheckResponse(
        contract=contract,
        name=analysis.metadata.name if analysis.metadata else None,
        symbol=analysis.metadata.symbol if analysis.metadata else None,
        timestamp=datetime.now(timezone.utc),
        risk_score=risk_assessment.total_score,
        risk_level=risk_assessment.risk_level,
        authorities=authority_info,
        token_metrics=token_metrics,
        holder_distribution=holder_distribution,
        liquidity=liquidity_info,
        market_data=market_data,
        risk_factors=risk_factors,
        summary=risk_assessment.summary,
    )

    _cache[cache_key] = response

    if format == "text":
        text_response = _format_text_response(response)
        return PlainTextResponse(content=text_response, media_type="text/plain")

    logger.info(f"Rugcheck completed for {contract}: {risk_assessment.risk_level} ({risk_assessment.total_score}/100)")
    return response


def _format_text_response(response: RugcheckResponse) -> str:
    lines = [
        f"RUGPULL CHECK: {response.name or 'Unknown'} ({response.symbol or 'N/A'})",
        f"Contract: {response.contract}",
        f"",
        f"RISK SCORE: {response.risk_score}/100 - {response.risk_level}",
        f"",
        f"=== AUTHORITIES ===",
        f"Mint Authority: {'REVOKED' if response.authorities.mint_authority_revoked else 'ACTIVE (DANGER!)'}",
        f"Freeze Authority: {'REVOKED' if response.authorities.freeze_authority_revoked else 'ACTIVE (DANGER!)'}",
        f"",
        f"=== TOKEN METRICS ===",
        f"Total Supply: {response.token_metrics.total_supply}",
        f"Decimals: {response.token_metrics.decimals}",
    ]

    if response.holder_distribution:
        lines.extend([
            f"",
            f"=== HOLDER DISTRIBUTION ===",
            f"Top 10 Hold: {response.holder_distribution.top_10_percentage:.1f}%",
        ])
        if response.holder_distribution.creator_percentage is not None:
            lines.append(f"Creator Holds: {response.holder_distribution.creator_percentage:.2f}%")

    if response.liquidity:
        lines.extend([
            f"",
            f"=== LIQUIDITY ===",
            f"Has Liquidity: {'Yes' if response.liquidity.has_liquidity else 'No'}",
        ])
        if response.liquidity.total_liquidity_usd:
            lines.append(f"Total Liquidity: ${response.liquidity.total_liquidity_usd:,.0f}")
        lines.append(f"LP Burned: {'Yes' if response.liquidity.lp_burned else 'No'}")
        lines.append(f"LP Locked: {'Yes' if response.liquidity.lp_locked else 'No'}")

    if response.market_data:
        lines.extend([
            f"",
            f"=== MARKET DATA ===",
        ])
        if response.market_data.price_usd:
            lines.append(f"Price: ${response.market_data.price_usd:.10f}")
        if response.market_data.volume_24h_usd:
            lines.append(f"24h Volume: ${response.market_data.volume_24h_usd:,.0f}")
        if response.market_data.market_cap_usd:
            lines.append(f"Market Cap: ${response.market_data.market_cap_usd:,.0f}")

    lines.extend([
        f"",
        f"=== RISK FACTORS ===",
    ])

    for factor in response.risk_factors:
        indicator = "X" if factor.risk_level in ["critical", "high"] else "!"  if factor.risk_level == "medium" else "+"
        lines.append(f"[{indicator}] {factor.name}: {factor.description}")

    lines.extend([
        f"",
        f"=== SUMMARY ===",
        response.summary,
    ])

    return "\n".join(lines)


@router.get(
    "/rugcheck",
    responses={
        200: {"description": "Rugcheck analysis complete"},
        404: {"description": "Token not found"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
    include_in_schema=False,  # Hide from OpenAPI so APIX doesn't pick this
)
@limiter.limit("60/minute")
async def get_rugcheck_query(
    request: Request,
    contract: str = Query(
        None,
        description="Solana token mint address (base58 format)",
    ),
    mint_address: str = Query(
        None,
        description="Alias for contract parameter",
    ),
    format: Literal["json", "text"] = Query(
        default="json",
        description="Response format: json or text",
    ),
):
    # DEBUG: Log everything APIX sends
    logger.info(f"RUGCHECK DEBUG - Full URL: {request.url}")
    logger.info(f"RUGCHECK DEBUG - Headers: {dict(request.headers)}")
    logger.info(f"RUGCHECK DEBUG - Query params: {dict(request.query_params)}")

    # Try to extract contract from request body (some systems send body with GET)
    try:
        body_bytes = await request.body()
        if body_bytes:
            logger.info(f"RUGCHECK DEBUG - Body: {body_bytes.decode()}")
            import json
            try:
                body_json = json.loads(body_bytes)
                if isinstance(body_json, dict):
                    if not contract:
                        contract = body_json.get("contract") or body_json.get("mint_address")
            except json.JSONDecodeError:
                pass
    except Exception as e:
        logger.warning(f"Could not read body: {e}")

    # Accept both parameter names for compatibility
    token_address = contract or mint_address

    if not token_address:
        # Check if this is an APIX request with misconfiguration
        apix_diag = check_apix_configuration(request)
        if apix_diag:
            # APIX is calling but not passing contract parameter - configuration issue
            logger.error(f"APIX MISCONFIGURATION: {apix_diag}")
            return JSONResponse(
                status_code=200,
                content={
                    "error": "APIX_CONFIGURATION_ERROR",
                    "message": "The APIX tool is not passing the 'contract' parameter. The tool registration needs to be updated to include the contract parameter in the API call.",
                    "diagnosis": apix_diag,
                    "solution": "Re-register the APIX tool with endpoint '/api/rugpull-detection-api/rugcheck-analysis' and ensure 'contract' is configured as a required query parameter extracted from user input."
                }
            )

        # Regular request without token - return ready status
        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "message": "Rugcheck API - provide 'contract' parameter with a Solana token mint address",
                "example": "/rugcheck?contract=DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
                "parameters": {
                    "contract": "Solana token mint address (required)",
                    "format": "json or text (optional, default: json)"
                }
            }
        )
    return await _generate_rugcheck(token_address, format)


@router.get(
    "/rugcheck/{contract}",
    response_model=RugcheckResponse,
    responses={
        200: {"description": "Rugcheck analysis complete"},
        400: {"description": "Invalid contract address"},
        404: {"description": "Token not found"},
        422: {"description": "Invalid parameters"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
    include_in_schema=False,  # Hide from OpenAPI so APIX doesn't pick this
)
@limiter.limit("60/minute")
async def get_rugcheck_path(
    request: Request,
    contract: str,
    format: Literal["json", "text"] = Query(
        default="json",
        description="Response format: json or text",
    ),
) -> Union[RugcheckResponse, PlainTextResponse]:
    return await _generate_rugcheck(contract, format)


def parse_apix_query_field(query_string: str) -> dict:
    """
    Parse APIX query field format: "mint_address=VALUE" or "key1=val1&key2=val2"
    Returns dict of parsed parameters.
    """
    from urllib.parse import parse_qs
    result = {}
    if not query_string:
        return result
    parsed = parse_qs(query_string)
    for key, values in parsed.items():
        result[key] = values[0] if values else None
    return result


@router.post(
    "/rugcheck-analysis",
    responses={
        200: {"description": "Rugcheck analysis complete"},
        400: {"description": "Invalid contract address"},
        404: {"description": "Token not found"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
    summary="Analyze token for rugpull risk (APIX POST)",
    description="POST endpoint for APIX x402 marketplace tool calls. Send mint_address in JSON body.",
)
@limiter.limit("60/minute")
async def post_rugcheck_analysis(
    request: Request,
):
    """APIX-compatible POST endpoint for rugcheck analysis"""
    import json

    # Log everything APIX sends for debugging
    logger.info(f"POST DEBUG - Headers: {dict(request.headers)}")
    logger.info(f"POST DEBUG - Query params: {dict(request.query_params)}")

    token_address = None

    # Try to get mint_address from body
    try:
        body_bytes = await request.body()
        logger.info(f"POST DEBUG - Raw body: {body_bytes}")
        if body_bytes:
            body_json = json.loads(body_bytes)
            logger.info(f"POST DEBUG - Parsed body: {body_json}")
            if isinstance(body_json, dict):
                # Method 1: Direct field access (standard JSON body)
                token_address = body_json.get("mint_address") or body_json.get("contract")

                # Method 2: APIX sends {"query": "mint_address=VALUE"} format
                if not token_address and "query" in body_json:
                    query_string = body_json.get("query", "")
                    logger.info(f"POST DEBUG - Parsing APIX query field: {query_string}")
                    parsed_query = parse_apix_query_field(query_string)
                    logger.info(f"POST DEBUG - Parsed query params: {parsed_query}")
                    token_address = parsed_query.get("mint_address") or parsed_query.get("contract")
    except Exception as e:
        logger.warning(f"POST DEBUG - Body parse error: {e}")

    # Also check URL query params as fallback
    if not token_address:
        token_address = request.query_params.get("mint_address") or request.query_params.get("contract")

    if not token_address:
        # Check APIX JWT for diagnosis
        apix_diag = check_apix_configuration(request)
        if apix_diag:
            logger.error(f"APIX POST MISCONFIGURATION: {apix_diag}")

        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "message": "POST /rugcheck-analysis - send JSON body with mint_address field",
                "example": {"mint_address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"},
                "apix_diagnosis": apix_diag
            }
        )

    logger.info(f"POST - Analyzing token: {token_address}")
    return await _generate_rugcheck(token_address, "json")


@router.get(
    "/rugcheck-analysis/{contract}",
    response_model=RugcheckResponse,
    responses={
        200: {"description": "Rugcheck analysis complete"},
        400: {"description": "Invalid contract address"},
        404: {"description": "Token not found"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
    summary="Analyze token for rugpull risk (APIX PATH)",
    description="PATH parameter endpoint - contract address is part of URL",
)
@limiter.limit("60/minute")
async def get_rugcheck_analysis_path(
    request: Request,
    contract: str,
) -> RugcheckResponse:
    """APIX-compatible PATH parameter endpoint for rugcheck analysis"""
    return await _generate_rugcheck(contract, "json")


@router.get(
    "/rugcheck-analysis",
    responses={
        200: {"description": "Rugcheck analysis complete"},
        400: {"description": "Invalid contract address"},
        404: {"description": "Token not found"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
    summary="Analyze token for rugpull risk (APIX GET)",
    description="GET endpoint for APIX x402 marketplace tool calls",
)
@limiter.limit("60/minute")
async def get_rugcheck_analysis(
    request: Request,
    contract: str = Query(None, description="Solana token mint address (base58 format)"),
    mint_address: str = Query(None, description="Alias for contract parameter"),
    format: Literal["json", "text"] = Query(default="json", description="Response format"),
):
    """APIX-compatible GET endpoint for rugcheck analysis"""
    # Log EVERYTHING for debugging
    logger.info(f"APIX DEBUG - Headers: {dict(request.headers)}")
    logger.info(f"APIX DEBUG - Query params: {dict(request.query_params)}")
    logger.info(f"APIX DEBUG - Path params: {request.path_params}")

    # Try to get body even for GET request (some systems do this)
    try:
        body_bytes = await request.body()
        if body_bytes:
            logger.info(f"APIX DEBUG - Body: {body_bytes.decode()}")
            import json
            try:
                body_json = json.loads(body_bytes)
                if isinstance(body_json, dict):
                    # Try to extract contract from body
                    if not contract:
                        contract = body_json.get("contract") or body_json.get("mint_address")
            except json.JSONDecodeError:
                pass
    except Exception as e:
        logger.warning(f"Could not read body: {e}")

    # Accept both 'contract' and 'mint_address' parameters
    token_address = contract or mint_address

    if not token_address:
        # Check if this is an APIX request with misconfiguration
        apix_diag = check_apix_configuration(request)
        if apix_diag:
            logger.error(f"APIX MISCONFIGURATION: {apix_diag}")
            return JSONResponse(
                status_code=200,
                content={
                    "error": "APIX_CONFIGURATION_ERROR",
                    "message": "The APIX tool is not passing the 'contract' parameter. The tool registration needs to be updated.",
                    "diagnosis": apix_diag,
                    "solution": "Re-register the APIX tool and ensure 'contract' is configured as a required query parameter extracted from user input."
                }
            )

        # Regular request without token
        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "message": "Rugcheck Analysis API - provide 'contract' parameter with a Solana token mint address",
                "example": "/rugcheck-analysis?contract=DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
                "parameters": {
                    "contract": "Solana token mint address (required)",
                    "format": "json or text (optional, default: json)"
                }
            }
        )
    return await _generate_rugcheck(token_address, format)
