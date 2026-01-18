"""
Threat Intelligence Provider Interface and Implementations.

This module provides an extensible framework for integrating threat intelligence
providers to enrich security findings with additional context.

Design Status: PLACEHOLDER - No actual API integrations yet.

Future providers could include:
- AlienVault OTX
- VirusTotal
- Shodan
- GreyNoise
- AbuseIPDB
- CrowdStrike Falcon
- MISP

Usage:
    from threat_intel_providers import get_provider_registry

    registry = get_provider_registry()
    for provider in registry.get_enabled_providers():
        result = provider.enrich_finding(finding)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ThreatCategory(str, Enum):
    """Categories of threats from intelligence sources."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    SCANNER = "scanner"
    BRUTEFORCE = "bruteforce"
    EXPLOIT = "exploit"
    C2 = "command_and_control"
    APT = "apt"
    RANSOMWARE = "ransomware"
    CRYPTOMINER = "cryptominer"
    DATA_THEFT = "data_theft"
    UNKNOWN = "unknown"


class ThreatConfidence(str, Enum):
    """Confidence levels for threat intelligence."""

    HIGH = "high"  # Multiple sources, recent data
    MEDIUM = "medium"  # Single source or older data
    LOW = "low"  # Weak indicators or very old data
    UNKNOWN = "unknown"


@dataclass
class ThreatIndicator:
    """An individual threat indicator from an intelligence source."""

    indicator_type: str  # e.g., "ip", "domain", "hash", "url"
    indicator_value: str
    categories: list[ThreatCategory] = field(default_factory=list)
    confidence: ThreatConfidence = ThreatConfidence.UNKNOWN
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    source: str = ""
    reference_url: str | None = None


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence enrichment query."""

    provider_name: str
    query_time: datetime
    found: bool = False
    indicators: list[ThreatIndicator] = field(default_factory=list)
    risk_score_delta: float = 0.0  # Adjustment to base risk score
    categories: list[ThreatCategory] = field(default_factory=list)
    confidence: ThreatConfidence = ThreatConfidence.UNKNOWN
    related_campaigns: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    raw_response: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        """Convert result to dictionary for JSON storage."""
        return {
            "provider_name": self.provider_name,
            "query_time": self.query_time.isoformat(),
            "found": self.found,
            "indicators": [
                {
                    "indicator_type": i.indicator_type,
                    "indicator_value": i.indicator_value,
                    "categories": [c.value for c in i.categories],
                    "confidence": i.confidence.value,
                    "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                    "last_seen": i.last_seen.isoformat() if i.last_seen else None,
                    "tags": i.tags,
                    "source": i.source,
                    "reference_url": i.reference_url,
                }
                for i in self.indicators
            ],
            "risk_score_delta": self.risk_score_delta,
            "categories": [c.value for c in self.categories],
            "confidence": self.confidence.value,
            "related_campaigns": self.related_campaigns,
            "mitre_techniques": self.mitre_techniques,
            "error": self.error,
        }


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    def __init__(self, api_key: str | None = None, config: dict | None = None):
        """
        Initialize the provider.

        Args:
            api_key: Optional API key for the provider
            config: Optional additional configuration
        """
        self.api_key = api_key
        self.config = config or {}
        self._enabled = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name."""
        pass

    @property
    @abstractmethod
    def supported_indicator_types(self) -> list[str]:
        """Return list of supported indicator types (ip, domain, hash, etc.)."""
        pass

    @abstractmethod
    async def enrich_finding(self, finding: dict) -> ThreatIntelResult:
        """
        Enrich a security finding with threat intelligence.

        Args:
            finding: The finding dictionary to enrich

        Returns:
            ThreatIntelResult with enrichment data
        """
        pass

    @abstractmethod
    async def lookup_indicator(
        self, indicator_type: str, indicator_value: str
    ) -> ThreatIntelResult:
        """
        Look up a specific indicator.

        Args:
            indicator_type: Type of indicator (ip, domain, hash, url)
            indicator_value: The indicator value to look up

        Returns:
            ThreatIntelResult with lookup data
        """
        pass

    def is_enabled(self) -> bool:
        """Check if the provider is enabled and configured."""
        return self._enabled

    def enable(self) -> None:
        """Enable the provider."""
        self._enabled = True

    def disable(self) -> None:
        """Disable the provider."""
        self._enabled = False


class PlaceholderProvider(ThreatIntelProvider):
    """
    Placeholder provider for design demonstration.

    This provider does not make any actual API calls. It serves as a template
    for implementing real threat intelligence integrations.
    """

    @property
    def name(self) -> str:
        return "placeholder"

    @property
    def supported_indicator_types(self) -> list[str]:
        return ["ip", "domain", "hash", "url"]

    async def enrich_finding(self, finding: dict) -> ThreatIntelResult:
        """
        Return placeholder enrichment data.

        In a real implementation, this would:
        1. Extract relevant indicators from the finding (IPs, domains, hashes)
        2. Query the threat intel API for each indicator
        3. Aggregate and return the results
        """
        return ThreatIntelResult(
            provider_name=self.name,
            query_time=datetime.utcnow(),
            found=False,
            error="Placeholder provider - no actual enrichment performed. "
            "Configure a real threat intel provider for enrichment.",
        )

    async def lookup_indicator(
        self, indicator_type: str, indicator_value: str
    ) -> ThreatIntelResult:
        """Return placeholder lookup data."""
        return ThreatIntelResult(
            provider_name=self.name,
            query_time=datetime.utcnow(),
            found=False,
            indicators=[
                ThreatIndicator(
                    indicator_type=indicator_type,
                    indicator_value=indicator_value,
                    categories=[],
                    confidence=ThreatConfidence.UNKNOWN,
                    source=self.name,
                )
            ],
            error="Placeholder provider - no actual lookup performed.",
        )


class ProviderRegistry:
    """Registry for managing threat intelligence providers."""

    def __init__(self):
        self._providers: dict[str, ThreatIntelProvider] = {}
        # Register the placeholder provider by default
        self.register(PlaceholderProvider())

    def register(self, provider: ThreatIntelProvider) -> None:
        """Register a provider."""
        self._providers[provider.name] = provider

    def unregister(self, name: str) -> None:
        """Unregister a provider."""
        self._providers.pop(name, None)

    def get(self, name: str) -> ThreatIntelProvider | None:
        """Get a provider by name."""
        return self._providers.get(name)

    def get_all(self) -> list[ThreatIntelProvider]:
        """Get all registered providers."""
        return list(self._providers.values())

    def get_enabled(self) -> list[ThreatIntelProvider]:
        """Get all enabled providers."""
        return [p for p in self._providers.values() if p.is_enabled()]

    def list_names(self) -> list[str]:
        """List all registered provider names."""
        return list(self._providers.keys())


# Global registry instance
_registry: ProviderRegistry | None = None


def get_provider_registry() -> ProviderRegistry:
    """Get the global provider registry."""
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry


def extract_indicators_from_finding(finding: dict) -> list[tuple[str, str]]:
    """
    Extract potential threat indicators from a finding.

    Args:
        finding: The finding dictionary

    Returns:
        List of (indicator_type, indicator_value) tuples
    """
    import re

    indicators = []

    # Common fields to search
    text_fields = [
        finding.get("description", ""),
        finding.get("poc_evidence", ""),
        finding.get("remediation", ""),
        finding.get("resource_id", ""),
    ]

    full_text = " ".join(str(f) for f in text_fields if f)

    # IP address pattern
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    for match in re.findall(ip_pattern, full_text):
        # Exclude private IPs using ipaddress module for accurate RFC 1918 detection
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(match)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                indicators.append(("ip", match))
        except ValueError:
            # Invalid IP, skip
            pass

    # Domain pattern (simplified)
    domain_pattern = r"\b[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}\b"
    for match in re.findall(domain_pattern, full_text):
        # Exclude common AWS/Azure/GCP domains
        if not any(
            exc in match.lower()
            for exc in [
                "amazonaws.com",
                "azure.com",
                "microsoft.com",
                "google.com",
                "googleapis.com",
            ]
        ):
            indicators.append(("domain", match.lower()))

    # SHA256 hash pattern
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
    for match in re.findall(sha256_pattern, full_text):
        indicators.append(("hash", match.lower()))

    # MD5 hash pattern
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    for match in re.findall(md5_pattern, full_text):
        indicators.append(("hash", match.lower()))

    return list(set(indicators))  # Deduplicate


if __name__ == "__main__":
    # Design demonstration
    import asyncio

    async def demo():
        print("Threat Intelligence Provider Framework - Design Demo")
        print("=" * 60)

        # Get the registry
        registry = get_provider_registry()

        print(f"\nRegistered providers: {registry.list_names()}")

        # Get the placeholder provider
        provider = registry.get("placeholder")
        if provider:
            print(f"\nProvider: {provider.name}")
            print(f"Supported types: {provider.supported_indicator_types}")
            print(f"Enabled: {provider.is_enabled()}")

            # Test lookup
            result = await provider.lookup_indicator("ip", "1.2.3.4")
            print(f"\nLookup result: {result.to_dict()}")

        # Test indicator extraction
        test_finding = {
            "description": "Found exposed API key communicating with 203.0.113.50",
            "poc_evidence": "Hash: abcd1234" * 8,  # 64 char hash
            "resource_id": "suspicious.example.com",
        }
        indicators = extract_indicators_from_finding(test_finding)
        print(f"\nExtracted indicators: {indicators}")

    asyncio.run(demo())
