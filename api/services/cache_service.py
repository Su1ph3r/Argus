"""
Cache Service for Nubicustos

Provides TTL-based caching for expensive operations like compliance score calculations.
Uses cachetools for in-memory caching with automatic expiration.

Features:
- Configurable TTL per cache type
- Thread-safe operations
- Automatic cache invalidation on scan completion
- Cache statistics for monitoring
"""

import hashlib
import logging
import threading
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Any, TypeVar

from cachetools import TTLCache

logger = logging.getLogger(__name__)

# Type variable for generic cache function
T = TypeVar("T")


class CacheConfig:
    """Configuration for cache TTLs (in seconds)."""

    # Compliance scores: 1 hour TTL (expensive calculations)
    COMPLIANCE_SCORE_TTL = 3600

    # Framework comparison: 1 hour TTL
    COMPLIANCE_COMPARISON_TTL = 3600

    # Credential status: 5 minutes TTL (can change frequently)
    CREDENTIAL_STATUS_TTL = 300

    # Asset data: 30 minutes TTL
    ASSET_DATA_TTL = 1800

    # Blast radius: 15 minutes TTL
    BLAST_RADIUS_TTL = 900

    # Attack path confidence: 30 minutes TTL
    ATTACK_PATH_CONFIDENCE_TTL = 1800

    # Default TTL for unspecified caches
    DEFAULT_TTL = 3600

    # Maximum items per cache
    MAX_SIZE = 1000


class CacheService:
    """
    Thread-safe caching service with TTL support.

    Provides multiple cache instances for different data types,
    each with its own TTL and size limits.
    """

    def __init__(self):
        self._lock = threading.RLock()

        # Initialize caches for different data types
        self._caches: dict[str, TTLCache] = {
            "compliance_scores": TTLCache(
                maxsize=CacheConfig.MAX_SIZE,
                ttl=CacheConfig.COMPLIANCE_SCORE_TTL,
            ),
            "compliance_comparison": TTLCache(
                maxsize=CacheConfig.MAX_SIZE,
                ttl=CacheConfig.COMPLIANCE_COMPARISON_TTL,
            ),
            "credential_status": TTLCache(
                maxsize=100,
                ttl=CacheConfig.CREDENTIAL_STATUS_TTL,
            ),
            "asset_data": TTLCache(
                maxsize=CacheConfig.MAX_SIZE,
                ttl=CacheConfig.ASSET_DATA_TTL,
            ),
            "blast_radius": TTLCache(
                maxsize=CacheConfig.MAX_SIZE,
                ttl=CacheConfig.BLAST_RADIUS_TTL,
            ),
            "attack_path_confidence": TTLCache(
                maxsize=CacheConfig.MAX_SIZE,
                ttl=CacheConfig.ATTACK_PATH_CONFIDENCE_TTL,
            ),
        }

        # Cache statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "invalidations": 0,
            "last_invalidation": None,
        }

    def _generate_key(self, *args, **kwargs) -> str:
        """Generate a cache key from arguments."""
        key_parts = [str(arg) for arg in args]
        key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()

    def get(self, cache_name: str, key: str) -> Any | None:
        """
        Get a value from cache.

        Args:
            cache_name: Name of the cache to query
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            cache = self._caches.get(cache_name)
            if cache is None:
                return None

            value = cache.get(key)
            if value is not None:
                self._stats["hits"] += 1
                logger.debug(f"Cache hit: {cache_name}:{key[:8]}...")
            else:
                self._stats["misses"] += 1
                logger.debug(f"Cache miss: {cache_name}:{key[:8]}...")

            return value

    def set(self, cache_name: str, key: str, value: Any) -> None:
        """
        Set a value in cache.

        Args:
            cache_name: Name of the cache
            key: Cache key
            value: Value to cache
        """
        with self._lock:
            cache = self._caches.get(cache_name)
            if cache is None:
                # Create a new cache with default TTL if it doesn't exist
                cache = TTLCache(
                    maxsize=CacheConfig.MAX_SIZE,
                    ttl=CacheConfig.DEFAULT_TTL,
                )
                self._caches[cache_name] = cache

            cache[key] = value
            logger.debug(f"Cache set: {cache_name}:{key[:8]}...")

    def delete(self, cache_name: str, key: str) -> bool:
        """
        Delete a specific key from cache.

        Args:
            cache_name: Name of the cache
            key: Cache key

        Returns:
            True if key was deleted, False if not found
        """
        with self._lock:
            cache = self._caches.get(cache_name)
            if cache is None:
                return False

            if key in cache:
                del cache[key]
                self._stats["invalidations"] += 1
                return True
            return False

    def invalidate_cache(self, cache_name: str) -> int:
        """
        Invalidate all entries in a specific cache.

        Args:
            cache_name: Name of the cache to invalidate

        Returns:
            Number of entries invalidated
        """
        with self._lock:
            cache = self._caches.get(cache_name)
            if cache is None:
                return 0

            count = len(cache)
            cache.clear()
            self._stats["invalidations"] += count
            self._stats["last_invalidation"] = datetime.utcnow()
            logger.info(f"Invalidated {count} entries from cache: {cache_name}")
            return count

    def invalidate_all(self) -> int:
        """
        Invalidate all caches.

        Returns:
            Total number of entries invalidated
        """
        total = 0
        with self._lock:
            for cache_name in list(self._caches.keys()):
                total += self.invalidate_cache(cache_name)
        return total

    def invalidate_on_scan_completion(self, scan_id: str | None = None) -> int:
        """
        Invalidate caches that should be refreshed after scan completion.

        Args:
            scan_id: Optional scan ID for targeted invalidation

        Returns:
            Number of entries invalidated
        """
        # Caches to invalidate after scan
        caches_to_invalidate = [
            "compliance_scores",
            "compliance_comparison",
            "blast_radius",
            "attack_path_confidence",
        ]

        total = 0
        for cache_name in caches_to_invalidate:
            total += self.invalidate_cache(cache_name)

        logger.info(f"Scan completion invalidation: {total} entries cleared")
        return total

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            cache_sizes = {name: len(cache) for name, cache in self._caches.items()}
            hit_rate = 0.0
            total_requests = self._stats["hits"] + self._stats["misses"]
            if total_requests > 0:
                hit_rate = self._stats["hits"] / total_requests

            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "hit_rate": round(hit_rate, 3),
                "invalidations": self._stats["invalidations"],
                "last_invalidation": self._stats["last_invalidation"],
                "cache_sizes": cache_sizes,
                "total_cached_items": sum(cache_sizes.values()),
            }


# Singleton instance
_cache_service: CacheService | None = None
_cache_lock = threading.Lock()


def get_cache_service() -> CacheService:
    """Get or create the cache service singleton."""
    global _cache_service
    if _cache_service is None:
        with _cache_lock:
            if _cache_service is None:
                _cache_service = CacheService()
    return _cache_service


def cached(cache_name: str, key_func: Callable[..., str] | None = None):
    """
    Decorator for caching function results.

    Args:
        cache_name: Name of the cache to use
        key_func: Optional function to generate cache key from args/kwargs.
                  If None, uses default key generation from all args.

    Usage:
        @cached("compliance_scores")
        def calculate_compliance_score(scan_id: str, framework: str):
            ...

        @cached("blast_radius", key_func=lambda finding_id: str(finding_id))
        def get_blast_radius(finding_id: int):
            ...
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            cache = get_cache_service()

            # Generate cache key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                key = cache._generate_key(*args, **kwargs)

            # Try to get from cache
            result = cache.get(cache_name, key)
            if result is not None:
                return result

            # Calculate and cache result
            result = func(*args, **kwargs)
            cache.set(cache_name, key, result)
            return result

        # Add method to bypass cache
        def no_cache(*args, **kwargs) -> T:
            return func(*args, **kwargs)

        wrapper.no_cache = no_cache
        return wrapper

    return decorator


def async_cached(cache_name: str, key_func: Callable[..., str] | None = None):
    """
    Async version of the cached decorator.

    Args:
        cache_name: Name of the cache to use
        key_func: Optional function to generate cache key from args/kwargs

    Usage:
        @async_cached("compliance_scores")
        async def calculate_compliance_score(scan_id: str, framework: str):
            ...
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            cache = get_cache_service()

            # Generate cache key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                key = cache._generate_key(*args, **kwargs)

            # Try to get from cache
            result = cache.get(cache_name, key)
            if result is not None:
                return result

            # Calculate and cache result
            result = await func(*args, **kwargs)
            cache.set(cache_name, key, result)
            return result

        # Add method to bypass cache
        async def no_cache(*args, **kwargs) -> T:
            return await func(*args, **kwargs)

        wrapper.no_cache = no_cache
        return wrapper

    return decorator
