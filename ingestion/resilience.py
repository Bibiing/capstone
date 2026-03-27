"""
Resilience patterns for Wazuh API integration.

Implements:
- Exponential backoff with jitter
- Circuit breaker pattern
- Retry logic with configurable strategies
- Idempotency tracking

Design goals:
- Prevent cascading failures
- Graceful degradation under load
- Production-ready error handling
- Observability via logging
"""

import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Fail fast, don't try
    HALF_OPEN = "half_open"  # Test if service recovered


@dataclass
class RetryConfig:
    """Retry Strategy Configuration."""
    max_attempts: int = 3
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.1  # ±10% random jitter
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for exponential backoff with jitter."""
        # Exponential: delay = initial * (multiplier ^ attempt)
        exponential_delay = self.initial_delay_seconds * (self.backoff_multiplier ** attempt)
        
        # Cap at max
        delay = min(exponential_delay, self.max_delay_seconds)
        
        # Add jitter: ±jitter_factor%
        jitter = delay * self.jitter_factor * (2 * random.random() - 1)
        
        return max(0, delay + jitter)


@dataclass
class CircuitBreakerConfig:
    """Circuit Breaker Configuration."""
    failure_threshold: int = 5  # Failures before opening circuit
    success_threshold: int = 2  # Successes before closing (from half-open)
    timeout_seconds: int = 60   # Time before trying to recover from OPEN
    

@dataclass
class CircuitBreaker:
    """Circuit breaker for fault tolerance."""
    name: str
    config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    
    # State tracking
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def record_success(self) -> None:
        """Record successful call."""
        self.failure_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                logger.info(
                    "Circuit breaker closed | name=%s | successes=%d",
                    self.name,
                    self.success_count,
                )
                self.state = CircuitState.CLOSED
                self.success_count = 0
                self.last_state_change = datetime.now(timezone.utc)
    
    def record_failure(self) -> None:
        """Record failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)
        
        if self.failure_count >= self.config.failure_threshold:
            logger.warning(
                "Circuit breaker opened | name=%s | failures=%d",
                self.name,
                self.failure_count,
            )
            self.state = CircuitState.OPEN
            self.last_state_change = datetime.now(timezone.utc)
    
    def can_attempt(self) -> bool:
        """Check if call should be attempted."""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if timeout expired
            now = datetime.now(timezone.utc)
            if self.last_state_change + timedelta(seconds=self.config.timeout_seconds) <= now:
                logger.info("Circuit breaker entering half-open | name=%s", self.name)
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                return True
            return False
        
        # HALF_OPEN: allow attempts
        return True
    
    def __repr__(self) -> str:
        return (
            f"CircuitBreaker(name={self.name!r}, state={self.state.value}, "
            f"failures={self.failure_count}, successes={self.success_count})"
        )


def retry_with_backoff(config: Optional[RetryConfig] = None) -> Callable:
    """
    Decorator for retrying function with exponential backoff.
    
    Args:
        config: RetryConfig instance
        
    Usage:
        @retry_with_backoff(RetryConfig(max_attempts=3))
        def fetch_data():
            return wazuh_client.get_agents()
    """
    _config = config or RetryConfig()
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Optional[Exception] = None
            
            for attempt in range(_config.max_attempts):
                try:
                    result = func(*args, **kwargs)
                    if attempt > 0:
                        logger.info(
                            "Function succeeded after retries | func=%s | attempt=%d",
                            func.__name__,
                            attempt + 1,
                        )
                    return result
                    
                except Exception as exc:
                    last_exception = exc
                    
                    if attempt < _config.max_attempts - 1:
                        delay = _config.calculate_delay(attempt)
                        logger.warning(
                            "Function failed, retrying | func=%s | attempt=%d | delay=%.2fs | error=%s",
                            func.__name__,
                            attempt + 1,
                            delay,
                            str(exc),
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            "Function failed after all retries | func=%s | attempts=%d | error=%s",
                            func.__name__,
                            _config.max_attempts,
                            str(exc),
                        )
            
            raise last_exception  # type: ignore
        
        return wrapper
    
    return decorator


def with_circuit_breaker(circuit_breaker: CircuitBreaker) -> Callable:
    """
    Decorator to apply circuit breaker pattern.
    
    Args:
        circuit_breaker: CircuitBreaker instance
        
    Usage:
        breaker = CircuitBreaker("wazuh_api")
        
        @with_circuit_breaker(breaker)
        def fetch_data():
            return wazuh_client.get_agents()
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            if not circuit_breaker.can_attempt():
                raise RuntimeError(
                    f"Circuit breaker is {circuit_breaker.state.value} for {circuit_breaker.name}"
                )
            
            try:
                result = func(*args, **kwargs)
                circuit_breaker.record_success()
                return result
            except Exception as exc:
                circuit_breaker.record_failure()
                logger.error(
                    "Circuit breaker recorded failure | breaker=%s | error=%s",
                    circuit_breaker.name,
                    str(exc),
                )
                raise
        
        return wrapper
    
    return decorator


@dataclass
class IdempotencyKey:
    """Tracking for idempotent operations."""
    key: str
    operation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    result: Optional[Any] = None
    error: Optional[str] = None
    
    def is_expired(self, ttl_hours: int = 24) -> bool:
        """Check if idempotency key expired."""
        expiry = self.timestamp + timedelta(hours=ttl_hours)
        return datetime.now(timezone.utc) > expiry


class IdempotencyCache:
    """Simple in-memory cache for idempotent operations."""
    
    def __init__(self, ttl_hours: int = 24) -> None:
        self._cache: dict[str, IdempotencyKey] = {}
        self._ttl_hours = ttl_hours
    
    def get(self, key: str) -> Optional[IdempotencyKey]:
        """Retrieve cached result."""
        item = self._cache.get(key)
        if item and not item.is_expired(self._ttl_hours):
            return item
        # Clean up expired items
        if item:
            del self._cache[key]
        return None
    
    def set(
        self,
        key: str,
        operation: str,
        result: Any = None,
        error: Optional[str] = None,
    ) -> None:
        """Store operation result."""
        self._cache[key] = IdempotencyKey(
            key=key,
            operation=operation,
            result=result,
            error=error,
        )
        logger.debug("Idempotency key stored | key=%s", key)
    
    def clear_expired(self) -> int:
        """Remove expired items, return count."""
        to_delete = [
            key for key, item in self._cache.items()
            if item.is_expired(self._ttl_hours)
        ]
        for key in to_delete:
            del self._cache[key]
        return len(to_delete)
