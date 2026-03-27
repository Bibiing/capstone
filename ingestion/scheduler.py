"""
Pipeline Scheduler - Automated orchestration.

Runs ingestion pipeline on a schedule:
- Default: Every hour (configurable)
- Manual triggers available
- Health monitoring
- Error recovery with exponential backoff

Design:
- Background scheduler thread
- Graceful shutdown
- State persistence (last run, last error, status)
- Idempotency (prevents overlapping runs)
"""

import asyncio
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional

from ingestion.pipeline import IngestionPipeline, PipelineStats

logger = logging.getLogger(__name__)


class SchedulerStatus(str, Enum):
    """Scheduler state."""
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    PAUSED = "paused"


@dataclass
class SchedulerConfig:
    """Scheduler configuration."""
    interval_seconds: int = 3600  # 1 hour default
    max_retries: int = 3
    retry_backoff_seconds: int = 60
    error_threshold: int = 5  # Pause after 5 consecutive errors
    timeout_seconds: int = 600  # 10 minute timeout for full cycle


@dataclass
class SchedulerState:
    """Scheduler runtime state."""
    status: SchedulerStatus = SchedulerStatus.IDLE
    last_run_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_errors: int = 0
    total_runs: int = 0
    total_errors: int = 0
    last_stats: Optional[PipelineStats] = None
    is_running: bool = False
    start_time: Optional[datetime] = None
    
    def reset_errors(self) -> None:
        """Reset error counter on successful run."""
        self.consecutive_errors = 0
        self.last_error = None
        self.last_error_at = None


class PipelineScheduler:
    """
    Automated ingestion pipeline orchestrator.
    
    Runs pipeline on a schedule with error recovery.
    """
    
    def __init__(
        self,
        pipeline: Optional[IngestionPipeline] = None,
        config: Optional[SchedulerConfig] = None,
    ) -> None:
        self._pipeline = pipeline or IngestionPipeline()
        self._config = config or SchedulerConfig()
        self._state = SchedulerState()
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._scheduler_thread: Optional[threading.Thread] = None
    
    # ========== Control ==========
    
    def start(self) -> None:
        """Start the scheduler."""
        with self._lock:
            if self._scheduler_thread is not None:
                logger.warning("Scheduler already running")
                return
            
            logger.info(
                "Starting scheduler | interval=%ds | max_retries=%d",
                self._config.interval_seconds,
                self._config.max_retries,
            )
            
            self._event.clear()
            self._scheduler_thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="PipelineScheduler",
            )
            self._scheduler_thread.start()
    
    def stop(self) -> None:
        """Stop the scheduler gracefully."""
        with self._lock:
            if self._scheduler_thread is None:
                logger.warning("Scheduler not running")
                return
            
            logger.info("Stopping scheduler...")
            self._event.set()
        
        # Wait for thread to finish
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
            logger.info("Scheduler stopped")
    
    def pause(self) -> None:
        """Pause the scheduler (can be resumed)."""
        with self._lock:
            self._state.status = SchedulerStatus.PAUSED
            logger.info("Scheduler paused")
    
    def resume(self) -> None:
        """Resume a paused scheduler."""
        with self._lock:
            if self._state.status == SchedulerStatus.PAUSED:
                self._state.status = SchedulerStatus.IDLE
                logger.info("Scheduler resumed")
    
    def trigger_now(self, wait: bool = False) -> Optional[PipelineStats]:
        """
        Trigger pipeline execution immediately.
        
        Args:
            wait: Whether to block until execution completes
            
        Returns:
            PipelineStats if wait=True, else None
        """
        logger.info("Triggering manual pipeline run")
        
        if wait:
            return self._execute_pipeline()
        else:
            # Queue for next iteration
            threading.Thread(
                target=self._execute_pipeline,
                daemon=True,
                name="ManualTrigger",
            ).start()
            return None
    
    # ========== Execution ==========
    
    def _run_loop(self) -> None:
        """Main scheduler loop (runs in background thread)."""
        logger.info("Scheduler loop started")
        
        while not self._event.is_set():
            try:
                # Check pause
                if self._state.status == SchedulerStatus.PAUSED:
                    self._event.wait(timeout=30)
                    continue
                
                # Check error threshold
                if self._state.consecutive_errors >= self._config.error_threshold:
                    logger.error(
                        "Error threshold reached | consecutive_errors=%d | pausing scheduler",
                        self._state.consecutive_errors,
                    )
                    self._state.status = SchedulerStatus.ERROR
                    self._event.wait(timeout=300)  # Wait 5 min before retry
                    continue
                
                # Calculate next run time
                now = datetime.now(timezone.utc)
                
                if self._state.last_run_at is None:
                    # First run
                    should_run = True
                else:
                    # Check interval
                    elapsed = (now - self._state.last_run_at).total_seconds()
                    should_run = elapsed >= self._config.interval_seconds
                
                if should_run:
                    self._execute_pipeline_with_retry()
                
                # Sleep before next check
                self._event.wait(timeout=30)
                
            except Exception as exc:
                logger.error("Scheduler loop error | error=%s", str(exc), exc_info=True)
                self._event.wait(timeout=10)
        
        logger.info("Scheduler loop exited")
    
    def _execute_pipeline_with_retry(self) -> None:
        """Execute pipeline with retry logic."""
        attempt = 0
        
        while attempt < self._config.max_retries:
            try:
                stats = self._execute_pipeline()
                
                # Success
                with self._lock:
                    self._state.reset_errors()
                    self._state.last_success_at = datetime.now(timezone.utc)
                
                logger.info("Pipeline execution successful | stats=%s", stats)
                return
                
            except Exception as exc:
                attempt += 1
                
                if attempt < self._config.max_retries:
                    backoff = self._config.retry_backoff_seconds * (2 ** (attempt - 1))
                    logger.warning(
                        "Pipeline execution failed, retrying | attempt=%d/%d | "
                        "backoff=%ds | error=%s",
                        attempt,
                        self._config.max_retries,
                        backoff,
                        str(exc),
                    )
                    self._event.wait(timeout=backoff)
                else:
                    logger.error(
                        "Pipeline execution failed after retries | "
                        "attempts=%d | error=%s",
                        self._config.max_retries,
                        str(exc),
                    )
                    with self._lock:
                        self._state.consecutive_errors += 1
                        self._state.total_errors += 1
                        self._state.last_error = str(exc)
                        self._state.last_error_at = datetime.now(timezone.utc)
                    return
    
    def _execute_pipeline(self) -> Optional[PipelineStats]:
        """Execute the pipeline."""
        with self._lock:
            if self._state.is_running:
                logger.warning("Pipeline already running, skipping")
                return None
            
            self._state.is_running = True
            self._state.status = SchedulerStatus.RUNNING
            self._state.last_run_at = datetime.now(timezone.utc)
        
        try:
            logger.info("Executing pipeline cycle")
            stats = self._pipeline.execute_full_cycle()
            
            with self._lock:
                self._state.last_stats = stats
                self._state.total_runs += 1
            
            return stats
            
        except Exception as exc:
            logger.error("Pipeline execution error | error=%s", str(exc), exc_info=True)
            raise
            
        finally:
            with self._lock:
                self._state.is_running = False
                self._state.status = SchedulerStatus.IDLE
    
    # ========== State Access ==========
    
    def get_status(self) -> dict:
        """Get current scheduler status."""
        with self._lock:
            return {
                "status": self._state.status.value,
                "is_running": self._state.is_running,
                "total_runs": self._state.total_runs,
                "total_errors": self._state.total_errors,
                "consecutive_errors": self._state.consecutive_errors,
                "last_run_at": self._state.last_run_at.isoformat() if self._state.last_run_at else None,
                "last_success_at": self._state.last_success_at.isoformat() if self._state.last_success_at else None,
                "last_error_at": self._state.last_error_at.isoformat() if self._state.last_error_at else None,
                "last_error": self._state.last_error,
                "last_stats": dict(
                    timestamp=self._state.last_stats.timestamp.isoformat(),
                    duration_seconds=self._state.last_stats.duration_seconds,
                    assets_created=self._state.last_stats.assets_created,
                    assets_updated=self._state.last_stats.assets_updated,
                    alerts_fetched=self._state.last_stats.alerts_fetched,
                    sca_scans_fetched=self._state.last_stats.sca_scans_fetched,
                    risks_calculated=self._state.last_stats.risks_calculated,
                ) if self._state.last_stats else None,
                "config": {
                    "interval_seconds": self._config.interval_seconds,
                    "max_retries": self._config.max_retries,
                    "error_threshold": self._config.error_threshold,
                },
            }
    
    def get_health(self) -> dict:
        """Get health check data."""
        with self._lock:
            # Determine health status
            if self._state.status == SchedulerStatus.ERROR:
                health = "unhealthy"
            elif self._state.status == SchedulerStatus.PAUSED:
                health = "paused"
            elif self._state.consecutive_errors >= 2:
                health = "degraded"
            else:
                health = "healthy"
            
            # Time since last success
            if self._state.last_success_at:
                time_since_success = (
                    datetime.now(timezone.utc) - self._state.last_success_at
                ).total_seconds()
            else:
                time_since_success = None
            
            return {
                "health": health,
                "scheduler_status": self._state.status.value,
                "is_running": self._state.is_running,
                "seconds_since_last_success": time_since_success,
                "total_runs": self._state.total_runs,
                "consecutive_errors": self._state.consecutive_errors,
                "error_threshold": self._config.error_threshold,
            }


# Global scheduler instance
_scheduler_instance: Optional[PipelineScheduler] = None
_scheduler_lock = threading.Lock()


def get_scheduler() -> PipelineScheduler:
    """Get or create global scheduler instance."""
    global _scheduler_instance
    
    if _scheduler_instance is None:
        with _scheduler_lock:
            if _scheduler_instance is None:
                _scheduler_instance = PipelineScheduler()
    
    return _scheduler_instance


if __name__ == "__main__":
    import sys
    import time
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    
    print("=" * 70)
    print("  Pipeline Scheduler - Demo")
    print("=" * 70)
    
    # Create scheduler with short interval for demo
    config = SchedulerConfig(interval_seconds=10)
    scheduler = PipelineScheduler(config=config)
    
    try:
        scheduler.start()
        print("\n✓ Scheduler started (interval: 10s)")
        print("  Press Ctrl+C to stop\n")
        
        # Demo: trigger manually after 2 seconds
        time.sleep(2)
        print("  → Triggering manual run...")
        scheduler.trigger_now()
        
        # Keep running
        while True:
            time.sleep(5)
            status = scheduler.get_status()
            print(f"  Status: {status['status']} | Runs: {status['total_runs']} | "
                  f"Errors: {status['total_errors']}")
        
    except KeyboardInterrupt:
        print("\n✓ Shutting down...")
        scheduler.stop()
        print("  Scheduler stopped")
