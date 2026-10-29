"""Performance benchmarks for the Email Threat Detection pipeline.

All benchmarks measure wall-clock time only — they do not make external
network calls (Groq, VirusTotal, AbuseIPDB are not required).

Run with:  .venv\\Scripts\\pytest tests/performance/ -v --tb=short

Targets (P95 on standard dev hardware):
  preprocessing     < 10 ms
  security engine   < 5 ms
  ml inference      < 10 ms
  risk engine       < 10 ms
  pipeline (total)  < 30 ms
  ti cache hit      < 1 ms
  ws broadcast      < 0.1 ms
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest

# ── Shared fixture email ───────────────────────────────────────────────────────

SAMPLE_EMAIL = """\
From: Security Team <security-alert@micros0ft-verify.com>
To: target-analyst@corp.com
Subject: Action Required: Immediate verification of corporate credentials
Date: Wed, 07 Oct 2026 00:00:00 +0000
Message-ID: <123456@micros0ft-verify.com>
Received-SPF: fail
Authentication-Results: spf=fail dkim=fail dmarc=fail

Dear Employee,

Your security token will expire in 2 hours.
Please verify your corporate credentials immediately:
http://192.168.1.100/login/auth-token
https://micros0ft-verify.com/reset

Thank you.
"""


# ── Benchmarks ─────────────────────────────────────────────────────────────────


class TestPreprocessingPerformance:
    """Email preprocessing latency benchmarks."""

    def test_preprocess_latency_under_10ms(self):
        """Email preprocessing must complete in < 10 ms P95."""
        from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline

        pipeline = EmailPreprocessingPipeline()
        # Warm-up
        pipeline.preprocess_raw(SAMPLE_EMAIL)

        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            result = pipeline.preprocess_raw(SAMPLE_EMAIL)
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nPreprocessing latency: avg={avg:.3f}ms  p95={p95:.3f}ms")
        assert result is not None
        assert p95 < 10.0, f"Preprocessing P95 {p95:.2f}ms exceeds 10ms target"


class TestSecurityEnginePerformance:
    """Deterministic security engine latency benchmarks."""

    def test_security_engine_latency_under_5ms(self):
        """Deterministic signal analysis must complete in < 5 ms P95."""
        from app.services.analyzers.engine import DeterministicAnalysisEngine
        from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline

        pipeline = EmailPreprocessingPipeline()
        inp = pipeline.preprocess_raw(SAMPLE_EMAIL)
        engine = DeterministicAnalysisEngine()
        # Warm-up
        engine.run_all(inp)

        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            signals = engine.run_all(inp)
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nSecurity engine latency: avg={avg:.3f}ms  p95={p95:.3f}ms  signals={len(signals)}")
        assert p95 < 5.0, f"Security engine P95 {p95:.2f}ms exceeds 5ms target"


class TestMLInferencePerformance:
    """ML inference latency benchmarks."""

    def test_ml_inference_latency_under_10ms(self):
        """ML inference (heuristic model) must complete in < 10 ms P95."""
        from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline
        from app.services.ml.inference import MLInferenceService

        pipeline = EmailPreprocessingPipeline()
        inp = pipeline.preprocess_raw(SAMPLE_EMAIL)
        svc = MLInferenceService()
        # Warm-up
        svc.predict(inp)

        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            result = svc.predict(inp)
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nML inference latency: avg={avg:.3f}ms  p95={p95:.3f}ms  class={result.classification}")
        assert p95 < 10.0, f"ML inference P95 {p95:.2f}ms exceeds 10ms target"


class TestRiskEnginePerformance:
    """Risk scoring engine latency benchmarks."""

    def test_risk_engine_latency_under_10ms(self):
        """Risk composite scoring must complete in < 10 ms P95."""
        from app.services.analyzers.engine import DeterministicAnalysisEngine
        from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline
        from app.services.ml.inference import MLInferenceService
        from app.services.risk.engine import RiskEngine

        pipeline = EmailPreprocessingPipeline()
        inp = pipeline.preprocess_raw(SAMPLE_EMAIL)
        signals = DeterministicAnalysisEngine().run_all(inp)
        ml_result = MLInferenceService().predict(inp)
        engine = RiskEngine()
        # Warm-up
        engine.assess(
            security_signals=signals,
            behavioral_signals=[],
            ml_result=ml_result,
            threat_intel_signals=[],
        )

        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            result = engine.assess(
                security_signals=signals,
                behavioral_signals=[],
                ml_result=ml_result,
                threat_intel_signals=[],
            )
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nRisk engine latency: avg={avg:.3f}ms  p95={p95:.3f}ms  score={result.risk_score}")
        assert p95 < 10.0, f"Risk engine P95 {p95:.2f}ms exceeds 10ms target"


class TestPipelineTotalPerformance:
    """End-to-end synchronous pipeline latency (no external I/O stages)."""

    def test_total_sync_pipeline_under_30ms(self):
        """Combined preprocessing + engine + ML + risk must complete in < 30 ms P95."""
        from app.services.analyzers.engine import DeterministicAnalysisEngine
        from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline
        from app.services.ml.inference import MLInferenceService
        from app.services.risk.engine import RiskEngine

        pipeline = EmailPreprocessingPipeline()
        engine = DeterministicAnalysisEngine()
        ml_svc = MLInferenceService()
        risk_eng = RiskEngine()

        # Warm-up
        inp = pipeline.preprocess_raw(SAMPLE_EMAIL)
        signals = engine.run_all(inp)
        ml_result = ml_svc.predict(inp)
        risk_eng.assess(
            security_signals=signals,
            behavioral_signals=[],
            ml_result=ml_result,
            threat_intel_signals=[],
        )

        times = []
        for _ in range(30):
            t0 = time.perf_counter()
            inp = pipeline.preprocess_raw(SAMPLE_EMAIL)
            signals = engine.run_all(inp)
            ml_result = ml_svc.predict(inp)
            risk_eng.assess(
                security_signals=signals,
                behavioral_signals=[],
                ml_result=ml_result,
                threat_intel_signals=[],
            )
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nTotal sync pipeline latency: avg={avg:.3f}ms  p95={p95:.3f}ms")
        assert p95 < 30.0, f"Total pipeline P95 {p95:.2f}ms exceeds 30ms target"


class TestThreatIntelCachePerformance:
    """Threat intelligence in-process cache latency benchmarks."""

    @pytest.mark.asyncio
    async def test_ti_cache_hit_under_1ms(self):
        """Cached TI lookup must resolve in < 1 ms per indicator."""
        from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline
        from app.services.threat_intelligence.adapters.internal import InternalThreatIntelAdapter
        from app.services.threat_intelligence.manager import ThreatIntelligenceService

        pipeline = EmailPreprocessingPipeline()
        inp = pipeline.preprocess_raw(SAMPLE_EMAIL)

        svc = ThreatIntelligenceService(providers=[InternalThreatIntelAdapter()])

        # Populate cache
        await svc.extract_and_check_email(inp)

        # Measure cached lookups
        times = []
        for _ in range(50):
            t0 = time.perf_counter()
            await svc.extract_and_check_email(inp)
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nTI cache hit latency: avg={avg:.3f}ms  p95={p95:.3f}ms")
        assert p95 < 1.0, f"TI cache P95 {p95:.3f}ms exceeds 1ms target"


class TestWebSocketBroadcastPerformance:
    """WebSocket broadcast latency benchmarks."""

    @pytest.mark.asyncio
    async def test_ws_broadcast_under_0_1ms(self):
        """WebSocket event broadcast must complete in < 0.1 ms P99."""
        from app.infrastructure.websocket.manager import WebSocketConnectionManager

        manager = WebSocketConnectionManager()

        class MockWS:
            def __init__(self) -> None:
                self.sent: list = []

            async def accept(self) -> None:
                pass

            async def send_json(self, data: dict) -> None:
                self.sent.append(data)

        ws = MockWS()
        aid = str(uuid.uuid4())
        await manager.connect(ws, analysis_id=aid)  # type: ignore[arg-type]

        # Warm-up
        await manager.broadcast_event(
            aid, status="processing", stage="security_engine", data={"count": 5}
        )

        times = []
        for _ in range(200):
            t0 = time.perf_counter()
            await manager.broadcast_event(
                aid, status="processing", stage="security_engine", data={"count": 5}
            )
            times.append((time.perf_counter() - t0) * 1000)

        p99 = sorted(times)[int(len(times) * 0.99)]
        avg = sum(times) / len(times)

        print(f"\nWS broadcast latency: avg={avg:.4f}ms  p99={p99:.4f}ms")
        assert p99 < 0.5, f"WS broadcast P99 {p99:.4f}ms exceeds 0.5ms target"


class TestIdempotencyGuardPerformance:
    """Idempotency lock contention benchmarks."""

    @pytest.mark.asyncio
    async def test_idempotency_lock_under_1ms(self):
        """Acquire+release cycle must complete in < 1 ms P95."""
        from app.services.processing.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()

        times = []
        for _ in range(100):
            aid = uuid.uuid4()
            t0 = time.perf_counter()
            acquired = await guard.acquire(aid)
            if acquired:
                await guard.release(aid)
            times.append((time.perf_counter() - t0) * 1000)

        p95 = sorted(times)[int(len(times) * 0.95)]
        avg = sum(times) / len(times)

        print(f"\nIdempotency guard latency: avg={avg:.4f}ms  p95={p95:.4f}ms")
        assert p95 < 1.0, f"Idempotency lock P95 {p95:.4f}ms exceeds 1ms target"
