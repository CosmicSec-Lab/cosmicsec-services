"""Phase 4 predictive security helpers for zero-day risk forecasting."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from statistics import mean
from typing import Dict, List


@dataclass
class PredictorState:
    trained: bool = False
    baseline_cvss: float = 5.0
    baseline_exploitability: float = 0.3
    sample_count: int = 0


class ZeroDayPredictor:
    def __init__(self) -> None:
        self.state = PredictorState()

    def train(self, records: List[Dict[str, float]]) -> Dict[str, object]:
        if not records:
            self.state = PredictorState(trained=True, baseline_cvss=5.0, baseline_exploitability=0.3, sample_count=0)
            return {"status": "trained", "sample_count": 0, "baseline_cvss": 5.0, "baseline_exploitability": 0.3}

        cvss_values = [float(r.get("cvss", 0.0)) for r in records]
        exploit_values = [float(r.get("exploit_probability", 0.0)) for r in records]

        self.state = PredictorState(
            trained=True,
            baseline_cvss=round(mean(cvss_values), 3),
            baseline_exploitability=round(mean(exploit_values), 3),
            sample_count=len(records),
        )
        return {
            "status": "trained",
            "sample_count": self.state.sample_count,
            "baseline_cvss": self.state.baseline_cvss,
            "baseline_exploitability": self.state.baseline_exploitability,
        }

    def forecast(self, technology: str, telemetry: Dict[str, float]) -> Dict[str, object]:
        if not self.state.trained:
            self.train([])

        exposure = float(telemetry.get("internet_exposure", 0.5))
        patch_latency = float(telemetry.get("patch_latency_days", 14))
        vuln_density = float(telemetry.get("vuln_density", 0.4))
        intel_signal = float(telemetry.get("threat_intel_signal", 0.3))

        weighted_score = (
            self.state.baseline_cvss * 0.28
            + self.state.baseline_exploitability * 10 * 0.22
            + exposure * 10 * 0.20
            + min(patch_latency / 30, 1.0) * 10 * 0.15
            + vuln_density * 10 * 0.10
            + intel_signal * 10 * 0.05
        )
        risk_score = max(0, min(100, round(weighted_score * 10 / 8.5)))

        if risk_score >= 80:
            trend = "elevated"
        elif risk_score >= 55:
            trend = "watch"
        else:
            trend = "stable"

        return {
            "technology": technology,
            "risk_score": risk_score,
            "risk_trend": trend,
            "forecast_window_days": 30,
            "generated_at": datetime.utcnow().isoformat(),
            "drivers": {
                "internet_exposure": exposure,
                "patch_latency_days": patch_latency,
                "vulnerability_density": vuln_density,
                "threat_intel_signal": intel_signal,
            },
        }

    def risk_trends(self, portfolio: List[Dict[str, object]]) -> Dict[str, object]:
        forecasts = [self.forecast(str(item.get("technology", "unknown")), item.get("telemetry", {})) for item in portfolio]
        avg = round(mean([f["risk_score"] for f in forecasts]), 2) if forecasts else 0.0
        return {
            "portfolio_size": len(forecasts),
            "average_risk_score": avg,
            "forecasts": forecasts,
            "generated_at": datetime.utcnow().isoformat(),
        }
