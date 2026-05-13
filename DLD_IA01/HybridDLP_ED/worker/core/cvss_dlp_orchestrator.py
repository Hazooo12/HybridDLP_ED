"""
Orchestrator — CVSS-Inspired DLP Risk (Noteupdate.txt §6).
Luồng: base → exfiltration temparol → environmental → attack chain → fusion → policy.
"""
from __future__ import annotations

from typing import Any, Dict

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig

from core.base_scoring import compute_base_score
from core.exfiltration_temparol import compute_exfiltration_temparol
from core.environmental_scoring import compute_environmental_score
from core.attack_chain import compute_attack_chain_bonus
from core.final_risk_fusion import fuse_final_risk, apply_force_max_risk
from core.policy_decision import decide_recommended_action, build_reason_codes


class CVSSDLPScoringEngine:
    """Risk engine theo mô hình Base + EM + Environmental + AttackChain (Noteupdate)."""

    def calculate_score(
        self,
        fast_scan_result: Dict[str, Any],
        deep_analysis_result: Dict[str, Any],
        event_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        _, base_components = compute_base_score(
            fast_scan_result, deep_analysis_result, event_context
        )
        base_val = float(base_components["base_score"])

        em = compute_exfiltration_temparol(fast_scan_result, event_context)
        env_val, env_parts = compute_environmental_score(event_context)
        chain_bonus, chain_reasons = compute_attack_chain_bonus(
            event_context, fast_scan_result
        )

        use_f1 = getattr(WorkerConfig, "CVSS_DLP_USE_FORMULA1_EM_FACTOR", False)
        total = fuse_final_risk(
            base_val,
            float(em["temparol_numeric"]),
            env_val,
            chain_bonus,
            float(em["em_factor"]),
            use_em_factor_on_base=bool(use_f1),
        )
        total, forced = apply_force_max_risk(total, event_context)
        if forced:
            logger.warning("CVSS-DLP: force_max_risk applied")

        # UEBA Anomaly Assurance (Noteupdate § ML Integration):
        # Nếu ML UEBA phát hiện bất thường với độ nghiêm trọng cao nhưng bị 
        # công thức CVSS làm loãng (do không có file/content nhạy cảm), 
        # ta vẫn phải ép điểm lên trên mức Alert để cảnh báo lên Dashboard.
        ml_is_anomaly = event_context.get("ml_is_anomaly", False)
        ml_anomaly_score = float(event_context.get("ml_anomaly_score") or 0.0)
        boost_threshold = getattr(WorkerConfig, "ML_ANOMALY_BOOST_THRESHOLD", 7.0)
        
        if ml_is_anomaly and ml_anomaly_score >= boost_threshold:
            alert_threshold = getattr(WorkerConfig, "RISK_THRESHOLDS", {}).get("alert", 4.0)
            if total < alert_threshold:
                # Boost tỷ lệ theo mức độ nghiêm trọng của anomaly (Ví dụ: 8.04 -> 7.2)
                boosted_total = min(10.0, max(alert_threshold, ml_anomaly_score * 0.9))
                logger.warning(
                    f"CVSS-DLP Boost: UEBA Anomaly score ({ml_anomaly_score:.2f}) vượt ngưỡng {boost_threshold}. "
                    f"Tự động boost final risk từ {total:.2f} lên {boosted_total:.2f} để cảnh báo (Alert) lên Dashboard."
                )
                total = boosted_total
                forced = True

        action, rec_label = decide_recommended_action(
            total,
            str(em["exfiltration_temparol"]),
            float(base_components["content_sensitivity"]),
        )

        reason_codes = build_reason_codes(
            base_components,
            em,
            env_parts,
            chain_reasons,
            extra=[event_context.get("force_max_risk_reason")]
            if event_context.get("force_max_risk_reason")
            else None,
        )
        reason_codes = [r for r in reason_codes if r]

        from core.risk_scoring import classify_risk_level, total_score_to_cvss10

        cvss_payload = {
            "event_id": event_context.get("event_id"),
            "base_score": round(base_val, 2),
            "content_sensitivity": base_components["content_sensitivity"],
            "data_criticality": base_components["data_criticality"],
            "behavior_anomaly": base_components["behavior_anomaly"],
            "confidence": base_components["confidence"],
            "exfiltration_temparol": em["exfiltration_temparol"],
            "temparol_band": em["temparol_band"],
            "temparol_score": em["temparol_score"],
            "temparol_numeric": em["temparol_numeric"],
            "em_factor": em["em_factor"],
            "environmental_score": env_parts["environmental_score"],
            "environmental_breakdown": {k: v for k, v in env_parts.items() if k != "environmental_score"},
            "attack_chain_bonus": round(chain_bonus, 2),
            "attack_chain_reasons": chain_reasons,
            "final_risk": total,
            "recommended_action": rec_label,
            "reason_codes": reason_codes,
        }

        details: Dict[str, Any] = {
            "cvss_dlp": cvss_payload,
            "exfiltration_temparol_detail": em,
        }

        return {
            "total_score": total,
            "cvss_score": total_score_to_cvss10(total),
            "content_score": base_components["content_sensitivity"],
            "behavior_score": em["temparol_score"],
            "context_score": env_parts["environmental_score"],
            "action": action,
            "risk_level": classify_risk_level(total),
            "details": details,
            "method": "cvss_dlp",
        }
