def create_unified_schema():
    return {
        "source": None,
        "timestamp": None,
        "asset_id": None,  # على مستوى الـ root — مهم للـ matching بين
                            # threat_intelligence/pentest/prediction
                            # بدون الاعتماد على nesting مختلف لكل مصدر

        # ==================================================
        # THREAT INTELLIGENCE
        # ==================================================
        "threat_intelligence": {
            "cve_id": None,
            "cve_vendor": None,
            "cve_product": None,

            "asset_id": None,
            "asset_name": None,
            "asset_type": None,
            "asset_vendor": None,
            "asset_product": None,

            "business_criticality": None,

            "cvss_score": None,
            "severity": None,

            "epss_score": None,
            "epss_percentile": None,

            "published": None,
            "date_added": None,

            "days_since_published": None,
            "days_since_kev_added": None,

            "known_ransomware": None,

            "vuln_type": None,
            "description": None,

            "match_confidence": None,
            "scope": None,
            "source": None,

            "threat_score": None,
            "threat_pressure_factor": None,
            "alert_level": None,

            "version_confirmed": None,
            "detected_version": None,
            "confirmation_method": None,
            "cpe_range_matched": None,

            "is_behind_waf": None,
            "waf_name": None,

            "has_public_exploit": None,
            "exploit_count": None,
            "exploit_ids": None,

            "cwe_id": None,
            "cwe_name": None,

            "attack_technique_id": None,
            "attack_technique_name": None,
            "attack_tactic": None
        },

        # ==================================================
        # FINANCIAL LOSS PREDICTION
        # ==================================================
        "financial_loss": {
            "predicted_cost_usd": None,
            "predicted_log_cost": None,
            "risk_category": None,

            "prediction_interval_low": None,
            "prediction_interval_high": None,

            "financial_loss_report": None,
            "formatted_report": None,

            # مهم جدًا عشان متفقديش output الأصلي
            "raw_prediction_output": None
        },

        # ==================================================
        # PENTEST RESULTS
        # ==================================================
        "pentest": {
            "status": None,
            "scanner_type": None,

            "started_at": None,
            "ended_at": None,

            "findings_count": None,
            "traces_count": None,

            "errors": [],

            "scan_info": {
                "target": None,
                "param": None,
                "method": None,
                "model": None,
                "timestamp": None,
                "steps": None,
                "total_reward": None,
                "scan_duration_seconds": None,
                "endpoints_discovered": None,
                "endpoints_scanned": None
            },

            "summary": {
                "total_findings": None,
                "critical": None,
                "high": None,
                "medium": None,
                "low": None
            },

            "findings": [],
            "action_log": [],
            "endpoints": []
        }
    }
