from normalizers.unified_schema import create_unified_schema


def _fill_single_threat(threat: dict) -> dict:
    schema = create_unified_schema()

    schema["source"] = "threat_intelligence"
    schema["timestamp"] = threat.get("timestamp")
    schema["asset_id"] = threat.get("asset_id")  # على مستوى root كمان

    ti = schema["threat_intelligence"]

    fields = [
        "cve_id", "cve_vendor", "cve_product",
        "asset_id", "asset_name", "asset_type",
        "asset_vendor", "asset_product",
        "business_criticality",
        "cvss_score", "severity",
        "epss_score", "epss_percentile",
        "published", "date_added",
        "days_since_published", "days_since_kev_added",
        "known_ransomware",
        "vuln_type", "description",
        "match_confidence",
        "scope", "source",
        "threat_score", "threat_pressure_factor",
        "alert_level",
        "version_confirmed", "detected_version",
        "confirmation_method", "cpe_range_matched",
        "is_behind_waf", "waf_name",
        "has_public_exploit", "exploit_count", "exploit_ids",
        "cwe_id", "cwe_name",
        "attack_technique_id", "attack_technique_name",
        "attack_tactic"
    ]

    for f in fields:
        ti[f] = threat.get(f)

    return schema


def normalize_threat_intelligence(threat_output):
    """
    Always returns List[schema] — schema واحدة لكل CVE.
    """

    if isinstance(threat_output, list):
        return [_fill_single_threat(t) for t in threat_output or []]

    return [_fill_single_threat(threat_output)]
