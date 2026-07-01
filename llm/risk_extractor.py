"""
Risk Extractor

يستخرج الـ outputs اللي مش محتاجة LLM، من الـ unified schema
اللي خرجت من الـ normalizers:

  - critical_vulnerabilities   (فلترة من threat_intelligence + pentest)
  - risk_category               (جاهز من prediction، matched بالـ asset_id الصحيح)
  - risk_score                   (composite score محسوب — technical + business)
  - financial_loss                 (رقم واحد بس: predicted_cost_usd، جاهز من prediction)
  - priority_rank                    (ترتيب الـ CVEs مع بعض، بعد ما كل واحدة تاخد الـ 14 output بتاعتها)

كل الدوال هنا بتفترض إن الـ input دخل بالفعل بعد ما يعدي على
normalize_threat_intelligence() / normalize_pentest() / normalize_prediction().
"""

from typing import List, Dict, Any, Optional


# ══════════════════════════════════════════════
# BUSINESS WEIGHTS
# ══════════════════════════════════════════════

BUSINESS_WEIGHT = {
    "critical": 1.3,
    "high"    : 1.1,
    "medium"  : 1.0,
    "low"     : 0.8,
}

DEFAULT_BUSINESS_WEIGHT = 1.0


# ══════════════════════════════════════════════
# CRITICAL VULNERABILITIES
# فلترة من threat_intelligence + pentest
# ══════════════════════════════════════════════

def extract_critical_vulnerabilities(
    threat_records : List[dict],
    pentest_records: List[dict],
    cvss_threshold  : float = 9.0
) -> List[Dict[str, Any]]:
    """
    يفلتر الـ vulnerabilities الحرجة.
    Critical = severity == "critical" OR cvss_score >= threshold
               OR has_public_exploit OR known_ransomware

    Output مبسّط عمداً: asset_id + cve_id بس (مختصر مفيد —
    "إيه الـ CVEs اللي ظهرت على إيه الـ assets"). كل التفاصيل
    الإضافية (cvss_score, exploit_count, attack_technique, الخ)
    تُستخدم داخلياً بس في الفلترة، ومش بترجع في الـ output النهائي.
    """

    critical = []
    seen = set()  # لمنع التكرار (نفس asset_id + cve_id)

    # ── من threat intelligence ──
    for record in threat_records:
        ti = record.get("threat_intelligence", {})

        severity         = str(ti.get("severity") or "").lower()
        cvss_score       = ti.get("cvss_score") or 0
        has_exploit      = bool(ti.get("has_public_exploit"))
        known_ransomware = bool(ti.get("known_ransomware"))

        is_critical = (
            severity == "critical"
            or float(cvss_score) >= cvss_threshold
            or has_exploit
            or known_ransomware
        )

        if is_critical:
            asset_id = ti.get("asset_id")
            cve_id   = ti.get("cve_id")
            key = (asset_id, cve_id)

            if key not in seen:
                seen.add(key)
                critical.append({
                    "asset_id": asset_id,
                    "cve_id"  : cve_id,
                })

    # ملاحظة: pen_test findings مش CVEs معروفة (مفيهاش cve_id)،
    # فمش بتدخل في القائمة المختصرة دي. لو احتجنا نعرضهم لاحقاً
    # كـ "vulnerabilities مكتشفة بالفحص" منفصلة، نضيف دالة جديدة.

    return critical


# ══════════════════════════════════════════════
# FINANCIAL DATA
# جاهز من Prediction Model — رقم الخسارة المتوقعة بس
# ══════════════════════════════════════════════

def extract_financial_data(
    prediction_records: List[dict]
) -> List[Dict[str, Any]]:
    """
    يجيب financial_loss جاهز من الـ prediction model.

    Output: financial_loss (predicted_cost_usd) + low_interval +
    high_interval + asset_id للـ matching. مفيش log_cost، مفيش
    raw_prediction_output — اتشالوا عمداً عشان الـ output يكون
    نظيف ومباشر، بس الـ interval bounds (low/high) لازمة للعميل.
    """

    if not prediction_records:
        return [{
            "asset_id"       : None,
            "financial_loss" : None,
            "low_interval"   : None,
            "high_interval"  : None,
            "note"           : "No prediction data available."
        }]

    results = []
    for record in prediction_records:
        fl = record.get("financial_loss", {})

        asset_id = (
            record.get("asset_id")
            or fl.get("raw_prediction_output", {}).get("asset_id")
        )

        results.append({
            "asset_id"       : asset_id,
            "financial_loss" : fl.get("predicted_cost_usd"),
            "low_interval"   : fl.get("prediction_interval_low"),
            "high_interval"  : fl.get("prediction_interval_high"),
        })

    return results


# ══════════════════════════════════════════════
# COMPOSITE RISK SCORE
# Technical Severity (Threat Intel) × Business Weight (Prediction)
# ══════════════════════════════════════════════

def _normalize_risk_category(risk_category: Optional[str]) -> str:
    return str(risk_category or "").strip().lower()


def compute_risk_score(
    cvss_score        : Optional[float],
    epss_score          : Optional[float],
    has_public_exploit    : Optional[bool],
    known_ransomware         : Optional[bool],
    risk_category               : Optional[str]
) -> Dict[str, Any]:
    """
    يحسب composite risk score واحد (0-10) بناءً على:
      - الخطورة الفنية (cvss + epss + exploit + ransomware)
      - الوزن البيزنسي (risk_category من الـ prediction model)
    """

    cvss_score = cvss_score or 0.0
    epss_score = epss_score or 0.0

    technical_score = (
        (cvss_score * 0.5)
        + (epss_score * 10 * 0.3)
        + (1.0 if has_public_exploit else 0.0)
        + (1.2 if known_ransomware else 0.0)
    )

    technical_score = min(technical_score, 10.0)

    category_key    = _normalize_risk_category(risk_category)
    business_weight  = BUSINESS_WEIGHT.get(category_key, DEFAULT_BUSINESS_WEIGHT)

    final_score = min(technical_score * business_weight, 10.0)
    final_score = round(final_score, 2)

    if final_score >= 9:
        label = "Critical"
    elif final_score >= 7:
        label = "High"
    elif final_score >= 4:
        label = "Medium"
    else:
        label = "Low"

    return {
        "risk_score": final_score,
        "risk_label": label,
        "breakdown": {
            "technical_score": round(technical_score, 2),
            "business_weight" : business_weight,
            "inputs": {
                "cvss_score"        : cvss_score,
                "epss_score"         : epss_score,
                "has_public_exploit"  : bool(has_public_exploit),
                "known_ransomware"      : bool(known_ransomware),
                "risk_category"           : risk_category,
            }
        }
    }


def extract_risk_scores(
    threat_records    : List[dict],
    prediction_records   : List[dict]
) -> List[Dict[str, Any]]:
    """
    يحسب risk_score لكل CVE.

    لو فيه prediction لنفس asset_id يستخدمه (matching صحيح).
    لو مفيش matching يرجع لأول prediction متاح (fallback آمن).
    """

    prediction_by_asset = {}

    for record in prediction_records:
        fl = record.get("financial_loss", {})

        asset_id = (
            record.get("asset_id")
            or fl.get("raw_prediction_output", {}).get("asset_id")
        )

        if asset_id:
            prediction_by_asset[asset_id] = fl

    default_prediction = {}
    if prediction_records:
        default_prediction = prediction_records[0].get("financial_loss", {})

    results = []

    for record in threat_records:
        ti = record.get("threat_intelligence", {})

        asset_id = ti.get("asset_id")

        prediction_data = prediction_by_asset.get(asset_id, default_prediction)

        risk_category = prediction_data.get("risk_category")

        score_data = compute_risk_score(
            cvss_score=ti.get("cvss_score"),
            epss_score=ti.get("epss_score"),
            has_public_exploit=ti.get("has_public_exploit"),
            known_ransomware=ti.get("known_ransomware"),
            risk_category=risk_category
        )

        results.append({
            "cve_id"       : ti.get("cve_id"),
            "asset_id"     : asset_id,
            "risk_category": risk_category,
            **score_data
        })

    return results


# ══════════════════════════════════════════════
# MEMORY ALERT
# بدون LLM — بترجع جملة جاهزة بناءً على memory_context
# (هل شُوفت نفس الـ CVE على نفس الـ target قبل كده؟)
# ══════════════════════════════════════════════

def build_memory_alert(
    asset_id      : Optional[str],
    cve_id        : Optional[str],
    memory_context: Optional[List[Dict[str, Any]]]
) -> str:
    """
    يركّب جملة "memory_alert" مباشرة من البيانات، بدون LLM.

    لو memory_context فيها entry لنفس الـ asset_id (وده دايماً
    بيكون صحيح لأن multi_cve_pipeline بيجيب الـ memory بناءً
    على نفس الـ asset_id قبل ما يستدعي هنا)، بنفترض إن ده
    نفس الـ target اللي اتفحص قبل كده.
    """

    if not memory_context:
        return "First time analyzing this target for this CVE — no prior history found."

    previous = memory_context[0]  # أحدث entry محفوظة لنفس الـ asset

    prev_cve_id        = previous.get("cve_id")
    prev_risk_score    = previous.get("risk_score")
    prev_risk_category = previous.get("risk_category")

    if prev_cve_id == cve_id:
        return (
            f"This target ({asset_id}) was seen before. {cve_id} was "
            f"previously detected on it with risk_score {prev_risk_score} "
            f"({prev_risk_category})."
        )

    return (
        f"This target ({asset_id}) was seen before, but with a different "
        f"vulnerability ({prev_cve_id}, risk_score {prev_risk_score}). "
        f"This is the first time {cve_id} is detected on it."
    )


# ══════════════════════════════════════════════
# PRIORITY RANKING — بين كل الـ CVEs مع بعض
# بتتشغل بعد ما كل CVE تاخد الـ 14 output بتاعتها لوحدها
# ══════════════════════════════════════════════

def rank_cves_by_priority(cve_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    بترتب الـ CVEs (بعد ما كل واحدة خلصت تحليلها كاملاً) حسب
    risk_score تنازلياً، وتضيف "priority_rank" لكل واحدة.

    priority_rank = 1 → أعلى أولوية (يتحل الأول)

    Input : List[dict] — كل dict فيه على الأقل "risk_score" (وأي حقول تانية محفوظة)
    Output: نفس الـ list بس مرتبة + فيها "priority_rank" مُضافة
    """

    if not cve_results:
        return []

    sorted_cves = sorted(
        cve_results,
        key=lambda x: x.get("risk_score", 0) or 0,
        reverse=True
    )

    for i, cve in enumerate(sorted_cves, start=1):
        cve["priority_rank"] = i

    return sorted_cves
