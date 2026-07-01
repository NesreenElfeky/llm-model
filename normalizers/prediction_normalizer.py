from normalizers.unified_schema import create_unified_schema


def _fill_single_prediction(prediction_output: dict) -> dict:
    """
    يملي schema واحدة من prediction output واحد (Clean JSON only)
    """

    schema = create_unified_schema()

    schema["source"] = "prediction"

    # asset_id على مستوى الـ root — لازم تكون موجودة في الـ raw
    # input عشان يتم الـ matching الصحيح مع الـ CVE لاحقاً في
    # llm/pipeline.py._get_prediction_for_asset()
    schema["asset_id"] = prediction_output.get("asset_id")

    financial_loss = schema["financial_loss"]

    financial_loss["predicted_cost_usd"] = prediction_output.get(
        "predicted_cost_usd"
    )

    financial_loss["predicted_log_cost"] = prediction_output.get(
        "predicted_log_cost"
    )

    financial_loss["risk_category"] = prediction_output.get(
        "risk_category"
    )

    financial_loss["prediction_interval_low"] = prediction_output.get(
        "prediction_interval_low"
    )

    financial_loss["prediction_interval_high"] = prediction_output.get(
        "prediction_interval_high"
    )

    # ✅ مهم جدًا: حفظ الـ raw output بدون أي formatting string
    financial_loss["raw_prediction_output"] = prediction_output

    return schema


def normalize_prediction(prediction_output):
    """
    يرجع List[schema]

    - dict واحد → list فيه عنصر واحد
    - list → list schemas
    """

    if isinstance(prediction_output, list):
        return [
            _fill_single_prediction(p)
            for p in prediction_output or []
        ]

    return [_fill_single_prediction(prediction_output)]
