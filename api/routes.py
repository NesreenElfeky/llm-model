"""
API Routes

نقطة الدخول الرئيسية للمشروع. بتستقبل الـ raw outputs من
الموديلات التلاتة وترجع الـ 14 output (+ memory_alert) لكل CVE،
بالإضافة لرابط PDF جاهز في نفس الرد.

ملاحظة مهمة: التحليل (run_orchestrated_analysis) بيتشغل مرة
واحدة بس لكل request. الـ PDF بيتولّد من نفس النتيجة (بدون
استدعاء تحليل تاني)، وبيرجع رابطه جوه نفس الـ JSON response —
عشان نضمن عدم تضارب الـ Memory بين JSON وPDF.
"""

import os
import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from api.models import AnalyzeRequest, AnalyzeResponse, HealthResponse
from orchestrator.workflow import run_orchestrated_analysis
from rag.vector_store import get_count
from reports.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)

router = APIRouter()

OUTPUT_DIR = "generated_reports"


@router.get("/health", response_model=HealthResponse)
async def health():
    """
    بيتأكد إن السيرفر شغال + يرجع حالة RAG (عدد الـ chunks المخزنة)
    """
    try:
        chunk_count = get_count()
        rag_status = {"stored_chunks": chunk_count, "status": "ready" if chunk_count > 0 else "empty"}
    except Exception as e:
        logger.warning("Could not check RAG status: %s", e)
        rag_status = {"status": "unavailable", "error": str(e)}

    return HealthResponse(status="ok", rag_status=rag_status)


# ══════════════════════════════════════════════
# ENDPOINT الرئيسي — تحليل واحد، JSON + رابط PDF مع بعض
# ══════════════════════════════════════════════

@router.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    """
    النقطة الرئيسية الوحيدة. التحليل بيتشغل **مرة واحدة بس**،
    وبعدين:
      1. PDF يتولّد من نفس النتيجة (بدون إعادة تحليل)
      2. الرد يرجع JSON كامل + pdf_url بييشاور على نفس الملف

    عشان تحمّلي الـ PDF: استخدمي GET على الرابط اللي في pdf_url
    (مثلاً GET /api/v1/reports/cyber_risk_report_ASSET-301.pdf)
    """

    if not request.threat_intelligence:
        raise HTTPException(
            status_code=400,
            detail="threat_intelligence is empty — nothing to analyze."
        )

    logger.info(
        "Running analysis: %d CVE(s) in threat_intelligence",
        len(request.threat_intelligence)
    )

    # ── 1) التحليل — مرة واحدة بس ──
    try:
        results = await run_orchestrated_analysis(
            threat_intelligence_raw=request.threat_intelligence,
            pen_test_raw=request.pen_test,
            predictions_raw=request.predictions,
            use_rag=request.use_rag,
            use_memory=request.use_memory,
            run_concurrently=True,
        )

    except Exception as e:
        logger.exception("Orchestrated analysis failed")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

    # ── 2) PDF — من نفس النتيجة، بدون أي تحليل إضافي ──
    pdf_url = None

    if results:
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)

            asset_id = results[0].get("asset_id", "report")
            pdf_filename = f"cyber_risk_report_{asset_id}.pdf"
            pdf_path = f"{OUTPUT_DIR}/{pdf_filename}"

            generate_pdf_report(
                results=results,
                output_path=pdf_path
            )

            pdf_url = f"/api/v1/reports/{pdf_filename}"

        except Exception as e:
            # فشل توليد الـ PDF مش لازم يبوّظ الـ JSON الناجح —
            # بس نسجل تحذير ونرجع pdf_url=None
            logger.warning("PDF generation failed (JSON still returned): %s", e)

    # ── 3) رد واحد فيه الاتنين ──
    return AnalyzeResponse(
        results=results,
        total_cves=len(request.threat_intelligence),
        succeeded=len(results),
        pdf_url=pdf_url
    )


# ══════════════════════════════════════════════
# تحميل آخر PDF اتولّد تلقائياً (بدون ما تعرف الاسم)
# ══════════════════════════════════════════════

@router.get("/api/v1/reports/latest")
async def download_latest_report():
    """
    بيجيب آخر PDF اتولّد تلقائياً بدون ما تكتب اسم الملف.
    مفيد لو عايز تحمّل التقرير على طول بعد /api/v1/analyze.
    """
    if not os.path.exists(OUTPUT_DIR):
        raise HTTPException(status_code=404, detail="No reports directory found.")

    pdf_files = [
        f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pdf")
    ]

    if not pdf_files:
        raise HTTPException(status_code=404, detail="No reports found yet.")

    # آخر ملف اتعدّل = آخر تقرير اتولّد
    latest_file = max(
        pdf_files,
        key=lambda f: os.path.getmtime(os.path.join(OUTPUT_DIR, f))
    )

    file_path = os.path.join(OUTPUT_DIR, latest_file)

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=latest_file
    )


# ══════════════════════════════════════════════
# تحميل الـ PDF الجاهز (بدون أي تحليل إضافي)
# ══════════════════════════════════════════════

@router.get("/api/v1/reports/{filename}")
async def download_report(filename: str):
    """
    تحمّل ملف PDF تم توليده فعلاً من /api/v1/analyze.
    ده بس بيقرا الملف من القرص — مفيش أي تحليل جديد هنا.
    """

    file_path = os.path.join(OUTPUT_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found.")

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename
    )
