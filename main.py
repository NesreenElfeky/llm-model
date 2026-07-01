"""
Main — يشغّل FastAPI server

تشغيل:
    uvicorn main:app --host 0.0.0.0 --port 8080 --reload

أو:
    python main.py
"""

import logging
from fastapi import FastAPI

from api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

app = FastAPI(
    title="Cyber Risk Financial Loss Prediction — LLM Module",
    description="Analyzes CVEs with risk scoring, financial loss prediction, "
                "attack paths, mitigation plans, and long-term memory.",
    version="1.0.0"
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
