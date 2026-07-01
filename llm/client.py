import os
import json
import logging
from typing import Optional

from dotenv import load_dotenv
from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()

logger = logging.getLogger(__name__)

MODEL = os.getenv("OPENAI_MODEL", "gpt-5")
DEFAULT_TIMEOUT = 120.0


# ─────────────────────────────
# CLIENT
# ─────────────────────────────
def get_client(api_key: Optional[str] = None) -> AsyncOpenAI:
    key = api_key or os.getenv("OPENAI_API_KEY")

    if not key:
        raise ValueError("OPENAI_API_KEY is not set")

    logger.info("🔑 OPENAI KEY LOADED: YES")

    return AsyncOpenAI(
        api_key=key,
        timeout=DEFAULT_TIMEOUT
    )


# ─────────────────────────────
# LLM CALL (FIXED)
# ❌ NO temperature (GPT-5 restriction)
# ─────────────────────────────
@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
async def call_llm(
    system_prompt: str,
    user_prompt: str,
    client: AsyncOpenAI
) -> dict:

    response = await client.chat.completions.create(
        model=MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    )

    content = response.choices[0].message.content

    if not content:
        raise ValueError("LLM returned empty response")

    return json.loads(content)