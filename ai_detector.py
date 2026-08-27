"""
AI Act Shield - AI Detector
Sightengine integration for AI-generated image detection.

Environment variables:
    SIGHTENGINE_API_USER
    SIGHTENGINE_API_SECRET
"""

import os
import logging
from typing import Any, Dict, Optional

import requests


logger = logging.getLogger("AI-ACT-SHIELD")


SIGHTENGINE_URL = "https://api.sightengine.com/1.0/check.json"
SIGHTENGINE_MODEL = "genai"

# Timeout volutamente limitato: il worker non deve rimanere bloccato.
DEFAULT_TIMEOUT = 30


def _get_credentials() -> tuple[str, str]:
    """
    Read Sightengine credentials from environment variables.
    """

    api_user = os.getenv("SIGHTENGINE_API_USER", "").strip()
    api_secret = os.getenv("SIGHTENGINE_API_SECRET", "").strip()

    if not api_user:
        raise RuntimeError(
            "SIGHTENGINE_API_USER environment variable is missing"
        )

    if not api_secret:
        raise RuntimeError(
            "SIGHTENGINE_API_SECRET environment variable is missing"
        )

    return api_user, api_secret


def detect_ai(
    file_path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[float]:
    """
    Analyze an image with Sightengine.

    Returns:
        float: AI-generated probability in the range [0.0, 1.0]
        None: if the analysis cannot be completed

    The returned value corresponds to:
        response["type"]["ai_generated"]
    """

    logger.info("[AI DETECTOR] Starting Sightengine analysis")
    logger.info("[AI DETECTOR] File: %s", file_path)

    if not file_path:
        logger.warning("[AI DETECTOR] Empty file path")
        return None

    if not os.path.isfile(file_path):
        logger.warning(
            "[AI DETECTOR] File does not exist: %s",
            file_path,
        )
        return None

    try:
        api_user, api_secret = _get_credentials()
    except Exception as exc:
        logger.error(
            "[AI DETECTOR] Credentials error: %s",
            exc,
        )
        return None

    try:
        with open(file_path, "rb") as image_file:

            files = {
                "media": image_file,
            }

            data = {
                "models": SIGHTENGINE_MODEL,
                "api_user": api_user,
                "api_secret": api_secret,
            }

            logger.info(
                "[AI DETECTOR] Sending image to Sightengine"
            )

            response = requests.post(
                SIGHTENGINE_URL,
                files=files,
                data=data,
                timeout=timeout,
            )

        logger.info(
            "[AI DETECTOR] HTTP status: %s",
            response.status_code,
        )

    except requests.Timeout:
        logger.error(
            "[AI DETECTOR] Sightengine request timed out"
        )
        return None

    except requests.RequestException as exc:
        logger.error(
            "[AI DETECTOR] Sightengine request failed: %s",
            exc,
        )
        return None

    except OSError as exc:
        logger.error(
            "[AI DETECTOR] Could not read image: %s",
            exc,
        )
        return None

    # HTTP-level failure
    if not response.ok:
        logger.error(
            "[AI DETECTOR] Sightengine HTTP error: %s",
            response.text[:500],
        )
        return None

    try:
        result: Dict[str, Any] = response.json()
    except ValueError:
        logger.error(
            "[AI DETECTOR] Sightengine returned invalid JSON"
        )
        return None

    # Sightengine can explicitly return status=failure
    status = result.get("status")

    if status != "success":
        logger.error(
            "[AI DETECTOR] Sightengine returned failure: %s",
            result,
        )
        return None

    # Expected structure:
    #
    # {
    #   "status": "success",
    #   "type": {
    #       "ai_generated": 0.001
    #   }
    # }
    #
    type_data = result.get("type", {})

    if not isinstance(type_data, dict):
        logger.error(
            "[AI DETECTOR] Invalid 'type' response"
        )
        return None

    ai_score = type_data.get("ai_generated")

    if ai_score is None:
        logger.warning(
            "[AI DETECTOR] No ai_generated score returned"
        )
        return None

    try:
        ai_score = float(ai_score)
    except (TypeError, ValueError):
        logger.error(
            "[AI DETECTOR] Invalid AI score: %r",
            ai_score,
        )
        return None

    # Defensive validation.
    if not 0.0 <= ai_score <= 1.0:
        logger.error(
            "[AI DETECTOR] AI score outside valid range: %s",
            ai_score,
        )
        return None

    logger.info(
        "[AI DETECTOR] AI score: %.6f",
        ai_score,
    )

    return ai_score


def analyze_image(
    file_path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Higher-level interface for analyzer.py.

    Returns a normalized result instead of only a float.

    Example:

    {
        "available": True,
        "provider": "sightengine",
        "model": "genai",
        "ai_score": 0.97
    }

    If Sightengine is unavailable:

    {
        "available": False,
        "provider": "sightengine",
        "model": "genai",
        "ai_score": None
    }
    """

    score = detect_ai(
        file_path=file_path,
        timeout=timeout,
    )

    if score is None:
        return {
            "available": False,
            "provider": "sightengine",
            "model": SIGHTENGINE_MODEL,
            "ai_score": None,
        }

    return {
        "available": True,
        "provider": "sightengine",
        "model": SIGHTENGINE_MODEL,
        "ai_score": score,
    }


# Optional direct test:
# python ai_detector.py /path/to/image.jpg
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if len(sys.argv) < 2:
        print("Usage: python ai_detector.py <image_path>")
        raise SystemExit(1)

    image_path = sys.argv[1]

    result = analyze_image(image_path)

    print(result)
