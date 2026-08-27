import time
import os
import io
import json
import hashlib
import threading
import mimetypes
import struct

from urllib.parse import urlparse, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler

from supabase import create_client, Client
import c2pa


# ============================================================
# AI ACT SHIELD
# ANALYZER ENGINE
#
# Pipeline:
#
# Supabase audits
#       ↓
# media-to-check
#       ↓
# Analyzer
#       ├── File engine
#       ├── SHA-256
#       ├── C2PA engine
#       ├── Metadata engine
#       ├── Watermark engine
#       ├── AI detection engine
#       ├── Evidence engine
#       └── Risk engine
#       ↓
# Supabase audits
#       ↓
# Fixer AI-act shield
#
# IMPORTANT:
# - Nessuno score AI viene inventato.
# - Nessuna firma C2PA falsa viene generata.
# - "compliant" indica conformità tecnica rispetto
#   alle regole attualmente implementate, NON certificazione
#   legale definitiva di conformità all'AI Act.
# ============================================================


# ============================================================
# 1. CONFIGURAZIONE
# ============================================================

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://ulvlohhszcmdzqvipvan.supabase.co"
)

SUPABASE_SECRET_KEY = os.environ.get(
    "SUPABASE_SECRET_KEY",
    ""
)

MEDIA_BUCKET = os.environ.get(
    "MEDIA_BUCKET",
    "media-to-check"
)

FIXER_BUCKET = os.environ.get(
    "FIXER_BUCKET",
    "Fixer AI-act shield"
)

WORKER_NAME = "AI Act Shield"

WORKER_INTERVAL_SECONDS = int(
    os.environ.get(
        "WORKER_INTERVAL_SECONDS",
        "5"
    )
)

MAX_FILE_SIZE_MB = int(
    os.environ.get(
        "MAX_FILE_SIZE_MB",
        "50"
    )
)

MAX_FILE_SIZE_BYTES = (
    MAX_FILE_SIZE_MB * 1024 * 1024
)


if not SUPABASE_SECRET_KEY:

    raise RuntimeError(
        "SUPABASE_SECRET_KEY non configurata "
        "nelle Environment Variables di Render."
    )


supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# ============================================================
# 2. LOGGING
# ============================================================

def log(message: str):

    print(
        f"[AI-ACT-SHIELD] {message}",
        flush=True
    )


# ============================================================
# 3. SERVER HTTP PER RENDER
# ============================================================

class SimpleHTTPRequestHandler(
    BaseHTTPRequestHandler
):

    def do_GET(self):

        self.send_response(200)

        self.send_header(
            "Content-type",
            "application/json"
        )

        self.end_headers()

        response = {
            "service": WORKER_NAME,
            "status": "running",
            "worker_interval_seconds": (
                WORKER_INTERVAL_SECONDS
            ),
            "media_bucket": MEDIA_BUCKET,
            "fixer_bucket": FIXER_BUCKET
        }

        self.wfile.write(
            json.dumps(response).encode(
                "utf-8"
            )
        )

    def do_HEAD(self):

        self.send_response(200)

        self.send_header(
            "Content-type",
            "application/json"
        )

        self.end_headers()

    def log_message(
        self,
        format,
        *args
    ):

        return


def run_http_server():

    port = int(
        os.environ.get(
            "PORT",
            "10000"
        )
    )

    server_address = (
        "",
        port
    )

    httpd = HTTPServer(
        server_address,
        SimpleHTTPRequestHandler
    )

    log(
        f"HTTP server avviato sulla porta {port}."
    )

    httpd.serve_forever()


# ============================================================
# 4. NORMALIZZAZIONE STORAGE PATH
# ============================================================

def normalize_storage_path(
    file_url: str
) -> str:
    """
    Supporta:

        user-id/file.png

    oppure URL Supabase Storage complete.
    """

    if not file_url:

        raise ValueError(
            "file_url vuoto"
        )

    value = str(
        file_url
    ).strip()

    # --------------------------------------------------------
    # Caso normale:
    #
    # user-id/file.png
    # --------------------------------------------------------

    if not value.startswith(
        (
            "http://",
            "https://"
        )
    ):

        return unquote(
            value.lstrip("/")
        )

    # --------------------------------------------------------
    # URL Supabase Storage
    # --------------------------------------------------------

    parsed = urlparse(
        value
    )

    path = unquote(
        parsed.path.lstrip("/")
    )

    markers = [
        (
            "storage/v1/object/public/"
            + MEDIA_BUCKET
            + "/"
        ),
        (
            "storage/v1/object/sign/"
            + MEDIA_BUCKET
            + "/"
        ),
        (
            "storage/v1/object/authenticated/"
            + MEDIA_BUCKET
            + "/"
        )
    ]

    for marker in markers:

        if marker in path:

            return path.split(
                marker,
                1
            )[1]

    raise ValueError(
        f"URL Storage non riconosciuta: {file_url}"
    )


# ============================================================
# 5. DOWNLOAD FILE
# ============================================================

def download_file_from_storage(
    file_url: str
) -> bytes:

    storage_path = normalize_storage_path(
        file_url
    )

    log(
        f"Download bucket={MEDIA_BUCKET}"
    )

    log(
        f"Download path={storage_path}"
    )

    try:

        file_bytes = (
            supabase
            .storage
            .from_(MEDIA_BUCKET)
            .download(storage_path)
        )

    except Exception as e:

        raise RuntimeError(
            "Download Supabase Storage fallito: "
            f"{e}"
        ) from e

    if not file_bytes:

        raise RuntimeError(
            "Supabase Storage ha restituito "
            "un file vuoto."
        )

    file_size = len(
        file_bytes
    )

    log(
        f"Download completato: {file_size} bytes"
    )

    if file_size > MAX_FILE_SIZE_BYTES:

        raise RuntimeError(
            f"File troppo grande: "
            f"{file_size} bytes. "
            f"Limite: "
            f"{MAX_FILE_SIZE_MB} MB."
        )

    return file_bytes


# ============================================================
# 6. MIME TYPE
# ============================================================

def detect_mime_type(
    file_url: str,
    file_bytes: bytes
) -> str:

    mime_type, _ = mimetypes.guess_type(
        file_url
    )

    if mime_type:

        return mime_type

    # JPEG
    if file_bytes.startswith(
        b"\xff\xd8\xff"
    ):

        return "image/jpeg"

    # PNG
    if file_bytes.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):

        return "image/png"

    # GIF
    if (
        file_bytes.startswith(b"GIF87a")
        or
        file_bytes.startswith(b"GIF89a")
    ):

        return "image/gif"

    # WEBP
    if (
        file_bytes.startswith(b"RIFF")
        and len(file_bytes) >= 12
        and file_bytes[8:12] == b"WEBP"
    ):

        return "image/webp"

    # PDF
    if file_bytes.startswith(
        b"%PDF-"
    ):

        return "application/pdf"

    # MP3
    if (
        file_bytes.startswith(b"ID3")
        or
        file_bytes.startswith(b"\xff\xfb")
    ):

        return "audio/mpeg"

    # MP4 / ISO BMFF
    if (
        len(file_bytes) >= 12
        and file_bytes[4:8] == b"ftyp"
    ):

        return "video/mp4"

    return "application/octet-stream"


# ============================================================
# 7. FILE ENGINE
# ============================================================

def analyze_file(
    file_bytes: bytes,
    file_url: str,
    file_name: str,
    mime_type: str
) -> dict:

    extension = ""

    if "." in file_name:

        extension = (
            file_name
            .rsplit(".", 1)[1]
            .lower()
        )

    sha256 = hashlib.sha256(
        file_bytes
    ).hexdigest()

    return {
        "file_name": file_name,
        "mime_type": mime_type,
        "extension": extension,
        "size_bytes": len(file_bytes),
        "sha256": sha256,
        "storage_path": file_url
    }


# ============================================================
# 8. C2PA ENGINE
# ============================================================

def check_c2pa_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    result = {
        "detected": False,
        "status": "not_detected",
        "claim_generator": None,
        "title": None,
        "active_manifest": None,
        "manifest_count": 0,
        "manifests": {},
        "error": None
    }

    try:

        stream = io.BytesIO(
            file_bytes
        )

        reader = c2pa.Reader(
            mime_type,
            stream
        )

        raw_json = reader.json()

        manifest_store = json.loads(
            raw_json
        )

        active_manifest = (
            manifest_store.get(
                "active_manifest"
            )
        )

        manifests = (
            manifest_store.get(
                "manifests",
                {}
            )
        )

        if not isinstance(
            manifests,
            dict
        ):

            manifests = {}

        result["manifest_count"] = len(
            manifests
        )

        result["manifests"] = manifests

        if not active_manifest:

            result["status"] = (
                "manifest_not_active"
            )

            return result

        manifest = manifests.get(
            active_manifest
        )

        if not manifest:

            result["status"] = (
                "active_manifest_missing"
            )

            result["active_manifest"] = (
                active_manifest
            )

            return result

        result["detected"] = True

        result["status"] = (
            "manifest_detected"
        )

        result["active_manifest"] = (
            active_manifest
        )

        result["claim_generator"] = (
            manifest.get(
                "claim_generator"
            )
        )

        result["title"] = (
            manifest.get(
                "title"
            )
        )

        # ----------------------------------------------------
        # Alcuni manifest C2PA possono contenere informazioni
        # aggiuntive utili alla provenance.
        # ----------------------------------------------------

        if "assertions" in manifest:

            result["assertion_count"] = len(
                manifest.get(
                    "assertions",
                    []
                )
            )

        if "ingredients" in manifest:

            result["ingredient_count"] = len(
                manifest.get(
                    "ingredients",
                    []
                )
            )

        return result

    except Exception as e:

        result["status"] = "error"

        result["error"] = str(
            e
        )

        log(
            f"C2PA engine error "
            f"({mime_type}): {e}"
        )

        return result


# ============================================================
# 9. JPEG METADATA ENGINE
# ============================================================

def analyze_jpeg_metadata(
    file_bytes: bytes
) -> dict:

    result = {
        "format": "jpeg",
        "exif_present": False,
        "xmp_present": False,
        "iptc_present": False,
        "software": None,
        "creator": None,
        "description": None,
        "raw_markers": []
    }

    if not file_bytes.startswith(
        b"\xff\xd8\xff"
    ):

        return result

    position = 2

    while position + 4 < len(
        file_bytes
    ):

        if file_bytes[position] != 0xFF:

            position += 1
            continue

        marker = file_bytes[
            position + 1
        ]

        position += 2

        # SOI / EOI / restart markers
        if marker in (
            0xD8,
            0xD9
        ):

            continue

        if position + 2 > len(
            file_bytes
        ):

            break

        segment_length = struct.unpack(
            ">H",
            file_bytes[
                position:
                position + 2
            ]
        )[0]

        if segment_length < 2:

            break

        segment_end = (
            position
            + segment_length
        )

        if segment_end > len(
            file_bytes
        ):

            break

        segment = file_bytes[
            position + 2:
            segment_end
        ]

        # APP1
        if marker == 0xE1:

            if segment.startswith(
                b"Exif\x00\x00"
            ):

                result["exif_present"] = True

            if segment.startswith(
                b"http://ns.adobe.com/xap/"
            ):

                result["xmp_present"] = True

            if b"<x:xmpmeta" in segment:

                result["xmp_present"] = True

        # APP13 = IPTC / Photoshop
        if marker == 0xED:

            result["iptc_present"] = True

        # APP0 / APP1 / APP13 etc.
        result["raw_markers"].append(
            hex(marker)
        )

        position = segment_end

    return result


# ============================================================
# 10. PNG METADATA ENGINE
# ============================================================

def analyze_png_metadata(
    file_bytes: bytes
) -> dict:

    result = {
        "format": "png",
        "text_chunks": [],
        "xmp_present": False,
        "software": None,
        "creator": None,
        "description": None
    }

    signature = (
        b"\x89PNG\r\n\x1a\n"
    )

    if not file_bytes.startswith(
        signature
    ):

        return result

    position = 8

    while position + 8 <= len(
        file_bytes
    ):

        try:

            length = struct.unpack(
                ">I",
                file_bytes[
                    position:
                    position + 4
                ]
            )[0]

            chunk_type = file_bytes[
                position + 4:
                position + 8
            ]

            data_start = (
                position + 8
            )

            data_end = (
                data_start + length
            )

            if data_end > len(
                file_bytes
            ):

                break

            data = file_bytes[
                data_start:
                data_end
            ]

            chunk_name = (
                chunk_type.decode(
                    "latin-1",
                    errors="ignore"
                )
            )

            if chunk_type in (
                b"tEXt",
                b"zTXt",
                b"iTXt"
            ):

                try:

                    text = data.decode(
                        "latin-1",
                        errors="ignore"
                    )

                except Exception:

                    text = ""

                if text:

                    result[
                        "text_chunks"
                    ].append(
                        text[:1000]
                    )

                    text_lower = (
                        text.lower()
                    )

                    if (
                        "xmp" in text_lower
                        or
                        "xmpmeta" in text_lower
                    ):

                        result[
                            "xmp_present"
                        ] = True

                    if (
                        "software" in text_lower
                    ):

                        result[
                            "software"
                        ] = text[:500]

                    if (
                        "creator" in text_lower
                    ):

                        result[
                            "creator"
                        ] = text[:500]

                    if (
                        "description"
                        in text_lower
                    ):

                        result[
                            "description"
                        ] = text[:500]

            position = (
                data_end + 4
            )

            if chunk_type == b"IEND":

                break

        except Exception:

            break

    return result


# ============================================================
# 11. GENERIC METADATA ENGINE
# ============================================================

def analyze_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    result = {
        "available": True,
        "format": mime_type,
        "exif_present": False,
        "xmp_present": False,
        "iptc_present": False,
        "software": None,
        "creator": None,
        "description": None,
        "signals": []
    }

    if mime_type == "image/jpeg":

        specific = analyze_jpeg_metadata(
            file_bytes
        )

        result.update(
            specific
        )

    elif mime_type == "image/png":

        specific = analyze_png_metadata(
            file_bytes
        )

        result.update(
            specific
        )

    else:

        result["available"] = False

        result["reason"] = (
            "Metadata parser specifico "
            "non ancora implementato "
            f"per {mime_type}."
        )

    # --------------------------------------------------------
    # Metadata signals
    # --------------------------------------------------------

    if result.get(
        "exif_present"
    ):

        result[
            "signals"
        ].append(
            "exif_present"
        )

    if result.get(
        "xmp_present"
    ):

        result[
            "signals"
        ].append(
            "xmp_present"
        )

    if result.get(
        "iptc_present"
    ):

        result[
            "signals"
        ].append(
            "iptc_present"
        )

    software = result.get(
        "software"
    )

    if software:

        result[
            "signals"
        ].append(
            "software_metadata_present"
        )

    creator = result.get(
        "creator"
    )

    if creator:

        result[
            "signals"
        ].append(
            "creator_metadata_present"
        )

    return result


# ============================================================
# 12. WATERMARK ENGINE
# ============================================================

def check_watermark(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    """
    Questo engine NON dichiara l'assenza di watermark
    semplicemente perché non trova una stringa.

    Per ora effettua soltanto controlli strutturali
    non invasivi.

    Il detector visuale reale verrà collegato qui.
    """

    result = {
        "available": False,
        "detected": None,
        "status": "not_implemented",
        "method": None,
        "signals": [],
        "detail": (
            "Watermark detection visuale "
            "non ancora collegato."
        )
    }

    # --------------------------------------------------------
    # Alcuni watermark testuali possono essere presenti
    # nei metadata, ma questo NON equivale a watermark
    # visuale.
    # --------------------------------------------------------

    if mime_type in (
        "image/jpeg",
        "image/png"
    ):

        result["status"] = (
            "metadata_only"
        )

        result["detail"] = (
            "Nessun detector visuale "
            "collegato. I metadata vengono "
            "analizzati separatamente."
        )

    return result


# ============================================================
# 13. AI DETECTION ENGINE
# ============================================================

def run_ai_detection(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    """
    Punto di integrazione per il vero modello
    AI-generated detection.

    NON restituisce score arbitrari.
    """

    return {
        "available": False,
        "score": None,
        "confidence": None,
        "status": "not_implemented",
        "model": None,
        "model_version": None,
        "signals": [],
        "detail": (
            "AI detection model reale "
            "non ancora collegato."
        )
    }


# ============================================================
# 14. PROVENANCE / EVIDENCE ENGINE
# ============================================================

def build_evidence(
    file_analysis: dict,
    c2pa_result: dict,
    metadata_result: dict,
    watermark_result: dict,
    ai_result: dict
) -> dict:

    signals = []

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    if c2pa_result.get(
        "detected"
    ):

        signals.append(
            {
                "type": "c2pa",
                "result": "present",
                "confidence": 1.0,
                "status": c2pa_result.get(
                    "status"
                )
            }
        )

    else:

        signals.append(
            {
                "type": "c2pa",
                "result": "not_detected",
                "confidence": None,
                "status": c2pa_result.get(
                    "status"
                )
            }
        )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    metadata_signals = (
        metadata_result.get(
            "signals",
            []
        )
    )

    for signal in metadata_signals:

        signals.append(
            {
                "type": "metadata",
                "result": signal,
                "confidence": None
            }
        )

    # --------------------------------------------------------
    # AI detection
    # --------------------------------------------------------

    if ai_result.get(
        "available"
    ):

        signals.append(
            {
                "type": "ai_detection",
                "result": "available",
                "score": ai_result.get(
                    "score"
                ),
                "confidence": ai_result.get(
                    "confidence"
                )
            }
        )

    else:

        signals.append(
            {
                "type": "ai_detection",
                "result": "unavailable",
                "confidence": None
            }
        )

    # --------------------------------------------------------
    # Watermark
    # --------------------------------------------------------

    if watermark_result.get(
        "available"
    ):

        signals.append(
            {
                "type": "watermark",
                "result": watermark_result.get(
                    "status"
                ),
                "detected": watermark_result.get(
                    "detected"
                )
            }
        )

    else:

        signals.append(
            {
                "type": "watermark",
                "result": "unavailable"
            }
        )

    # --------------------------------------------------------
    # File integrity
    # --------------------------------------------------------

    signals.append(
        {
            "type": "file_integrity",
            "result": "sha256_calculated",
            "sha256": file_analysis.get(
                "sha256"
            )
        }
    )

    return {
        "signal_count": len(
            signals
        ),
        "signals": signals
    }


# ============================================================
# 15. RISK ENGINE
# ============================================================

def calculate_risk(
    c2pa_result: dict,
    metadata_result: dict,
    watermark_result: dict,
    ai_result: dict
) -> dict:

    """
    Risk engine trasparente.

    Non usa un modello ML.
    Non inventa probabilità.

    Produce un rischio tecnico basato sulle evidenze
    effettivamente disponibili.
    """

    risk_points = 0

    reasons = []

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    if c2pa_result.get(
        "detected"
    ):

        risk_points += 0

    else:

        risk_points += 40

        reasons.append(
            "C2PA manifest non rilevato."
        )

    # --------------------------------------------------------
    # AI detector
    # --------------------------------------------------------

    if ai_result.get(
        "available"
    ):

        score = ai_result.get(
            "score"
        )

        if isinstance(
            score,
            (int, float)
        ):

            if score >= 0.80:

                risk_points += 40

                reasons.append(
                    "AI detector indica "
                    "alta probabilità di contenuto AI."
                )

            elif score >= 0.50:

                risk_points += 20

                reasons.append(
                    "AI detector indica "
                    "segnali intermedi di contenuto AI."
                )

    else:

        reasons.append(
            "AI detector non disponibile."
        )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    software = (
        metadata_result.get(
            "software"
        )
    )

    if software:

        software_lower = (
            str(software)
            .lower()
        )

        ai_software_terms = [
            "midjourney",
            "stable diffusion",
            "dall-e",
            "openai",
            "adobe firefly",
            "firefly",
            "generative ai",
            "generative",
            "comfyui",
            "automatic1111"
        ]

        for term in ai_software_terms:

            if term in software_lower:

                risk_points += 20

                reasons.append(
                    "Metadata software contiene "
                    f"un indicatore compatibile con "
                    f"generative AI: {term}."
                )

                break

    # --------------------------------------------------------
    # Clamp
    # --------------------------------------------------------

    risk_points = min(
        max(
            risk_points,
            0
        ),
        100
    )

    risk_level = "low"

    if risk_points >= 70:

        risk_level = "high"

    elif risk_points >= 40:

        risk_level = "medium"

    return {
        "score": risk_points,
        "level": risk_level,
        "reasons": reasons
    }


# ============================================================
# 16. COMPLIANCE ENGINE
# ============================================================

def evaluate_compliance(
    c2pa_result: dict,
    ai_result: dict,
    risk_result: dict
) -> dict:

    """
    ATTENZIONE:

    Questo non è un parere legale.

    Il sistema valuta la presenza di evidenze tecniche
    secondo le regole attualmente implementate.

    Regola attuale:

    C2PA presente + nessuna evidenza AI ad alto rischio
        -> compliant

    C2PA assente
        -> non_compliant

    AI detector disponibile e molto alto
        -> non_compliant
    """

    c2pa_detected = bool(
        c2pa_result.get(
            "detected"
        )
    )

    ai_available = bool(
        ai_result.get(
            "available"
        )
    )

    ai_score = ai_result.get(
        "score"
    )

    # --------------------------------------------------------
    # AI score molto alto
    # --------------------------------------------------------

    if (
        ai_available
        and
        isinstance(
            ai_score,
            (int, float)
        )
        and
        ai_score >= 0.80
    ):

        return {
            "status": "non_compliant",
            "reason": (
                "Il motore AI detection "
                "ha rilevato un'elevata "
                "probabilità di contenuto AI."
            )
        }

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    if c2pa_detected:

        return {
            "status": "compliant",
            "reason": (
                "Manifest C2PA rilevato. "
                "Provenance tecnica disponibile."
            )
        }

    # --------------------------------------------------------
    # Nessun C2PA
    # --------------------------------------------------------

    return {
        "status": "non_compliant",
        "reason": (
            "Nessun manifest C2PA rilevato."
        )
    }


# ============================================================
# 17. FIXER ENGINE
# ============================================================

def apply_c2pa_fix(
    file_bytes: bytes,
    audit_id: str,
    mime_type: str,
    file_name: str
):
    """
    Placeholder intenzionale.

    NON viene generata una firma C2PA falsa.

    Per creare una vera credenziale C2PA servono:
    - signer
    - private key
    - certificato compatibile
    - configurazione C2PA corretta

    Quando il signer sarà disponibile, questa funzione
    produrrà il file remediato e lo caricherà nel bucket:

        Fixer AI-act shield
    """

    log(
        f"Fixer richiesto per audit {audit_id}"
    )

    log(
        "Fixer C2PA non ancora attivo: "
        "nessuna firma falsa verrà applicata."
    )

    return None


# ============================================================
# 18. UPLOAD FIXER
# ============================================================

def upload_fixed_file(
    file_bytes: bytes,
    audit_id: str,
    file_name: str,
    mime_type: str
) -> str | None:

    """
    Funzione pronta per il futuro fixer.

    Non viene chiamata finché non abbiamo un file
    realmente remediato.
    """

    safe_name = (
        file_name
        .replace("/", "_")
        .replace("\\", "_")
    )

    storage_path = (
        f"{audit_id}/{safe_name}"
    )

    try:

        (
            supabase
            .storage
            .from_(FIXER_BUCKET)
            .upload(
                storage_path,
                file_bytes,
                {
                    "content-type": mime_type,
                    "upsert": "true"
                }
            )
        )

        log(
            f"File fixer caricato: "
            f"{FIXER_BUCKET}/{storage_path}"
        )

        # ----------------------------------------------------
        # Il bucket può essere privato.
        #
        # Non costruiamo una URL pubblica automaticamente.
        # Restituiamo il path interno.
        # ----------------------------------------------------

        return storage_path

    except Exception as e:

        log(
            f"Errore upload fixer: {e}"
        )

        return None


# ============================================================
# 19. DATABASE UPDATE
# ============================================================

def update_audit(
    audit_id,
    data
) -> bool:

    try:

        response = (
            supabase
            .table("audits")
            .update(data)
            .eq(
                "id",
                audit_id
            )
            .execute()
        )

        updated_rows = (
            response.data or []
        )

        if not updated_rows:

            log(
                f"ATTENZIONE: audit "
                f"{audit_id} non aggiornato."
            )

            return False

        log(
            f"Audit {audit_id} aggiornato."
        )

        return True

    except Exception as e:

        log(
            f"Errore aggiornamento audit "
            f"{audit_id}: {e}"
        )

        return False


# ============================================================
# 20. AUDIT ERROR
# ============================================================

def mark_audit_error(
    audit_id: str,
    error_message: str,
    extra_details: dict | None = None
):

    details = {
        "worker": WORKER_NAME,
        "status": "error",
        "error": error_message
    }

    if extra_details:

        details.update(
            extra_details
        )

    update_audit(
        audit_id,
        {
            "compliance_status": "non_compliant",
            "details": details
        }
    )


# ============================================================
# 21. SINGOLO AUDIT
# ============================================================

def process_single_audit(
    audit: dict
):

    audit_id = audit.get(
        "id"
    )

    file_url = audit.get(
        "file_url"
    )

    file_name = audit.get(
        "file_name",
        "unknown"
    )

    log("")
    log(
        "============================================================"
    )

    log(
        f"Audit pending: {audit_id}"
    )

    log(
        f"File: {file_name}"
    )

    log(
        f"Storage path: {file_url}"
    )

    log(
        "============================================================"
    )

    # --------------------------------------------------------
    # VALIDAZIONE
    # --------------------------------------------------------

    if not audit_id:

        log(
            "Audit senza ID. Ignorato."
        )

        return

    if not file_url:

        mark_audit_error(
            audit_id,
            "file_url mancante"
        )

        return

    # --------------------------------------------------------
    # DOWNLOAD
    # --------------------------------------------------------

    try:

        file_bytes = (
            download_file_from_storage(
                file_url
            )
        )

    except Exception as e:

        log(
            f"DOWNLOAD ERROR: {e}"
        )

        mark_audit_error(
            audit_id,
            "Impossibile scaricare "
            "il file da Supabase Storage",
            {
                "reason": str(e),
                "file_url": file_url,
                "bucket": MEDIA_BUCKET
            }
        )

        return

    # --------------------------------------------------------
    # MIME
    # --------------------------------------------------------

    mime_type = detect_mime_type(
        file_url,
        file_bytes
    )

    log(
        f"MIME: {mime_type}"
    )

    # --------------------------------------------------------
    # FILE ENGINE
    # --------------------------------------------------------

    log(
        "File engine: starting"
    )

    file_analysis = analyze_file(
        file_bytes,
        file_url,
        file_name,
        mime_type
    )

    log(
        f"File size: "
        f"{file_analysis['size_bytes']} bytes"
    )

    log(
        f"SHA-256: "
        f"{file_analysis['sha256']}"
    )

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    log(
        "C2PA: starting"
    )

    c2pa_result = check_c2pa_metadata(
        file_bytes,
        mime_type
    )

    c2pa_detected = bool(
        c2pa_result.get(
            "detected"
        )
    )

    log(
        f"C2PA detected: "
        f"{c2pa_detected}"
    )

    log(
        f"C2PA status: "
        f"{c2pa_result.get('status')}"
    )

    # --------------------------------------------------------
    # METADATA
    # --------------------------------------------------------

    log(
        "Metadata: starting"
    )

    metadata_result = analyze_metadata(
        file_bytes,
        mime_type
    )

    log(
        "Metadata signals: "
        f"{metadata_result.get('signals', [])}"
    )

    # --------------------------------------------------------
    # WATERMARK
    # --------------------------------------------------------

    log(
        "Watermark: starting"
    )

    watermark_result = check_watermark(
        file_bytes,
        mime_type
    )

    watermark_detected = (
        watermark_result.get(
            "detected"
        )
    )

    log(
        f"Watermark detected: "
        f"{watermark_detected}"
    )

    # --------------------------------------------------------
    # AI DETECTION
    # --------------------------------------------------------

    log(
        "AI detection: starting"
    )

    ai_result = run_ai_detection(
        file_bytes,
        mime_type
    )

    ai_score = ai_result.get(
        "score"
    )

    log(
        f"AI score: {ai_score}"
    )

    # --------------------------------------------------------
    # EVIDENCE ENGINE
    # --------------------------------------------------------

    log(
        "Evidence engine: starting"
    )

    evidence_result = build_evidence(
        file_analysis,
        c2pa_result,
        metadata_result,
        watermark_result,
        ai_result
    )

    log(
        "Evidence signals: "
        f"{evidence_result.get('signal_count')}"
    )

    # --------------------------------------------------------
    # RISK ENGINE
    # --------------------------------------------------------

    log(
        "Risk engine: starting"
    )

    risk_result = calculate_risk(
        c2pa_result,
        metadata_result,
        watermark_result,
        ai_result
    )

    log(
        f"Risk: "
        f"{risk_result.get('level')} "
        f"({risk_result.get('score')}/100)"
    )

    # --------------------------------------------------------
    # COMPLIANCE ENGINE
    # --------------------------------------------------------

    log(
        "Compliance engine: starting"
    )

    compliance_result = (
        evaluate_compliance(
            c2pa_result,
            ai_result,
            risk_result
        )
    )

    compliance_status = (
        compliance_result.get(
            "status"
        )
    )

    recommendation = (
        compliance_result.get(
            "reason"
        )
    )

    log(
        f"Compliance: "
        f"{compliance_status}"
    )

    # --------------------------------------------------------
    # FIXER
    # --------------------------------------------------------

    fixed_url = None

    if (
        compliance_status
        == "non_compliant"
    ):

        fixed_url = apply_c2pa_fix(
            file_bytes,
            audit_id,
            mime_type,
            file_name
        )

    # --------------------------------------------------------
    # DETAILS
    # --------------------------------------------------------

    details = {

        "worker": WORKER_NAME,

        "engine_version": "2.0",

        "file": file_analysis,

        "storage": {
            "input_bucket": MEDIA_BUCKET,
            "input_path": file_url,
            "fixer_bucket": FIXER_BUCKET
        },

        "c2pa": c2pa_result,

        "metadata": metadata_result,

        "watermark": watermark_result,

        "ai_detection": ai_result,

        "evidence": evidence_result,

        "risk": risk_result,

        "compliance": compliance_result,

        "recommendation": recommendation,

        "fixer": {
            "attempted": (
                compliance_status
                == "non_compliant"
            ),
            "fixed_file": (
                fixed_url
                is not None
            )
        }
    }

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    log(
        f"Updating audit {audit_id}"
    )

    update_data = {

        "compliance_status":
            compliance_status,

        "c2pa_detected":
            c2pa_detected,

        "watermark_detected":
            watermark_detected,

        "ai_score":
            ai_score,

        "file_hash":
            file_analysis[
                "sha256"
            ],

        "fixed_file_url":
            fixed_url,

        "details":
            details
    }

    success = update_audit(
        audit_id,
        update_data
    )

    if not success:

        log(
            f"ERRORE: impossibile completare "
            f"update audit {audit_id}"
        )

        return

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    log(
        "============================================================"
    )

    log(
        f"Audit {audit_id} completed: "
        f"{compliance_status}"
    )

    log(
        f"C2PA: {c2pa_detected}"
    )

    log(
        f"AI score: {ai_score}"
    )

    log(
        f"Watermark: {watermark_detected}"
    )

    log(
        f"Risk: "
        f"{risk_result.get('level')} "
        f"({risk_result.get('score')}/100)"
    )

    log(
        "============================================================"
    )


# ============================================================
# 22. PENDING AUDITS
# ============================================================

def process_pending_audits():

    try:

        response = (
            supabase
            .table("audits")
            .select("*")
            .eq(
                "compliance_status",
                "pending"
            )
            .order(
                "created_at",
                desc=False
            )
            .execute()
        )

        pending_audits = (
            response.data or []
        )

        log(
            "AUDIT PENDING TROVATI: "
            f"{len(pending_audits)}"
        )

        if not pending_audits:

            log(
                "Nessun audit pending."
            )

            return

        log(
            f"Trovati {len(pending_audits)} "
            "audit pending."
        )

        for audit in pending_audits:

            try:

                process_single_audit(
                    audit
                )

            except Exception as e:

                audit_id = audit.get(
                    "id"
                )

                log(
                    f"Errore non gestito "
                    f"nell'audit {audit_id}: {e}"
                )

                if audit_id:

                    mark_audit_error(
                        audit_id,
                        "Errore interno "
                        "durante l'elaborazione",
                        {
                            "reason": str(e)
                        }
                    )

    except Exception as e:

        log(
            "ERRORE ELABORAZIONE AUDIT: "
            f"{e}"
        )


# ============================================================
# 23. WORKER LOOP
# ============================================================

def audit_loop():

    log(
        "WORKER LOOP ATTIVO"
    )

    log(
        f"Intervallo: "
        f"{WORKER_INTERVAL_SECONDS}s"
    )

    log(
        f"Input bucket: "
        f"{MEDIA_BUCKET}"
    )

    log(
        f"Fixer bucket: "
        f"{FIXER_BUCKET}"
    )

    log(
        f"Max file size: "
        f"{MAX_FILE_SIZE_MB} MB"
    )

    while True:

        log(
            "CICLO WORKER"
        )

        try:

            process_pending_audits()

        except Exception as e:

            log(
                f"ERRORE WORKER: {e}"
            )

        time.sleep(
            WORKER_INTERVAL_SECONDS
        )


# ============================================================
# 24. STARTUP
# ============================================================

if __name__ == "__main__":

    log(
        "============================================================"
    )

    log(
        "AI ACT SHIELD ANALYZER STARTING"
    )

    log(
        f"Supabase: {SUPABASE_URL}"
    )

    log(
        f"Media bucket: {MEDIA_BUCKET}"
    )

    log(
        f"Fixer bucket: {FIXER_BUCKET}"
    )

    log(
        f"Worker interval: "
        f"{WORKER_INTERVAL_SECONDS}s"
    )

    log(
        "============================================================"
    )

    threading.Thread(
        target=audit_loop,
        daemon=True
    ).start()

    run_http_server()
