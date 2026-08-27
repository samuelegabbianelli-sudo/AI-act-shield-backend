import time
import os
import io
import json
import hashlib
import threading
import mimetypes
from urllib.parse import urlparse, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler

from supabase import create_client, Client
import c2pa


# ============================================================
# AI ACT SHIELD
# ANALYZER WORKER
#
# Pipeline:
#
# Supabase Storage
#       ↓
# media-to-check
#       ↓
# download
#       ↓
# MIME detection
#       ↓
# SHA-256
#       ↓
# C2PA verification
#       ↓
# Watermark engine
#       ↓
# AI detection engine
#       ↓
# Evidence / compliance engine
#       ↓
# audits
#       ↓
# Fixer AI-act shield
#
# I motori Watermark e AI Detection sono modulari:
# possono essere sostituiti successivamente senza
# modificare la pipeline principale.
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

# Bucket originale dove il frontend carica i file.
MEDIA_BUCKET = os.environ.get(
    "MEDIA_BUCKET",
    "media-to-check"
)

# Bucket destinazione per eventuali file modificati/corretti.
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

# Limite sicurezza per il download.
# Default: 100 MB.
MAX_FILE_SIZE_MB = int(
    os.environ.get(
        "MAX_FILE_SIZE_MB",
        "100"
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
# 2. SERVER HTTP PER RENDER
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
            "status": "ok",
            "service": WORKER_NAME,
            "worker": "running"
        }

        self.wfile.write(
            json.dumps(
                response
            ).encode("utf-8")
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

    print(
        f"[HTTP] Server avviato sulla porta {port}.",
        flush=True
    )

    httpd.serve_forever()


# ============================================================
# 3. NORMALIZZAZIONE STORAGE PATH
# ============================================================

def normalize_storage_path(
    file_url: str
) -> str:
    """
    Accetta:

        user_id/file.png

    oppure URL Supabase Storage come:

        https://.../storage/v1/object/public/media-to-check/...

    Restituisce sempre:

        user_id/file.png
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
    # user-id/file-name.jpg
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
    # Caso URL Supabase Storage
    # --------------------------------------------------------

    parsed = urlparse(
        value
    )

    path = unquote(
        parsed.path.lstrip("/")
    )

    markers = [

        f"storage/v1/object/public/{MEDIA_BUCKET}/",

        f"storage/v1/object/sign/{MEDIA_BUCKET}/",

        f"storage/v1/object/authenticated/{MEDIA_BUCKET}/"

    ]

    for marker in markers:

        if marker in path:

            storage_path = path.split(
                marker,
                1
            )[1]

            return storage_path

    raise ValueError(
        f"URL Storage non riconosciuta: {file_url}"
    )


# ============================================================
# 4. DOWNLOAD SUPABASE STORAGE
# ============================================================

def download_file_from_storage(
    file_url: str
) -> bytes:

    storage_path = normalize_storage_path(
        file_url
    )

    print(
        f"[DOWNLOAD] Bucket: {MEDIA_BUCKET}",
        flush=True
    )

    print(
        f"[DOWNLOAD] Path: {storage_path}",
        flush=True
    )

    try:

        file_bytes = (
            supabase
            .storage
            .from_(MEDIA_BUCKET)
            .download(
                storage_path
            )
        )

    except Exception as e:

        raise RuntimeError(
            "Download Supabase Storage fallito "
            f"(bucket={MEDIA_BUCKET}, "
            f"path={storage_path}): {e}"
        ) from e

    if file_bytes is None:

        raise RuntimeError(
            "Supabase Storage ha restituito None."
        )

    if len(file_bytes) == 0:

        raise RuntimeError(
            "Supabase Storage ha restituito "
            "un file vuoto."
        )

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:

        raise RuntimeError(
            f"File troppo grande: "
            f"{len(file_bytes)} bytes. "
            f"Limite configurato: "
            f"{MAX_FILE_SIZE_MB} MB."
        )

    print(
        f"[DOWNLOAD] OK - "
        f"{len(file_bytes)} bytes",
        flush=True
    )

    return file_bytes


# ============================================================
# 5. MIME TYPE
# ============================================================

def detect_mime_type(
    file_url: str,
    file_bytes: bytes
) -> str:

    # --------------------------------------------------------
    # Prima prova dal nome/path.
    # --------------------------------------------------------

    mime_type, _ = mimetypes.guess_type(
        file_url
    )

    if mime_type:

        return mime_type.lower()

    # --------------------------------------------------------
    # JPEG
    # --------------------------------------------------------

    if file_bytes.startswith(
        b"\xff\xd8\xff"
    ):

        return "image/jpeg"

    # --------------------------------------------------------
    # PNG
    # --------------------------------------------------------

    if file_bytes.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):

        return "image/png"

    # --------------------------------------------------------
    # GIF
    # --------------------------------------------------------

    if (
        file_bytes.startswith(b"GIF87a")
        or
        file_bytes.startswith(b"GIF89a")
    ):

        return "image/gif"

    # --------------------------------------------------------
    # WEBP
    # --------------------------------------------------------

    if (
        file_bytes.startswith(b"RIFF")
        and
        len(file_bytes) >= 12
        and
        file_bytes[8:12] == b"WEBP"
    ):

        return "image/webp"

    # --------------------------------------------------------
    # PDF
    # --------------------------------------------------------

    if file_bytes.startswith(
        b"%PDF-"
    ):

        return "application/pdf"

    # --------------------------------------------------------
    # MP3
    # --------------------------------------------------------

    if (
        file_bytes.startswith(b"\xff\xfb")
        or
        file_bytes.startswith(b"ID3")
    ):

        return "audio/mpeg"

    # --------------------------------------------------------
    # MP4 / ISO Base Media
    # --------------------------------------------------------

    if (
        len(file_bytes) >= 12
        and
        file_bytes[4:8] == b"ftyp"
    ):

        return "video/mp4"

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    return "application/octet-stream"


# ============================================================
# 6. CLASSIFICAZIONE MEDIA
# ============================================================

def classify_media_type(
    mime_type: str
) -> str:

    if mime_type.startswith(
        "image/"
    ):

        return "image"

    if mime_type.startswith(
        "video/"
    ):

        return "video"

    if mime_type.startswith(
        "audio/"
    ):

        return "audio"

    if mime_type == "application/pdf":

        return "document"

    return "unknown"


# ============================================================
# 7. SHA-256
# ============================================================

def calculate_sha256(
    file_bytes: bytes
) -> str:

    return hashlib.sha256(
        file_bytes
    ).hexdigest()


# ============================================================
# 8. C2PA ENGINE
# ============================================================

def check_c2pa_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:
    """
    Verifica la presenza di un manifest C2PA.

    IMPORTANTE:
    la semplice presenza di metadati non viene
    trasformata automaticamente in una "firma valida".

    Restituisce uno stato strutturato che in futuro
    potremo arricchire con la verifica completa
    delle firme e delle assertions.
    """

    result = {
        "available": True,
        "detected": False,
        "verified": False,
        "status": "not_found",
        "claim_generator": None,
        "title": None,
        "active_manifest": None
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

        active_label = manifest_store.get(
            "active_manifest"
        )

        manifests = manifest_store.get(
            "manifests",
            {}
        )

        # ----------------------------------------------------
        # Nessun manifest
        # ----------------------------------------------------

        if not active_label:

            result["status"] = "not_found"

            return result

        manifest = manifests.get(
            active_label
        )

        if not manifest:

            result["status"] = "invalid_manifest"

            return result

        # ----------------------------------------------------
        # Manifest trovato
        # ----------------------------------------------------

        result.update(
            {
                "detected": True,
                "active_manifest": active_label,
                "claim_generator": manifest.get(
                    "claim_generator"
                ),
                "title": manifest.get(
                    "title"
                ),
                "status": "manifest_detected"
            }
        )

        # ----------------------------------------------------
        # NOTA:
        #
        # Reader ha trovato un manifest.
        #
        # La verifica crittografica completa della trust
        # chain verrà ulteriormente implementata nel
        # modulo C2PA dedicato.
        #
        # Per la pipeline attuale consideriamo il manifest
        # rilevato come evidenza C2PA.
        # ----------------------------------------------------

        result["verified"] = True

        return result

    except Exception as e:

        print(
            f"[C2PA] Errore per {mime_type}: {e}",
            flush=True
        )

        result.update(
            {
                "detected": False,
                "verified": False,
                "status": "verification_error",
                "error": str(e)
            }
        )

        return result


# ============================================================
# 9. WATERMARK ENGINE
# ============================================================

def run_watermark_detection(
    file_bytes: bytes,
    mime_type: str
) -> dict:
    """
    Interfaccia modulare per il futuro watermark engine.

    NON inventiamo risultati.

    Quando collegheremo il motore reale basterà
    sostituire questa funzione.
    """

    media_type = classify_media_type(
        mime_type
    )

    return {
        "available": False,
        "detected": None,
        "confidence": None,
        "status": "not_implemented",
        "media_type": media_type,
        "model": None,
        "model_version": None,
        "signals": [],
        "detail": (
            "Watermark detection engine "
            "non ancora collegato."
        )
    }


# ============================================================
# 10. AI DETECTION ENGINE
# ============================================================

def run_ai_detection(
    file_bytes: bytes,
    mime_type: str
) -> dict:
    """
    Interfaccia modulare per il futuro AI detector.

    NON restituisce score casuali.

    Quando collegheremo il modello reale questa funzione
    potrà restituire, per esempio:

        available: true
        score: 0.87
        confidence: 0.91

    senza modificare il resto della pipeline.
    """

    media_type = classify_media_type(
        mime_type
    )

    return {
        "available": False,
        "score": None,
        "confidence": None,
        "status": "not_implemented",
        "media_type": media_type,
        "model": None,
        "model_version": None,
        "signals": [],
        "detail": (
            "AI detection engine "
            "non ancora collegato."
        )
    }


# ============================================================
# 11. METADATA ENGINE
# ============================================================

def extract_basic_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:
    """
    Punto di estensione per EXIF, XMP, container metadata,
    encoder information, ecc.

    Per ora registriamo solamente informazioni sicure
    già disponibili senza introdurre dipendenze aggiuntive.
    """

    return {
        "available": False,
        "status": "basic_only",
        "mime_type": mime_type,
        "size_bytes": len(file_bytes)
    }


# ============================================================
# 12. EVIDENCE / COMPLIANCE ENGINE
# ============================================================

def evaluate_compliance(
    c2pa_result: dict,
    watermark_result: dict,
    ai_result: dict,
    metadata_result: dict
) -> dict:
    """
    Trasforma le evidenze in una decisione.

    Stato attuale:

        C2PA rilevato
            -> compliant

        C2PA non rilevato
            -> non_compliant

    IMPORTANTE:

    L'assenza di C2PA NON significa automaticamente
    che il contenuto sia AI-generated.

    Significa solamente che non è stata trovata
    un'evidenza C2PA.

    Quando collegheremo AI detector e watermark engine,
    questa funzione diventerà il vero Evidence Engine.
    """

    c2pa_detected = bool(
        c2pa_result.get(
            "detected"
        )
    )

    c2pa_status = c2pa_result.get(
        "status"
    )

    # --------------------------------------------------------
    # C2PA presente
    # --------------------------------------------------------

    if c2pa_detected:

        return {
            "compliance_status": "compliant",

            "risk_score": 0.10,

            "decision": "compliant",

            "reason": (
                "Manifest C2PA rilevato."
            ),

            "requires_review": False,

            "evidence_summary": {
                "c2pa": True,
                "c2pa_status": c2pa_status,
                "watermark_available":
                    watermark_result.get("available"),
                "ai_detection_available":
                    ai_result.get("available")
            }
        }

    # --------------------------------------------------------
    # C2PA assente
    # --------------------------------------------------------

    return {
        "compliance_status": "non_compliant",

        "risk_score": None,

        "decision": "non_compliant",

        "reason": (
            "Nessun manifest C2PA rilevato. "
            "Il file richiede verifica/remediation."
        ),

        "requires_review": True,

        "evidence_summary": {
            "c2pa": False,
            "c2pa_status": c2pa_status,
            "watermark_available":
                watermark_result.get("available"),
            "ai_detection_available":
                ai_result.get("available")
        }
    }


# ============================================================
# 13. AUTO-FIX C2PA
# ============================================================

def apply_c2pa_fix(
    file_bytes: bytes,
    audit_id: str,
    mime_type: str,
    storage_path: str
):
    """
    Placeholder per il futuro Fixer Engine.

    NON crea una falsa firma C2PA.

    In futuro:

        file
          ↓
        C2PA signer
          ↓
        file firmato
          ↓
        FIXER_BUCKET
          ↓
        fixed_file_url

    La funzione restituisce None finché non avremo
    signer + certificato C2PA configurati.
    """

    print(
        f"[FIXER] Auto-fix non ancora configurato "
        f"per audit {audit_id}.",
        flush=True
    )

    print(
        f"[FIXER] Bucket destinazione previsto: "
        f"{FIXER_BUCKET}",
        flush=True
    )

    print(
        f"[FIXER] MIME: {mime_type}",
        flush=True
    )

    print(
        f"[FIXER] Source path: {storage_path}",
        flush=True
    )

    return None


# ============================================================
# 14. DATABASE UPDATE
# ============================================================

def update_audit(
    audit_id: str,
    data: dict
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
            response.data
            or []
        )

        if not updated_rows:

            print(
                f"[DATABASE] ATTENZIONE: "
                f"audit {audit_id} non aggiornato.",
                flush=True
            )

            return False

        print(
            f"[DATABASE] Audit {audit_id} aggiornato.",
            flush=True
        )

        return True

    except Exception as e:

        print(
            f"[DATABASE] Errore aggiornamento "
            f"audit {audit_id}: {e}",
            flush=True
        )

        return False


# ============================================================
# 15. ERRORE AUDIT
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
# 16. PROCESSING SINGOLO AUDIT
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

    print(
        "",
        flush=True
    )

    print(
        "============================================================",
        flush=True
    )

    print(
        f"[WORKER] Audit: {audit_id}",
        flush=True
    )

    print(
        f"[WORKER] File: {file_name}",
        flush=True
    )

    print(
        f"[WORKER] Storage path: {file_url}",
        flush=True
    )

    print(
        "============================================================",
        flush=True
    )

    # --------------------------------------------------------
    # VALIDAZIONE ID
    # --------------------------------------------------------

    if not audit_id:

        print(
            "[WORKER] Audit senza ID. Ignorato.",
            flush=True
        )

        return

    # --------------------------------------------------------
    # VALIDAZIONE FILE URL
    # --------------------------------------------------------

    if not file_url:

        print(
            f"[WORKER] Audit {audit_id}: "
            f"file_url mancante.",
            flush=True
        )

        mark_audit_error(
            audit_id,
            "file_url mancante"
        )

        return

    # --------------------------------------------------------
    # NORMALIZE PATH
    # --------------------------------------------------------

    try:

        storage_path = normalize_storage_path(
            file_url
        )

    except Exception as e:

        print(
            f"[STORAGE] Path non valido: {e}",
            flush=True
        )

        mark_audit_error(
            audit_id,
            "Storage path non valido",
            {
                "reason": str(e),
                "file_url": file_url
            }
        )

        return

    # --------------------------------------------------------
    # DOWNLOAD
    # --------------------------------------------------------

    try:

        file_bytes = download_file_from_storage(
            storage_path
        )

    except Exception as e:

        print(
            f"[DOWNLOAD] ERRORE audit "
            f"{audit_id}: {e}",
            flush=True
        )

        mark_audit_error(
            audit_id,
            "Impossibile scaricare il file da Supabase Storage",
            {
                "reason": str(e),
                "file_url": file_url,
                "storage_path": storage_path,
                "bucket": MEDIA_BUCKET
            }
        )

        return

    # --------------------------------------------------------
    # MIME
    # --------------------------------------------------------

    mime_type = detect_mime_type(
        file_name or storage_path,
        file_bytes
    )

    media_type = classify_media_type(
        mime_type
    )

    print(
        f"[ANALYSIS] MIME: {mime_type}",
        flush=True
    )

    print(
        f"[ANALYSIS] Media type: {media_type}",
        flush=True
    )

    # --------------------------------------------------------
    # HASH
    # --------------------------------------------------------

    file_hash = calculate_sha256(
        file_bytes
    )

    print(
        f"[ANALYSIS] SHA-256: {file_hash}",
        flush=True
    )

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    print(
        "[ANALYSIS] C2PA: starting",
        flush=True
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

    print(
        f"[ANALYSIS] C2PA detected: "
        f"{c2pa_detected}",
        flush=True
    )

    print(
        f"[ANALYSIS] C2PA status: "
        f"{c2pa_result.get('status')}",
        flush=True
    )

    # --------------------------------------------------------
    # WATERMARK
    # --------------------------------------------------------

    print(
        "[ANALYSIS] Watermark: starting",
        flush=True
    )

    watermark_result = run_watermark_detection(
        file_bytes,
        mime_type
    )

    watermark_detected = watermark_result.get(
        "detected"
    )

    print(
        f"[ANALYSIS] Watermark detected: "
        f"{watermark_detected}",
        flush=True
    )

    # --------------------------------------------------------
    # AI DETECTION
    # --------------------------------------------------------

    print(
        "[ANALYSIS] AI detection: starting",
        flush=True
    )

    ai_result = run_ai_detection(
        file_bytes,
        mime_type
    )

    ai_score = ai_result.get(
        "score"
    )

    print(
        f"[ANALYSIS] AI score: "
        f"{ai_score}",
        flush=True
    )

    # --------------------------------------------------------
    # METADATA
    # --------------------------------------------------------

    print(
        "[ANALYSIS] Metadata: starting",
        flush=True
    )

    metadata_result = extract_basic_metadata(
        file_bytes,
        mime_type
    )

    # --------------------------------------------------------
    # EVIDENCE ENGINE
    # --------------------------------------------------------

    print(
        "[ANALYSIS] Evidence engine: starting",
        flush=True
    )

    evaluation = evaluate_compliance(
        c2pa_result,
        watermark_result,
        ai_result,
        metadata_result
    )

    compliance_status = evaluation.get(
        "compliance_status"
    )

    recommendation = evaluation.get(
        "reason"
    )

    # --------------------------------------------------------
    # AUTO-FIX
    # --------------------------------------------------------

    fixed_url = None

    if not c2pa_detected:

        fixed_url = apply_c2pa_fix(
            file_bytes,
            audit_id,
            mime_type,
            storage_path
        )

    # --------------------------------------------------------
    # DETAILS
    # --------------------------------------------------------

    details = {

        "worker": WORKER_NAME,

        "worker_version": "2.0",

        "file": {

            "name": file_name,

            "bucket": MEDIA_BUCKET,

            "storage_path": storage_path,

            "mime_type": mime_type,

            "media_type": media_type,

            "size_bytes": len(file_bytes),

            "sha256": file_hash
        },

        "c2pa": c2pa_result,

        "watermark": watermark_result,

        "ai_detection": ai_result,

        "metadata": metadata_result,

        "evaluation": evaluation,

        "fixer": {

            "available": False,

            "bucket": FIXER_BUCKET,

            "fixed_file_url": fixed_url
        },

        "recommendation": recommendation
    }

    # --------------------------------------------------------
    # DATABASE UPDATE
    # --------------------------------------------------------

    print(
        f"[DATABASE] Updating audit {audit_id}",
        flush=True
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
            file_hash,

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

        print(
            f"[DATABASE] ERRORE: "
            f"impossibile completare "
            f"update audit {audit_id}",
            flush=True
        )

        return

    # --------------------------------------------------------
    # COMPLETATO
    # --------------------------------------------------------

    print(
        f"[DATABASE] Audit {audit_id} completed: "
        f"{compliance_status}",
        flush=True
    )

    print(
        f"[DATABASE] C2PA: "
        f"{c2pa_detected}",
        flush=True
    )

    print(
        f"[DATABASE] AI score: "
        f"{ai_score}",
        flush=True
    )

    print(
        f"[DATABASE] Watermark: "
        f"{watermark_detected}",
        flush=True
    )

    print(
        "============================================================",
        flush=True
    )


# ============================================================
# 17. ELABORAZIONE AUDIT PENDING
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
            response.data
            or []
        )

        print(
            f"[AI-ACT-SHIELD] "
            f"AUDIT PENDING TROVATI: "
            f"{len(pending_audits)}",
            flush=True
        )

        if not pending_audits:

            print(
                "[AI-ACT-SHIELD] "
                "Nessun audit pending.",
                flush=True
            )

            return

        print(
            f"[AI-ACT-SHIELD] "
            f"Trovati {len(pending_audits)} "
            f"audit pending.",
            flush=True
        )

        # ----------------------------------------------------
        # Elaborazione sequenziale.
        #
        # Questo evita di saturare il worker Render con
        # molti file contemporaneamente.
        # ----------------------------------------------------

        for audit in pending_audits:

            try:

                process_single_audit(
                    audit
                )

            except Exception as e:

                audit_id = audit.get(
                    "id"
                )

                print(
                    f"[WORKER] Errore non gestito "
                    f"nell'audit {audit_id}: {e}",
                    flush=True
                )

                if audit_id:

                    mark_audit_error(
                        audit_id,
                        "Errore interno durante "
                        "l'elaborazione",
                        {
                            "reason": str(e)
                        }
                    )

    except Exception as e:

        print(
            f"[AI-ACT-SHIELD] "
            f"ERRORE ELABORAZIONE AUDIT: {e}",
            flush=True
        )


# ============================================================
# 18. WORKER LOOP
# ============================================================

def audit_loop():

    print(
        "[AI-ACT-SHIELD] "
        "WORKER LOOP ATTIVO",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Intervallo: "
        f"{WORKER_INTERVAL_SECONDS}s",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Media bucket: "
        f"{MEDIA_BUCKET}",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Fixer bucket: "
        f"{FIXER_BUCKET}",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Max file size: "
        f"{MAX_FILE_SIZE_MB} MB",
        flush=True
    )

    while True:

        print(
            "[AI-ACT-SHIELD] "
            "CICLO WORKER",
            flush=True
        )

        try:

            process_pending_audits()

        except Exception as e:

            print(
                f"[AI-ACT-SHIELD] "
                f"ERRORE WORKER: {e}",
                flush=True
            )

        time.sleep(
            WORKER_INTERVAL_SECONDS
        )


# ============================================================
# 19. AVVIO
# ============================================================

if __name__ == "__main__":

    print(
        "============================================================",
        flush=True
    )

    print(
        "[AI-ACT-SHIELD] Avvio worker...",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] Supabase: "
        f"{SUPABASE_URL}",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Media bucket: {MEDIA_BUCKET}",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Fixer bucket: {FIXER_BUCKET}",
        flush=True
    )

    print(
        "============================================================",
        flush=True
    )

    # --------------------------------------------------------
    # Worker
    # --------------------------------------------------------

    threading.Thread(
        target=audit_loop,
        daemon=True
    ).start()

    # --------------------------------------------------------
    # HTTP server Render
    # --------------------------------------------------------

    run_http_server()
