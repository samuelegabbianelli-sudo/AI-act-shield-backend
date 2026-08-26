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

WORKER_NAME = "AI Act Shield"

WORKER_INTERVAL_SECONDS = int(
    os.environ.get("WORKER_INTERVAL_SECONDS", "5")
)

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY non configurata nelle Environment Variables di Render."
    )


supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# ============================================================
# 2. SERVER HTTP PER RENDER
# ============================================================

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        self.wfile.write(
            b"AI Act Shield Worker is Running!"
        )

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

    def log_message(self, format, *args):
        # Evita log HTTP inutili
        return


def run_http_server():

    port = int(
        os.environ.get("PORT", "10000")
    )

    server_address = ("", port)

    httpd = HTTPServer(
        server_address,
        SimpleHTTPRequestHandler
    )

    print(
        f"[AI-ACT-SHIELD] HTTP server avviato sulla porta {port}.",
        flush=True
    )

    httpd.serve_forever()


# ============================================================
# 3. NORMALIZZAZIONE PATH STORAGE
# ============================================================

def normalize_storage_path(file_url: str) -> str:
    """
    Il frontend salva normalmente file_url come:

        <user_id>/<filename>

    Non è una URL HTTP.

    Questa funzione accetta anche una eventuale URL Supabase
    completa, così il worker rimane compatibile con eventuali
    vecchi record.
    """

    if not file_url:
        raise ValueError("file_url vuoto")

    value = str(file_url).strip()

    # Caso normale:
    # user-id/nome-file.jpg
    if not value.startswith(("http://", "https://")):
        return unquote(value.lstrip("/"))

    # Compatibilità con eventuali URL Storage complete.
    parsed = urlparse(value)

    path = unquote(
        parsed.path.lstrip("/")
    )

    markers = [
        f"storage/v1/object/public/{MEDIA_BUCKET}/",
        f"storage/v1/object/sign/{MEDIA_BUCKET}/",
        f"storage/v1/object/authenticated/{MEDIA_BUCKET}/",
    ]

    for marker in markers:

        if marker in path:

            return path.split(
                marker,
                1
            )[1]

    # Se non riconosciamo il formato, non tentiamo
    # una richiesta HTTP: meglio fallire chiaramente.
    raise ValueError(
        f"URL Storage non riconosciuta: {file_url}"
    )


# ============================================================
# 4. DOWNLOAD DA SUPABASE STORAGE
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
            .download(storage_path)
        )

    except Exception as e:

        raise RuntimeError(
            f"Download Supabase Storage fallito "
            f"(bucket={MEDIA_BUCKET}, path={storage_path}): {e}"
        ) from e

    if not file_bytes:

        raise RuntimeError(
            "Supabase Storage ha restituito un file vuoto."
        )

    print(
        f"[DOWNLOAD] OK - {len(file_bytes)} bytes",
        flush=True
    )

    return file_bytes


# ============================================================
# 5. RILEVAZIONE MIME TYPE
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
    if file_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"

    # PNG
    if file_bytes.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        return "image/png"

    # GIF
    if (
        file_bytes.startswith(b"GIF87a")
        or file_bytes.startswith(b"GIF89a")
    ):
        return "image/gif"

    # WebP
    if (
        file_bytes.startswith(b"RIFF")
        and len(file_bytes) >= 12
        and file_bytes[8:12] == b"WEBP"
    ):
        return "image/webp"

    # PDF
    if file_bytes.startswith(b"%PDF-"):
        return "application/pdf"

    # MP3
    if (
        file_bytes.startswith(b"\xff\xfb")
        or file_bytes.startswith(b"ID3")
    ):
        return "audio/mpeg"

    # MP4 / ISO Base Media
    if (
        len(file_bytes) >= 12
        and file_bytes[4:8] == b"ftyp"
    ):
        return "video/mp4"

    return "application/octet-stream"


# ============================================================
# 6. HASH SHA-256
# ============================================================

def calculate_sha256(
    file_bytes: bytes
) -> str:

    return hashlib.sha256(
        file_bytes
    ).hexdigest()


# ============================================================
# 7. CONTROLLO C2PA
# ============================================================

def check_c2pa_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    try:

        stream = io.BytesIO(
            file_bytes
        )

        reader = c2pa.Reader(
            mime_type,
            stream
        )

        manifest_store = json.loads(
            reader.json()
        )

        active_label = manifest_store.get(
            "active_manifest"
        )

        manifests = manifest_store.get(
            "manifests",
            {}
        )

        if not active_label:

            return {
                "detected": False,
                "claim_generator": None,
                "title": None
            }

        manifest = manifests.get(
            active_label
        )

        if not manifest:

            return {
                "detected": False,
                "claim_generator": None,
                "title": None
            }

        return {
            "detected": True,
            "claim_generator": manifest.get(
                "claim_generator"
            ),
            "title": manifest.get(
                "title"
            ),
            "active_manifest": active_label
        }

    except Exception as e:

        print(
            f"[C2PA] Nessun manifest valido "
            f"rilevato per {mime_type}: {e}",
            flush=True
        )

        return {
            "detected": False,
            "claim_generator": None,
            "title": None,
            "error": str(e)
        }


# ============================================================
# 8. WATERMARK
# ============================================================
#
# NON inventiamo un risultato.
#
# Il rilevatore watermark reale non è ancora collegato
# al worker. Restituiamo quindi uno stato esplicito.
# ============================================================

def check_watermark(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    return {
        "detected": None,
        "status": "not_implemented",
        "detail": (
            "Watermark detection non ancora "
            "collegato al motore reale."
        )
    }


# ============================================================
# 9. AI DETECTION
# ============================================================
#
# NON restituiamo uno score casuale.
#
# Il modello AI detection reale dovrà essere collegato
# successivamente.
# ============================================================

def run_ai_detection(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    return {
        "available": False,
        "score": None,
        "status": "not_implemented",
        "detail": (
            "AI detection model non ancora "
            "collegato al worker."
        )
    }


# ============================================================
# 10. AUTO-FIX C2PA
# ============================================================

def apply_c2pa_fix(
    file_bytes: bytes,
    audit_id: str,
    mime_type: str
):

    print(
        f"[C2PA] Auto-fix non configurato "
        f"per audit {audit_id}.",
        flush=True
    )

    # Non generiamo una falsa firma C2PA.
    return None


# ============================================================
# 11. AGGIORNAMENTO AUDIT
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
            .eq("id", audit_id)
            .execute()
        )

        updated_rows = response.data or []

        if not updated_rows:

            print(
                f"[DATABASE] ATTENZIONE: audit {audit_id} "
                f"non aggiornato.",
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
# 12. GESTIONE ERRORE AUDIT
# ============================================================

def mark_audit_error(
    audit_id: str,
    error_message: str,
    extra_details: dict | None = None
):

    details = {
        "worker": WORKER_NAME,
        "error": error_message
    }

    if extra_details:
        details.update(
            extra_details
        )

    # Manteniamo lo schema attuale:
    # pending / compliant / non_compliant
    #
    # Non introduciamo uno stato "error" che potrebbe
    # non essere previsto dal database.
    update_audit(
        audit_id,
        {
            "compliance_status": "non_compliant",
            "details": details
        }
    )


# ============================================================
# 13. ELABORAZIONE SINGOLO AUDIT
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
        f"[WORKER] Audit pending: {audit_id}",
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

    if not audit_id:

        print(
            "[WORKER] Audit senza ID. Ignorato.",
            flush=True
        )

        return

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
    # DOWNLOAD
    # --------------------------------------------------------

    try:

        file_bytes = download_file_from_storage(
            file_url
        )

    except Exception as e:

        print(
            f"[DOWNLOAD] ERRORE audit {audit_id}: {e}",
            flush=True
        )

        mark_audit_error(
            audit_id,
            "Impossibile scaricare il file da Supabase Storage",
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

    print(
        f"[ANALYSIS] MIME: {mime_type}",
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
        f"[ANALYSIS] C2PA: starting",
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

    # --------------------------------------------------------
    # WATERMARK
    # --------------------------------------------------------

    print(
        f"[ANALYSIS] Watermark: starting",
        flush=True
    )

    watermark_result = check_watermark(
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
        f"[ANALYSIS] AI detection: starting",
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
        f"[ANALYSIS] AI score: {ai_score}",
        flush=True
    )

    # --------------------------------------------------------
    # C2PA AUTO-FIX
    # --------------------------------------------------------

    fixed_url = None

    if not c2pa_detected:

        fixed_url = apply_c2pa_fix(
            file_bytes,
            audit_id,
            mime_type
        )

    # --------------------------------------------------------
    # VALUTAZIONE
    # --------------------------------------------------------
    #
    # IMPORTANTE:
    #
    # Non consideriamo automaticamente "AI generated"
    # un file solo perché manca C2PA.
    #
    # L'assenza di C2PA significa semplicemente che
    # non abbiamo trovato un manifest C2PA.
    #
    # Per ora:
    #
    # C2PA presente -> compliant
    # C2PA assente  -> non_compliant
    #
    # Questa regola può essere raffinata successivamente
    # in base ai requisiti reali del prodotto.
    # --------------------------------------------------------

    if c2pa_detected:

        compliance_status = "compliant"

        recommendation = (
            "Manifest C2PA rilevato."
        )

    else:

        compliance_status = "non_compliant"

        recommendation = (
            "Nessun manifest C2PA rilevato. "
            "Il file richiede verifica/remediation."
        )

    # --------------------------------------------------------
    # DETTAGLI
    # --------------------------------------------------------

    details = {
        "worker": WORKER_NAME,
        "file_name": file_name,
        "storage_bucket": MEDIA_BUCKET,
        "storage_path": file_url,
        "mime_type": mime_type,
        "file_size": len(file_bytes),
        "sha256": file_hash,

        "c2pa": c2pa_result,

        "watermark": watermark_result,

        "ai_detection": ai_result,

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
        "compliance_status": compliance_status,

        "c2pa_detected": c2pa_detected,

        "watermark_detected": watermark_detected,

        "ai_score": ai_score,

        "file_hash": file_hash,

        "fixed_file_url": fixed_url,

        "details": details
    }

    success = update_audit(
        audit_id,
        update_data
    )

    if not success:

        print(
            f"[DATABASE] ERRORE: impossibile completare "
            f"update audit {audit_id}",
            flush=True
        )

        return

    print(
        f"[DATABASE] Audit {audit_id} completed: "
        f"{compliance_status}",
        flush=True
    )

    print(
        "============================================================",
        flush=True
    )


# ============================================================
# 14. ELABORAZIONE AUDIT PENDING
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

        pending_audits = response.data or []

        print(
            f"[AI-ACT-SHIELD] "
            f"AUDIT PENDING TROVATI: "
            f"{len(pending_audits)}",
            flush=True
        )

        if not pending_audits:

            print(
                "[AI-ACT-SHIELD] Nessun audit pending.",
                flush=True
            )

            return

        print(
            f"[AI-ACT-SHIELD] "
            f"Trovati {len(pending_audits)} audit pending.",
            flush=True
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

                print(
                    f"[WORKER] Errore non gestito "
                    f"nell'audit {audit_id}: {e}",
                    flush=True
                )

                if audit_id:

                    mark_audit_error(
                        audit_id,
                        "Errore interno durante l'elaborazione",
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
# 15. LOOP PRINCIPALE
# ============================================================

def audit_loop():

    print(
        "[AI-ACT-SHIELD] WORKER LOOP ATTIVO",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Intervallo: {WORKER_INTERVAL_SECONDS}s",
        flush=True
    )

    print(
        f"[AI-ACT-SHIELD] "
        f"Bucket Storage: {MEDIA_BUCKET}",
        flush=True
    )

    while True:

        print(
            "[AI-ACT-SHIELD] CICLO WORKER",
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
# 16. AVVIO
# ============================================================

if __name__ == "__main__":

    print(
        "[AI-ACT-SHIELD] Avvio worker...",
        flush=True
    )

    threading.Thread(
        target=audit_loop,
        daemon=True
    ).start()

    run_http_server()
