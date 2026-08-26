import time
import os
import io
import json
import threading
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from supabase import create_client, Client
import c2pa


# ============================================================
# 1. CONFIGURAZIONE SUPABASE
# ============================================================

SUPABASE_URL = "https://ulvlohhszcmdzqvipvan.supabase.co"

SUPABASE_SECRET_KEY = os.environ.get(
    "SUPABASE_SECRET_KEY",
    ""
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
        f"[AI-ACT-SHIELD] HTTP server avviato sulla porta {port}."
    )

    httpd.serve_forever()


# ============================================================
# 3. RILEVAZIONE MIME TYPE
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
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    # GIF
    if file_bytes.startswith(b"GIF87a") or file_bytes.startswith(b"GIF89a"):
        return "image/gif"

    # MP3
    if (
        file_bytes.startswith(b"\xff\xfb")
        or file_bytes.startswith(b"ID3")
    ):
        return "audio/mpeg"

    # MP4 / ISO Base Media
    if len(file_bytes) >= 12 and file_bytes[4:8] == b"ftyp":
        return "video/mp4"

    # WebP
    if (
        file_bytes.startswith(b"RIFF")
        and len(file_bytes) >= 12
        and file_bytes[8:12] == b"WEBP"
    ):
        return "image/webp"

    # Fallback
    return "application/octet-stream"


# ============================================================
# 4. CONTROLLO C2PA
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
            )
        }

    except Exception as e:

        print(
            f"[C2PA] Nessun manifest valido rilevato per {mime_type}: {e}"
        )

        return {
            "detected": False,
            "claim_generator": None,
            "title": None,
            "error": str(e)
        }


# ============================================================
# 5. AUTO-FIX C2PA
# ============================================================
#
# IMPORTANTE:
# Una vera firma C2PA richiede un signer/certificato.
# Non inseriamo una "finta" firma nel file.
#
# Per ora questa funzione restituisce None.
# La implementeremo dopo aver configurato il certificato
# C2PA corretto.
# ============================================================

def apply_c2pa_fix(
    file_bytes: bytes,
    audit_id: str,
    mime_type: str
):

    print(
        f"[C2PA] Auto-fix non ancora configurato per audit {audit_id}."
    )

    return None


# ============================================================
# 6. AGGIORNAMENTO AUDIT
# ============================================================

def update_audit(
    audit_id,
    data
):

    try:

        supabase.table(
            "audits"
        ).update(
            data
        ).eq(
            "id",
            audit_id
        ).execute()

    except Exception as e:

        print(
            f"[SUPABASE] Errore aggiornamento audit {audit_id}: {e}"
        )


# ============================================================
# 7. ELABORAZIONE AUDIT PENDING
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
            .execute()
        )

        pending_audits = response.data or []

        if not pending_audits:

            print(
                "[AI-ACT-SHIELD] Nessun audit pending."
            )

            return

        print(
            f"[AI-ACT-SHIELD] Trovati {len(pending_audits)} audit pending."
        )

        for audit in pending_audits:

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
                f"[AI-ACT-SHIELD] Analisi audit {audit_id} - {file_name}"
            )

            # ------------------------------------------------
            # URL mancante
            # ------------------------------------------------

            if not file_url:

                print(
                    f"[AI-ACT-SHIELD] Audit {audit_id}: file_url mancante."
                )

                update_audit(
                    audit_id,
                    {
                        "compliance_status": "non_compliant",
                        "details": {
                            "error": "URL file mancante",
                            "worker": "AI Act Shield"
                        }
                    }
                )

                continue

            # ------------------------------------------------
            # DOWNLOAD FILE
            # ------------------------------------------------

            try:

                file_res = requests.get(
                    file_url,
                    timeout=30
                )

                file_res.raise_for_status()

                file_bytes = file_res.content

            except Exception as e:

                print(
                    f"[DOWNLOAD] Errore audit {audit_id}: {e}"
                )

                update_audit(
                    audit_id,
                    {
                        "compliance_status": "non_compliant",
                        "details": {
                            "error": "Impossibile scaricare il file",
                            "reason": str(e),
                            "worker": "AI Act Shield"
                        }
                    }
                )

                continue

            # ------------------------------------------------
            # MIME TYPE
            # ------------------------------------------------

            mime_type = detect_mime_type(
                file_url,
                file_bytes
            )

            print(
                f"[AI-ACT-SHIELD] MIME rilevato: {mime_type}"
            )

            # ------------------------------------------------
            # CONTROLLO C2PA
            # ------------------------------------------------

            c2pa_result = check_c2pa_metadata(
                file_bytes,
                mime_type
            )

            c2pa_detected = bool(
                c2pa_result.get("detected")
            )

            # ------------------------------------------------
            # VALUTAZIONE
            # ------------------------------------------------

            if c2pa_detected:

                compliance_status = "compliant"

                # Score basso = basso rischio generativo
                ai_score = 0.10

                fixed_url = None

                recommendation = (
                    "File con manifest C2PA rilevato."
                )

            else:

                compliance_status = "non_compliant"

                # Score alto = necessita verifica/intervento
                ai_score = 0.85

                # Il vero auto-fix C2PA verrà configurato
                # successivamente con un signer valido.
                fixed_url = apply_c2pa_fix(
                    file_bytes,
                    audit_id,
                    mime_type
                )

                if fixed_url:

                    recommendation = (
                        "File privo di C2PA. "
                        "Applicata firma C2PA."
                    )

                else:

                    recommendation = (
                        "File privo di manifest C2PA. "
                        "Auto-fix C2PA non ancora configurato."
                    )

            # ------------------------------------------------
            # SALVATAGGIO RISULTATO
            # ------------------------------------------------

            details = {
                "worker": "AI Act Shield",
                "mime_type": mime_type,
                "ai_score": ai_score,
                "c2pa_info": c2pa_result,
                "recommendation": recommendation
            }

            update_audit(
                audit_id,
                {
                    "compliance_status": compliance_status,
                    "c2pa_detected": c2pa_detected,
                    "ai_score": ai_score,
                    "fixed_file_url": fixed_url,
                    "details": details
                }
            )

            print(
                f"[AI-ACT-SHIELD] Audit {audit_id} completato: "
                f"{compliance_status}"
            )
    except Exception as e:
        print(f"[AI-ACT-SHIELD] Errore nell'elaborazione audit: {e}")

# ============================================================
# 8. LOOP PRINCIPALE
# ============================================================

def audit_loop():

    print(
        "[AI-ACT-SHIELD] AI Act Shield real analysis worker avviato."
    )

    while True:

        try:

            process_pending_audits()

        except Exception as e:

            print(
                f"[AI-ACT-SHIELD] Errore generale worker: {e}"
            )

        time.sleep(5)


# ============================================================
# 9. AVVIO
# ============================================================

if __name__ == "__main__":

    threading.Thread(
        target=audit_loop,
        daemon=True
    ).start()

    run_http_server()
