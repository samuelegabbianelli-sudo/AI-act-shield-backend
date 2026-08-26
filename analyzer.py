import hashlib
import io
import json
import mimetypes
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import c2pa
from supabase import Client, create_client


# ============================================================
# CONFIGURAZIONE
# ============================================================

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://ulvlohhszcmdzqvipvan.supabase.co",
)

SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY non configurata. "
        "Impostala nelle Environment Variables di Render."
    )

supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY,
)


MEDIA_BUCKET = "media-to-check"
FIXED_BUCKET = "Fixer AI-act shield"

PENDING_STATUS = "pending"
COMPLIANT_STATUS = "compliant"
NON_COMPLIANT_STATUS = "non_compliant"

POLL_INTERVAL_SECONDS = 3

# TTL usato solo quando generiamo URL temporanee lato worker.
SIGNED_URL_TTL = 300


# ============================================================
# HEALTH CHECK SERVER
# ============================================================

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"AI Act Shield Worker is Running!"
        )

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.end_headers()

    def log_message(self, format, *args):
        # Evita log HTTP inutilmente rumorosi.
        return


def run_http_server():
    port = int(os.environ.get("PORT", "10000"))

    server_address = ("", port)

    httpd = HTTPServer(
        server_address,
        SimpleHTTPRequestHandler,
    )

    print(f"HTTP health server avviato sulla porta {port}")

    httpd.serve_forever()


# ============================================================
# UTILITY
# ============================================================

def log(message: str):
    print(f"[AI-ACT-SHIELD] {message}", flush=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_mime_type(
    file_name: str,
    declared_mime: str | None,
) -> str:

    if declared_mime and declared_mime != "application/octet-stream":
        return declared_mime

    guessed, _ = mimetypes.guess_type(file_name)

    if guessed:
        return guessed

    return "application/octet-stream"


def is_supported_for_c2pa(mime_type: str) -> bool:
    """
    C2PA support depends on the actual asset format supported
    by the installed c2pa SDK.

    We explicitly support common image/video/audio MIME types
    used by this application.
    """

    return (
        mime_type.startswith("image/")
        or mime_type.startswith("video/")
        or mime_type.startswith("audio/")
    )


# ============================================================
# SUPABASE STORAGE
# ============================================================

def download_storage_file(
    bucket: str,
    path: str,
) -> bytes:

    log(f"Download Storage: {bucket}/{path}")

    response = (
        supabase.storage
        .from_(bucket)
        .download(path)
    )

    if response is None:
        raise RuntimeError(
            f"Storage download vuoto: {bucket}/{path}"
        )

    return response


def upload_storage_file(
    bucket: str,
    path: str,
    data: bytes,
    mime_type: str,
):
    log(f"Upload Storage: {bucket}/{path}")

    result = (
        supabase.storage
        .from_(bucket)
        .upload(
            file=data,
            path=path,
            file_options={
                "content-type": mime_type,
                "cache-control": "3600",
                "upsert": "true",
            },
        )
    )

    return result


def create_signed_storage_url(
    bucket: str,
    path: str,
    expires_in: int = SIGNED_URL_TTL,
) -> str:

    result = (
        supabase.storage
        .from_(bucket)
        .create_signed_url(
            path,
            expires_in,
        )
    )

    if isinstance(result, dict):
        signed_url = result.get("signedURL") or result.get("signedUrl")
    else:
        signed_url = getattr(result, "signed_url", None)

    if not signed_url:
        raise RuntimeError(
            f"Impossibile creare signed URL: {bucket}/{path}"
        )

    return signed_url


# ============================================================
# C2PA — LETTURA REALE
# ============================================================

def check_c2pa_metadata(
    file_bytes: bytes,
    mime_type: str,
) -> dict:

    result = {
        "detected": False,
        "valid": False,
        "claim_generator": None,
        "title": None,
        "active_manifest": None,
        "validation_state": None,
        "signature_info": None,
        "error": None,
    }

    try:
        if not is_supported_for_c2pa(mime_type):
            result["error"] = (
                f"Formato non supportato dal worker C2PA: {mime_type}"
            )
            return result

        stream = io.BytesIO(file_bytes)

        with c2pa.Reader(mime_type, stream) as reader:

            manifest_store = json.loads(
                reader.json()
            )

            active_label = manifest_store.get(
                "active_manifest"
            )

            result["active_manifest"] = active_label

            manifests = manifest_store.get(
                "manifests",
                {},
            )

            if not active_label:
                return result

            manifest = manifests.get(
                active_label
            )

            if not manifest:
                return result

            result["detected"] = True

            result["claim_generator"] = (
                manifest.get("claim_generator")
            )

            result["title"] = (
                manifest.get("title")
            )

            signature_info = manifest.get(
                "signature_info"
            )

            result["signature_info"] = signature_info

            # La presenza del manifest non significa
            # automaticamente che la firma sia trusted.
            validation_state = None

            try:
                validation_state = reader.get_validation_state()
            except Exception:
                pass

            result["validation_state"] = validation_state

            # In questa prima versione consideriamo il manifest
            # effettivamente presente come C2PA detected.
            #
            # La trust validation viene conservata separatamente
            # e non viene trasformata arbitrariamente in "trusted".
            result["valid"] = True

    except Exception as exc:
        result["error"] = str(exc)

        log(
            f"C2PA Reader error ({mime_type}): {exc}"
        )

    return result


# ============================================================
# C2PA — SIGNER
# ============================================================

def create_c2pa_signer():
    """
    Crea il signer C2PA usando credenziali presenti nelle
    Environment Variables di Render.

    ENV richieste:

        C2PA_CERT_CHAIN
        C2PA_PRIVATE_KEY

    Opzionale:

        C2PA_TSA_URL

    La private key NON deve mai essere inserita nel repository.
    """

    cert_chain = os.environ.get(
        "C2PA_CERT_CHAIN"
    )

    private_key = os.environ.get(
        "C2PA_PRIVATE_KEY"
    )

    tsa_url = os.environ.get(
        "C2PA_TSA_URL",
        "http://timestamp.digicert.com",
    )

    if not cert_chain or not private_key:
        return None

    try:

        signer_info = c2pa.C2paSignerInfo(
            alg=c2pa.C2paSigningAlg.ES256,
            sign_cert=cert_chain.encode("utf-8"),
            private_key=private_key.encode("utf-8"),
            ta_url=tsa_url.encode("utf-8"),
        )

        return c2pa.Signer.from_info(
            signer_info
        )

    except Exception as exc:

        log(
            f"Creazione signer C2PA fallita: {exc}"
        )

        return None


# ============================================================
# C2PA — REMEDIATION REALE
# ============================================================

def apply_c2pa_fix(
    file_bytes: bytes,
    file_name: str,
    mime_type: str,
    audit_id: str,
) -> tuple[bytes, str]:

    signer = create_c2pa_signer()

    if signer is None:
        raise RuntimeError(
            "C2PA signer non configurato. "
            "Impostare C2PA_CERT_CHAIN e C2PA_PRIVATE_KEY "
            "nelle Environment Variables di Render."
        )

    manifest_definition = {
        "claim_generator_info": [
            {
                "name": "AI Act Shield",
                "version": "1.0.0",
            }
        ],
        "title": file_name,
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                        },
                        {
                            "action": "c2pa.edited",
                            "parameters": {
                                "description": (
                                    "AI Act Shield transparency "
                                    "remediation workflow."
                                )
                            },
                        },
                    ]
                },
            }
        ],
    }

    source = io.BytesIO(file_bytes)
    output = io.BytesIO()

    try:

        with signer:

            with c2pa.Builder(
                manifest_definition
            ) as builder:

                builder.sign(
                    signer,
                    mime_type,
                    source,
                    output,
                )

        fixed_bytes = output.getvalue()

    except Exception as exc:

        raise RuntimeError(
            f"Firma C2PA fallita: {exc}"
        ) from exc

    if not fixed_bytes:
        raise RuntimeError(
            "C2PA Builder non ha prodotto alcun file."
        )

    # Mantiene il nome originale ma aggiunge
    # un suffisso identificativo.
    base, ext = os.path.splitext(file_name)

    if not ext:
        ext = extension_from_mime(mime_type)

    fixed_name = (
        f"{base}-ai-act-shield{ext}"
    )

    # Il frontend utilizza path <user_id>/...
    # quindi il path viene costruito dal chiamante.
    return fixed_bytes, fixed_name


def extension_from_mime(
    mime_type: str,
) -> str:

    mapping = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/tiff": ".tiff",
        "video/mp4": ".mp4",
        "video/quicktime": ".mov",
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav",
    }

    return mapping.get(
        mime_type,
        ".bin",
    )


# ============================================================
# DATABASE
# ============================================================

def update_audit(
    audit_id: str,
    payload: dict,
):

    result = (
        supabase
        .table("audits")
        .update(payload)
        .eq("id", audit_id)
        .execute()
    )

    return result


def get_pending_audits():

    result = (
        supabase
        .table("audits")
        .select("*")
        .eq(
            "compliance_status",
            PENDING_STATUS,
        )
        .order(
            "created_at",
            desc=False,
        )
        .limit(10)
        .execute()
    )

    return result.data or []


# ============================================================
# ANALISI SINGOLO AUDIT
# ============================================================

def process_audit(
    audit: dict,
):

    audit_id = audit.get("id")
    user_id = audit.get("user_id")
    file_url = audit.get("file_url")
    file_name = audit.get("file_name") or "asset"
    declared_mime = audit.get("file_type")

    if not audit_id:
        log("Audit senza ID: ignorato.")
        return

    log(
        f"Inizio analisi audit {audit_id}"
    )

    if not user_id:
        update_audit(
            audit_id,
            {
                "compliance_status": NON_COMPLIANT_STATUS,
                "details": {
                    "error": "Audit privo di user_id.",
                    "engine": "AI Act Shield C2PA Engine",
                },
            },
        )
        return

    if not file_url:
        update_audit(
            audit_id,
            {
                "compliance_status": NON_COMPLIANT_STATUS,
                "details": {
                    "error": "File URL/path mancante.",
                    "engine": "AI Act Shield C2PA Engine",
                },
            },
        )
        return

    try:

        # ----------------------------------------------------
        # Il frontend salva normalmente un path Storage.
        # Per compatibilità gestiamo anche vecchie URL.
        # ----------------------------------------------------

        storage_path = file_url

        if "/storage/v1/object/" in storage_path:

            parts = storage_path.split(
                "/storage/v1/object/",
                1,
            )[1]

            parts = parts.split("/", 1)

            if len(parts) == 2:
                # public/sign/authenticated
                path_part = parts[1]

                bucket_and_path = path_part.split(
                    "/",
                    1,
                )

                if len(bucket_and_path) == 2:
                    storage_path = bucket_and_path[1]

        # ----------------------------------------------------
        # Sicurezza: l'audit deve puntare alla cartella
        # dell'utente.
        # ----------------------------------------------------

        expected_prefix = f"{user_id}/"

        if not storage_path.startswith(
            expected_prefix
        ):
            raise RuntimeError(
                "Il file_url non appartiene alla cartella "
                "Storage dell'utente."
            )

        # ----------------------------------------------------
        # Download reale da bucket privato
        # ----------------------------------------------------

        file_bytes = download_storage_file(
            MEDIA_BUCKET,
            storage_path,
        )

        if not file_bytes:
            raise RuntimeError(
                "Il file scaricato è vuoto."
            )

        # ----------------------------------------------------
        # MIME
        # ----------------------------------------------------

        mime_type = normalize_mime_type(
            file_name,
            declared_mime,
        )

        # ----------------------------------------------------
        # HASH REALE
        # ----------------------------------------------------

        file_hash = (
            "sha256:"
            + sha256_bytes(file_bytes)
        )

        # ----------------------------------------------------
        # ANALISI C2PA REALE
        # ----------------------------------------------------

        c2pa_result = check_c2pa_metadata(
            file_bytes,
            mime_type,
        )

        detected = bool(
            c2pa_result.get("detected")
        )

        # ----------------------------------------------------
        # DECISIONE
        #
        # In questa versione:
        #
        # C2PA manifest presente -> compliant
        # C2PA manifest assente  -> non_compliant
        #
        # Questo NON significa automaticamente che il
        # contenuto soddisfi ogni obbligo dell'AI Act.
        # È una verifica di provenienza/trasparenza C2PA.
        # ----------------------------------------------------

        if detected:

            status = COMPLIANT_STATUS

            score = 0.10

            fixed_file_url = None

            details = {
                "engine": (
                    "AI Act Shield C2PA Engine v1.0"
                ),
                "engine_mode": "real",
                "mime_type": mime_type,
                "generative_score": score,
                "c2pa": c2pa_result,
                "watermark": {
                    "detected": False,
                    "note": (
                        "Watermark analysis not implemented "
                        "by the C2PA engine."
                    ),
                },
                "ai_detection": {
                    "status": "not_implemented",
                    "note": (
                        "AI-generation detection is not "
                        "inferred from C2PA presence."
                    ),
                },
            }

            update_audit(
                audit_id,
                {
                    "compliance_status": status,
                    "c2pa_detected": True,
                    "watermark_detected": False,
                    "ai_score": score,
                    "file_hash": file_hash,
                    "fixed_file_url": fixed_file_url,
                    "details": details,
                },
            )

            log(
                f"Audit {audit_id}: C2PA manifest rilevato."
            )

            return

        # ----------------------------------------------------
        # NON COMPLIANT
        # ----------------------------------------------------

        status = NON_COMPLIANT_STATUS

        score = 0.85

        fixed_file_url = None

        details = {
            "engine": (
                "AI Act Shield C2PA Engine v1.0"
            ),
            "engine_mode": "real",
            "mime_type": mime_type,
            "generative_score": score,
            "c2pa": c2pa_result,
            "watermark": {
                "detected": False,
                "note": (
                    "Watermark analysis not implemented "
                    "by the C2PA engine."
                ),
            },
            "ai_detection": {
                "status": "not_implemented",
                "note": (
                    "AI-generation detection is not "
                    "inferred from C2PA absence."
                ),
            },
            "recommendation": (
                "No C2PA manifest detected."
            ),
        }

        # ----------------------------------------------------
        # Prima aggiorniamo l'audit a non_compliant.
        # ----------------------------------------------------

        update_audit(
            audit_id,
            {
                "compliance_status": status,
                "c2pa_detected": False,
                "watermark_detected": False,
                "ai_score": score,
                "file_hash": file_hash,
                "fixed_file_url": None,
                "details": details,
            },
        )

        log(
            f"Audit {audit_id}: nessun manifest C2PA."
        )

        # ----------------------------------------------------
        # Remediation automatica
        #
        # IMPORTANTE:
        # se il signer non è configurato, NON fingiamo
        # che la remediation sia avvenuta.
        # ----------------------------------------------------

        try:

            fixed_bytes, fixed_name = (
                apply_c2pa_fix(
                    file_bytes,
                    file_name,
                    mime_type,
                    audit_id,
                )
            )

            fixed_path = (
                f"{user_id}/{audit_id}-{fixed_name}"
            )

            upload_storage_file(
                FIXED_BUCKET,
                fixed_path,
                fixed_bytes,
                mime_type,
            )

            # ------------------------------------------------
            # Verifica del file appena firmato.
            # ------------------------------------------------

            verification = check_c2pa_metadata(
                fixed_bytes,
                mime_type,
            )

            if not verification.get(
                "detected"
            ):

                raise RuntimeError(
                    "Il file sanato è stato prodotto "
                    "ma la verifica successiva non "
                    "rileva alcun manifest C2PA."
                )

            fixed_details = {
                **details,
                "remediation": {
                    "status": "completed",
                    "engine": (
                        "AI Act Shield C2PA Engine v1.0"
                    ),
                    "fixed_path": fixed_path,
                    "verification": verification,
                },
            }

            update_audit(
                audit_id,
                {
                    "compliance_status": (
                        COMPLIANT_STATUS
                    ),
                    "c2pa_detected": True,
                    "watermark_detected": False,
                    "ai_score": score,
                    "file_hash": file_hash,
                    "fixed_file_url": fixed_path,
                    "details": fixed_details,
                },
            )

            log(
                f"Audit {audit_id}: remediation C2PA completata."
            )

        except Exception as remediation_error:

            log(
                f"Audit {audit_id}: remediation non eseguita: "
                f"{remediation_error}"
            )

            update_audit(
                audit_id,
                {
                    "details": {
                        **details,
                        "remediation": {
                            "status": "failed",
                            "error": str(
                                remediation_error
                            ),
                        },
                    },
                },
            )

    except Exception as exc:

        log(
            f"ERRORE audit {audit_id}: {exc}"
        )

        update_audit(
            audit_id,
            {
                "compliance_status": (
                    NON_COMPLIANT_STATUS
                ),
                "details": {
                    "engine": (
                        "AI Act Shield C2PA Engine v1.0"
                    ),
                    "engine_mode": "real",
                    "error": str(exc),
                },
            },
        )


# ============================================================
# WORKER LOOP
# ============================================================

def process_pending_audits():

    try:

        audits = get_pending_audits()

        if not audits:
            return

        log(
            f"Trovati {len(audits)} audit pending."
        )

        for audit in audits:

            try:
                process_audit(audit)

            except Exception as exc:

                audit_id = audit.get(
                    "id",
                    "unknown",
                )

                log(
                    f"Errore non gestito audit "
                    f"{audit_id}: {exc}"
                )

    except Exception as exc:

        log(
            f"Errore durante la scansione della coda: "
            f"{exc}"
        )


def audit_loop():

    log(
        "AI Act Shield real analysis worker avviato."
    )

    while True:

        process_pending_audits()

        time.sleep(
            POLL_INTERVAL_SECONDS
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    worker_thread = threading.Thread(
        target=audit_loop,
        daemon=True,
    )

    worker_thread.start()

    run_http_server()
