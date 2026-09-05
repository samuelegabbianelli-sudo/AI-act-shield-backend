import time
import os
import io
import json
import hashlib
import threading
import mimetypes
import struct
import tempfile
import urllib.request

from urllib.parse import urlparse, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler

from supabase import create_client, Client
import c2pa
from c2pa import (
    Context,
    Builder,
    Signer,
    C2paSignerInfo,
    C2paSigningAlg,
    C2paBuilderIntent,
)

from ai_detector import analyze_image


# ============================================================
# AI ACT SHIELD
# ANALYZER ENGINE 3.0
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
# ANALYZER ENGINE 3.0
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
# - "compliant" indica conformità tecnica rispetto alle
#   regole attualmente implementate, NON certificazione
#   legale definitiva di conformità all'AI Act.
#
# C2PA v2.2:
#
# detected:
#   Manifest C2PA rilevato.
#
# valid:
#   Integrità /validazione tecnica del manifest considerata
#   valida, anche se il certificato di firma non è trusted.
#
# trusted:
#   Signing credential trusted rispetto alla trust list
#   C2PA configurata.
#
# signingCredential.untrusted:
#   NON viene trattato come una firma/hash corrotta.
#   Viene distinto da un failure reale di integrità.
#
# Stati C2PA principali:
#
#   not_detected
#       Nessun manifest C2PA.
#
#   valid_untrusted
#       Manifest tecnicamente valido ma signer non trusted.
#
#   trusted
#       Manifest valido e signer trusted.
#
#   invalid
#       Manifest presente con failure reali di validazione.
#
#   detected_unverified
#       Manifest rilevato ma impossibile dimostrare
#       sufficientemente validità /trust.
# ============================================================


# ============================================================
# 1. CONFIGURAZIONE
# ============================================================

ENGINE_VERSION = "3.0"
WORKER_NAME = "AI Act Shield"

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


# ============================================================
# C2PA TRUST CONFIGURATION
# ============================================================

# Trust list ufficiale C2PA.
#
# Fonte:
# c2pa-org/conformance-public
#
# Può essere sovrascritta tramite Environment Variable.
C2PA_TRUST_LIST_URL = os.environ.get(
    "C2PA_TRUST_LIST_URL",
    "https://raw.githubusercontent.com/"
    "c2pa-org/conformance-public/"
    "refs/heads/main/trust-list/C2PA-TRUST-LIST.pem"
)

C2PA_TRUST_LIST_TIMEOUT_SECONDS = int(
    os.environ.get(
        "C2PA_TRUST_LIST_TIMEOUT_SECONDS",
        "15"
    )
)

# Se presente, questo PEM ha precedenza sulla URL.
#
# Deve contenere uno o più certificati PEM:
#
# -----BEGIN CERTIFICATE-----
# ...
# -----END CERTIFICATE-----
#
C2PA_TRUST_ANCHORS_PEM = os.environ.get(
    "C2PA_TRUST_ANCHORS_PEM",
    ""
)

# Certificati aggiuntivi interni ad AI Act Shield.
# Se valorizzato, viene aggiunto tramite user_anchors senza
# sostituire la trust list ufficiale C2PA.
C2PA_USER_ANCHORS_PEM = os.environ.get(
    "C2PA_USER_ANCHORS_PEM",
    ""
)

C2PA_CONTEXT = None

C2PA_TRUST_SOURCE = None

# ============================================================
# C2PA FIXER SIGNING
# ============================================================

C2PA_SIGNING_ENABLED = (
    os.environ.get(
        "C2PA_SIGNING_ENABLED",
        "false"
    ).lower()
    == "true"
)

C2PA_SIGNING_CERT_PEM = os.environ.get(
    "C2PA_SIGNING_CERT_PEM",
    ""
)

C2PA_SIGNING_PRIVATE_KEY_PEM = os.environ.get(
    "C2PA_SIGNING_PRIVATE_KEY_PEM",
    ""
)
FIXER_API_KEY = os.environ.get(
    "FIXER_API_KEY",
    ""
)
C2PA_SIGNING_ALGORITHM = os.environ.get(
    "C2PA_SIGNING_ALGORITHM",
    "ES256"
)

C2PA_TIMESTAMP_URL = os.environ.get(
    "C2PA_TIMESTAMP_URL",
    ""
)

# ============================================================
# SUPABASE CLIENT
# ============================================================

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
# 3. C2PA TRUST INITIALIZATION
# ============================================================

def load_c2pa_trust_anchors() -> tuple[str, str]:

    # --------------------------------------------------------
    # 1. PEM fornito direttamente da Environment Variable
    # --------------------------------------------------------

    if C2PA_TRUST_ANCHORS_PEM.strip():

        pem = (
            C2PA_TRUST_ANCHORS_PEM
            .strip()
        )

        if "BEGIN CERTIFICATE" not in pem:

            raise RuntimeError(
                "C2PA_TRUST_ANCHORS_PEM configurata "
                "ma non contiene certificati PEM validi."
            )

        log(
            "C2PA trust list: "
            "usando PEM fornito via Environment Variable."
        )

        return (
            pem,
            "environment"
        )

    # --------------------------------------------------------
    # 2. Trust List ufficiale C2PA
    # --------------------------------------------------------

    log(
        "C2PA trust list: "
        f"download da {C2PA_TRUST_LIST_URL}"
    )

    try:

        request = urllib.request.Request(
            C2PA_TRUST_LIST_URL,
            headers={
                "User-Agent":
                    f"{WORKER_NAME}/{ENGINE_VERSION}"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=C2PA_TRUST_LIST_TIMEOUT_SECONDS
        ) as response:

            pem_bytes = response.read()

        pem = (
            pem_bytes
            .decode("utf-8")
            .strip()
        )

    except Exception as e:

        raise RuntimeError(
            "Impossibile caricare la trust list C2PA "
            f"da {C2PA_TRUST_LIST_URL}: {e}"
        ) from e

    if not pem:

        raise RuntimeError(
            "La trust list C2PA è vuota."
        )

    if "BEGIN CERTIFICATE" not in pem:

        raise RuntimeError(
            "La trust list C2PA scaricata non contiene "
            "certificati PEM validi."
        )

    log(
        "C2PA trust list: caricata correttamente."
    )

    return (
        pem,
        C2PA_TRUST_LIST_URL
    )


def initialize_c2pa_context():

    global C2PA_CONTEXT
    global C2PA_TRUST_SOURCE

    anchors, source = (
        load_c2pa_trust_anchors()
    )

    user_anchors = C2PA_USER_ANCHORS_PEM.strip()

    if user_anchors and "BEGIN CERTIFICATE" not in user_anchors:
        raise RuntimeError(
            "C2PA_USER_ANCHORS_PEM configurata "
            "ma non contiene certificati PEM validi."
        )

    # --------------------------------------------------------
    # Context C2PA
    #
    # trust_anchors:
    #   usa esplicitamente la trust list configurata.
    #
    # user_anchors:
    #   aggiunge certificati interni senza sostituire
    #   la trust list ufficiale C2PA.
    #
    # verify_trust:
    #   abilita la verifica del signing credential.
    #
    # verify_after_reading:
    #   mantiene attiva la verifica durante la lettura.
    #
    # remote_manifest_fetch:
    #   mantiene la possibilità di recuperare manifest
    #   remoti referenziati dal contenuto.
    # --------------------------------------------------------

    trust_config = {
        "trust_anchors": anchors
    }

    if user_anchors:
        trust_config["user_anchors"] = user_anchors

    config = {

        "trust": trust_config,

        "verify": {

            "verify_after_reading":
                True,

            "verify_trust":
                True,

            "verify_timestamp_trust":
                True,

            "ocsp_fetch":
                False,

            "remote_manifest_fetch":
                True
        }
    }

    try:

        C2PA_CONTEXT = Context.from_dict(
            config
        )

    except Exception as e:

        raise RuntimeError(
            "Impossibile inizializzare "
            "il Context C2PA: "
            f"{e}"
        ) from e

    C2PA_TRUST_SOURCE = source

    log(
        "C2PA context inizializzato."
    )

    log(
        "C2PA trust verification: ENABLED"
    )

    if user_anchors:
        log(
            "C2PA additional user trust anchors: ENABLED"
        )
    else:
        log(
            "C2PA additional user trust anchors: DISABLED"
        )

    log(
        "C2PA trust source: "
        f"{C2PA_TRUST_SOURCE}"
    )


# ============================================================
# AUTHENTICATION
# ============================================================

def authenticate_supabase_request(
    handler
):
    """
    Autentica una richiesta HTTP tramite
    Supabase access token.

    Legge:
        Authorization: Bearer <access_token>

    Restituisce:
        user_id

    Solleva ValueError se la richiesta
    non è autenticata o il token non è valido.
    """

    auth_header = handler.headers.get(
        "Authorization",
        ""
    )

    if not auth_header:
        raise ValueError(
            "Authorization header missing"
        )

    if not auth_header.startswith(
        "Bearer "
    ):
        raise ValueError(
            "Authorization header must use Bearer token"
        )

    token = auth_header[
        len("Bearer "):
    ].strip()

    if not token:
        raise ValueError(
            "Access token missing"
        )

    try:
        response = (
            supabase
            .auth
            .get_user(token)
        )
    except Exception as e:
        log(
            f"Supabase token validation error: {e}"
        )

        raise ValueError(
            "Invalid access token"
        ) from e

    user = getattr(
        response,
        "user",
        None
    )

    if user is None:
        raise ValueError(
            "Invalid access token"
        )

    user_id = getattr(
        user,
        "id",
        None
    )

    if not user_id:
        raise ValueError(
            "User ID not found in token"
        )

    return user_id


# ============================================================
# 4. HTTP SERVER PER RENDER
# ============================================================

class SimpleHTTPRequestHandler(
    BaseHTTPRequestHandler
):
    def do_OPTIONS(self):
        self.send_response(204)

        self.send_header(
            "Access-Control-Allow-Origin",
            "*"
        )

        self.send_header(
            "Access-Control-Allow-Methods",
            "POST, OPTIONS"
        )

        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type"
        )

        self.send_header(
            "Access-Control-Max-Age",
            "600"
        )

        self.end_headers()

    def do_POST(self):
        if self.path != "/fixer/c2pa":
            self.send_response(404)

            self.send_header(
                "Access-Control-Allow-Origin",
                "*"
            )
            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type"
            )

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps({
                    "ok": False,
                    "error": "Not found"
                }).encode("utf-8")
            )
            return

        try:
            authenticated_user_id = (
                authenticate_supabase_request(
                    self
                )
            )

        except ValueError as e:
            self.send_response(401)

            self.send_header(
                "Access-Control-Allow-Origin",
                "*"
            )

            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type"
            )

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps({
                    "ok": False,
                    "error": str(e)
                }).encode("utf-8")
            )

            return

        content_type = self.headers.get(
            "Content-Type",
            ""
        )

        if "application/json" not in content_type.lower():
            self.send_response(400)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "ok": False,
                    "error": (
                        "Content-Type must be "
                        "application/json"
                    )
                }).encode("utf-8")
            )
            return

        try:
            content_length = int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )

            body = self.rfile.read(
                content_length
            )

            payload = json.loads(
                body.decode("utf-8")
            )

        except Exception:
            self.send_response(400)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "ok": False,
                    "error": "Invalid JSON body"
                }).encode("utf-8")
            )
            return

        audit_id = payload.get(
            "audit_id"
        )

        if not audit_id or not isinstance(
            audit_id,
            str
        ):
            self.send_response(400)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "ok": False,
                    "error": "audit_id is required"
                }).encode("utf-8")
            )
            return

        try:
            audit_response = (
                supabase
                .table("audits")
                .select(
                    "id, user_id, compliance_status, "
                    "fixed_file_url, file_url"
                )
                .eq(
                    "id",
                    audit_id
                )
                .limit(1)
                .execute()
            )

            audits = (
                audit_response.data or []
            )

            if not audits:
                self.send_response(404)

                self.send_header(
                    "Access-Control-Allow-Origin",
                    "*"
                )

                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type"
                )

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "ok": False,
                        "error": "Audit not found"
                    }).encode("utf-8")
                )

                return

            audit = audits[0]

            if audit.get("user_id") != authenticated_user_id:
                self.send_response(403)

                self.send_header(
                    "Access-Control-Allow-Origin",
                    "*"
                )

                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type"
                )

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "ok": False,
                        "error": "Forbidden"
                    }).encode("utf-8")
                )

                return

            compliance_status = (
                audit.get(
                    "compliance_status"
                )
            )

            if compliance_status not in (
                "manual_review",
                "non_compliant"
            ):
                self.send_response(409)

                self.send_header(
                    "Access-Control-Allow-Origin",
                    "*"
                )

                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type"
                )

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "ok": False,
                        "error": (
                            "Audit is not eligible "
                            "for remediation"
                        )
                    }).encode("utf-8")
                )

                return

            existing_fixed_url = (
                audit.get(
                    "fixed_file_url"
                )
            )

            if existing_fixed_url:
                self.send_response(200)

                self.send_header(
                    "Access-Control-Allow-Origin",
                    "*"
                )

                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type"
                )

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "ok": True,
                        "audit_id": audit_id,
                        "status": (
                            "already_remediated"
                        ),
                        "fixed_file_url": (
                            existing_fixed_url
                        )
                    }).encode("utf-8")
                )

                return

            file_url = audit.get(
                "file_url"
            )

            if not file_url:
                self.send_response(404)

                self.send_header(
                    "Access-Control-Allow-Origin",
                    "*"
                )

                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type"
                )

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "ok": False,
                        "error": (
                            "Original file not found"
                        )
                    }).encode("utf-8")
                )

                return

            print(
                "Fixer manual remediation started"
            )

            file_bytes, storage_path = (
                download_file_from_storage(
                    file_url
                )
            )

            file_name = os.path.basename(
                storage_path
            )

            mime_type = detect_mime_type(
                storage_path,
                file_bytes
            )

            fixed_url = apply_c2pa_fix(
                file_bytes,
                audit_id,
                mime_type,
                file_name
            )

            if not fixed_url:
                print(
                    "Fixer manual remediation failed"
                )

                self.send_response(500)

                self.send_header(
                    "Access-Control-Allow-Origin",
                    "*"
                )

                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type"
                )

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "ok": False,
                        "error": (
                            "C2PA remediation failed"
                        )
                    }).encode("utf-8")
                )

                return

            (
                supabase
                .table("audits")
                .update({
                    "fixed_file_url": fixed_url
                })
                .eq(
                    "id",
                    audit_id
                )
                .execute()
            )

            print(
                "Fixer manual remediation completed"
            )

            self.send_response(200)

            self.send_header(
                "Access-Control-Allow-Origin",
                "*"
            )

            self.send_header(
                "Access-Control-Allow-Methods",
                "POST, OPTIONS"
            )

            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type"
            )

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps({
                    "ok": True,
                    "audit_id": audit_id,
                    "status": "remediated",
                    "fixed_file_url": fixed_url
                }).encode("utf-8")
            )

        except Exception as exc:
            print(
                f"Fixer manual remediation error: "
                f"{exc}"
            )

            self.send_response(500)

            self.send_header(
                "Access-Control-Allow-Origin",
                "*"
            )

            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type"
            )

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps({
                    "ok": False,
                    "error": "Internal server error"
                }).encode("utf-8")
            )


# ============================================================
# 5. STORAGE
# ============================================================

def normalize_storage_path(file_url: str):
    """Extract only the object path from an audit file_url."""
    if not file_url:
        raise ValueError("file_url vuoto")

    value = str(file_url).strip()

    if value.startswith("storage://"):
        parsed = urlparse(value)
        bucket = unquote(parsed.netloc)
        object_path = unquote(parsed.path.lstrip("/"))

        if bucket and bucket != MEDIA_BUCKET:
            raise ValueError(
                f"Bucket Storage inatteso: {bucket}. Atteso: {MEDIA_BUCKET}"
            )

        if not object_path:
            raise ValueError("Storage reference priva di path")

        return object_path

    if not value.startswith(("http://", "https://")):
        return unquote(value.lstrip("/"))

    parsed = urlparse(value)
    path = unquote(parsed.path.lstrip("/"))

    markers = [
        "storage/v1/object/public/" + MEDIA_BUCKET + "/",
        "storage/v1/object/sign/" + MEDIA_BUCKET + "/",
        "storage/v1/object/authenticated/" + MEDIA_BUCKET + "/",
        "storage/v1/object/download/" + MEDIA_BUCKET + "/",
    ]

    for marker in markers:
        if marker in path:
            object_path = path.split(marker, 1)[1]
            if object_path:
                return object_path

    raise ValueError(
        f"URL Storage non riconosciuta per il bucket {MEDIA_BUCKET}: {file_url}"
    )


def download_file_from_storage(file_url: str):
    storage_path = normalize_storage_path(file_url)

    log(f"Download bucket={MEDIA_BUCKET}")
    log(f"Download path={storage_path}")

    response = (
        supabase
        .storage
        .from_(MEDIA_BUCKET)
        .download(storage_path)
    )

    if response is None:
        raise RuntimeError("Download Storage restituisce None")

    file_bytes = bytes(response)

    if not file_bytes:
        raise RuntimeError("File scaricato vuoto")

    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        raise RuntimeError(
            "File troppo grande: "
            f"{len(file_bytes)} bytes"
        )

    return file_bytes, storage_path


# ============================================================
# 6. FILE UTILITIES
# ============================================================

def detect_mime_type(
    file_name: str,
    file_bytes: bytes
):
    guessed, _ = mimetypes.guess_type(
        file_name
    )

    if guessed:
        return guessed

    if file_bytes.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        return "image/png"

    if file_bytes.startswith(
        b"\xff\xd8\xff"
    ):
        return "image/jpeg"

    if file_bytes.startswith(
        b"RIFF"
    ) and file_bytes[8:12] == b"WEBP":
        return "image/webp"

    if file_bytes.startswith(
        b"GIF87a"
    ) or file_bytes.startswith(
        b"GIF89a"
    ):
        return "image/gif"

    if file_bytes.startswith(
        b"%PDF"
    ):
        return "application/pdf"

    return "application/octet-stream"


def sha256_hex(file_bytes: bytes):
    return hashlib.sha256(
        file_bytes
    ).hexdigest()


def is_supported_media(mime_type: str):
    return (
        mime_type.startswith("image/")
        or mime_type.startswith("video/")
        or mime_type == "application/pdf"
    )


# ============================================================
# 7. C2PA ANALYSIS
# ============================================================

def _flatten_validation_results(node):
    """
    Appiattisce ricorsivamente validation_results
    per facilitare il parsing dei codici C2PA.
    """

    if isinstance(node, dict):
        yield node

        for value in node.values():
            yield from _flatten_validation_results(
                value
            )

    elif isinstance(node, list):
        for item in node:
            yield from _flatten_validation_results(
                item
            )


def _collect_validation_codes(node):
    codes = []

    for item in _flatten_validation_results(
        node
    ):
        code = item.get("code")

        if isinstance(code, str):
            codes.append(code)

    return codes


def _collect_validation_errors(node):
    errors = []

    for item in _flatten_validation_results(
        node
    ):
        code = item.get("code")

        if not isinstance(code, str):
            continue

        if code == "signingCredential.untrusted":
            continue

        errors.append(item)

    return errors


def _find_active_manifest(node):
    if not isinstance(node, dict):
        return None

    manifests = node.get(
        "manifests"
    )

    if isinstance(manifests, dict):
        active = manifests.get(
            "active_manifest"
        )

        if active:
            return active

    return None


def _extract_signing_credential(node):
    for item in _flatten_validation_results(
        node
    ):
        credential = item.get(
            "signingCredential"
        )

        if isinstance(credential, dict):
            return credential

    return None


def _extract_issuer_from_json(node):
    credential = _extract_signing_credential(
        node
    )

    if not credential:
        return None

    issuer = credential.get(
        "issuer"
    )

    if isinstance(issuer, str):
        return issuer

    if isinstance(issuer, dict):
        for key in (
            "commonName",
            "organization",
            "name"
        ):
            value = issuer.get(key)
            if value:
                return value

    return None


def check_c2pa_metadata(
    file_bytes: bytes,
    mime_type: str
):
    result = {
        "detected": False,
        "valid": False,
        "trusted": False,
        "status": "not_detected",
        "validation_state": None,
        "validation_status": [],
        "validation_errors": [],
        "signing_credential": None,
        "issuer": None,
        "raw": None
    }

    if C2PA_CONTEXT is None:
        initialize_c2pa_context()

    stream = io.BytesIO(
        file_bytes
    )

    try:
        reader = c2pa.Reader(
            mime_type,
            stream,
            context=C2PA_CONTEXT
        )

        raw_json = reader.json()

    except Exception as e:
        message = str(e)

        # Nessun manifest C2PA rilevato:
        # non deve diventare automaticamente
        # un errore tecnico.
        if (
            "manifest" in message.lower()
            or
            "c2pa" in message.lower()
        ):
            result["status"] = (
                "detected_unverified"
            )
            result["detected"] = True
            result["validation_errors"] = [
                {
                    "code": "reader.error",
                    "message": message
                }
            ]

        return result

    try:
        parsed = json.loads(
            raw_json
        ) if isinstance(
            raw_json,
            str
        ) else raw_json

    except Exception:
        parsed = raw_json

    result["raw"] = parsed

    if not isinstance(
        parsed,
        dict
    ):
        return result

    # --------------------------------------------------------
    # Manifest detection
    # --------------------------------------------------------

    manifests = parsed.get(
        "manifests"
    )

    active_manifest = _find_active_manifest(
        parsed
    )

    if manifests or active_manifest:
        result["detected"] = True

    # --------------------------------------------------------
    # Validation state
    # --------------------------------------------------------

    validation_state = parsed.get(
        "validation_state"
    )

    if validation_state is None:
        validation_state = parsed.get(
            "validationState"
        )

    result["validation_state"] = (
        validation_state
    )

    validation_status = parsed.get(
        "validation_status"
    )

    if validation_status is None:
        validation_status = parsed.get(
            "validationStatus"
        )

    if isinstance(
        validation_status,
        list
    ):
        result["validation_status"] = (
            validation_status
        )

    validation_results = parsed.get(
        "validation_results"
    )

    if validation_results is None:
        validation_results = parsed.get(
            "validationResults"
        )

    all_codes = _collect_validation_codes(
        validation_results
    )

    validation_errors = _collect_validation_errors(
        validation_results
    )

    # --------------------------------------------------------
    # signingCredential
    # --------------------------------------------------------

    credential = _extract_signing_credential(
        validation_results
    )

    if credential is not None:
        result["signing_credential"] = credential

    issuer = _extract_issuer_from_json(
        validation_results
    )

    if issuer is None:
        issuer = _extract_issuer_from_json(
            parsed
        )

    result["issuer"] = issuer

    # --------------------------------------------------------
    # IMPORTANT C2PA TRUST LOGIC
    # --------------------------------------------------------
    #
    # signingCredential.untrusted significa:
    #
    #   "il certificato non è nella trust list"
    #
    # e NON:
    #
    #   "firma/hash del manifest è corrotta"
    #
    # Quindi:
    #
    #   valid + untrusted -> valid_untrusted
    #
    # mentre:
    #
    #   real validation failure -> invalid
    #
    trusted_from_success = (
        "signingCredential.trusted"
        in all_codes
    )

    trusted_from_state = (
        str(validation_state).lower()
        == "trusted"
    )

    result["trusted"] = bool(
        (
            trusted_from_success
            or
            trusted_from_state
        )
        and
        not validation_errors
    )

    # --------------------------------------------------------
    # VALIDITY LOGIC
    # --------------------------------------------------------

    real_validation_errors = [
        item
        for item in validation_errors
        if item.get("code") not in (
            "timeStamp.untrusted",
            "ingredient.unknownProvenance"
        )
    ]

    result["validation_errors"] = (
        real_validation_errors
    )

    has_real_errors = bool(
        real_validation_errors
    )

    has_manifest = bool(
        result["detected"]
    )

    if not has_manifest:
        result["status"] = (
            "not_detected"
        )
        return result

    if has_real_errors:
        result["valid"] = False
        result["trusted"] = False
        result["status"] = "invalid"
        return result

    # C2PA manifest presente e senza
    # failure di integrità.
    result["valid"] = True

    if result["trusted"]:
        result["status"] = "trusted"

    elif (
        "signingCredential.untrusted"
        in all_codes
    ):
        result["status"] = (
            "valid_untrusted"
        )

    elif (
        str(validation_state).lower()
        == "valid"
    ):
        result["status"] = (
            "valid_untrusted"
        )

    else:
        result["status"] = (
            "detected_unverified"
        )

    return result


# ============================================================
# 8. AI DETECTION
# ============================================================

def check_ai_detection(
    file_bytes: bytes,
    mime_type: str,
    file_name: str
):
    result = {
        "available": False,
        "ai_generated": None,
        "score": None,
        "provider": None,
        "raw": None,
        "error": None
    }

    if not mime_type.startswith(
        "image/"
    ):
        return result

    try:
        analysis = analyze_image(
            file_bytes,
            file_name
        )

    except Exception as e:
        result["error"] = str(e)
        return result

    if not isinstance(
        analysis,
        dict
    ):
        return result

    result["available"] = bool(
        analysis.get(
            "available",
            True
        )
    )

    result["ai_generated"] = (
        analysis.get(
            "ai_generated"
        )
    )

    result["score"] = analysis.get(
        "score"
    )

    result["provider"] = analysis.get(
        "provider"
    )

    result["raw"] = analysis.get(
        "raw",
        analysis
    )

    result["error"] = analysis.get(
        "error"
    )

    return result


# ============================================================
# 9. WATERMARK / METADATA EVIDENCE
# ============================================================

def scan_text_markers(
    file_bytes: bytes
):
    markers = []

    sample = file_bytes[
        :min(
            len(file_bytes),
            2 * 1024 * 1024
        )
    ]

    lowered = sample.lower()

    known_markers = [
        b"c2pa",
        b"jumbf",
        b"content credentials",
        b"contentcredentials",
        b"adobe",
        b"openai",
        b"synthetic",
        b"ai-generated",
        b"generated by ai",
        b"watermark"
    ]

    for marker in known_markers:
        if marker in lowered:
            markers.append(
                marker.decode(
                    "utf-8",
                    errors="ignore"
                )
            )

    return sorted(
        set(markers)
    )


def analyze_metadata(
    file_bytes: bytes,
    mime_type: str
):
    result = {
        "markers": scan_text_markers(
            file_bytes
        ),
        "size_bytes": len(
            file_bytes
        ),
        "mime_type": mime_type
    }

    return result


# ============================================================
# 10. RISK ENGINE
# ============================================================

def evaluate_risk(
    c2pa_result,
    ai_result,
    metadata_result
):
    score = 0
    reasons = []

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    if c2pa_result.get(
        "status"
    ) == "invalid":

        score += 80

        reasons.append(
            "Manifest C2PA presente ma con errori di validazione."
        )

    elif c2pa_result.get(
        "status"
    ) == "valid_untrusted":

        score += 25

        reasons.append(
            "Manifest C2PA valido ma signing credential non trusted."
        )

    elif c2pa_result.get(
        "status"
    ) == "trusted":

        score = max(
            0,
            score - 50
        )

        reasons.append(
            "Manifest C2PA valido e signing credential trusted."
        )

    # --------------------------------------------------------
    # AI detector
    # --------------------------------------------------------

    ai_score = ai_result.get(
        "score"
    )

    if isinstance(
        ai_score,
        (int, float)
    ):

        if ai_score >= 0.90:
            score += 60
            reasons.append(
                "AI detector: alta probabilità di contenuto sintetico."
            )

        elif ai_score >= 0.70:
            score += 40
            reasons.append(
                "AI detector: probabilità significativa di contenuto sintetico."
            )

        elif ai_score >= 0.50:
            score += 20
            reasons.append(
                "AI detector: evidenza moderata di contenuto sintetico."
            )

    # --------------------------------------------------------
    # Metadata markers
    # --------------------------------------------------------

    markers = metadata_result.get(
        "markers",
        []
    )

    if "watermark" in markers:
        score = max(
            0,
            score - 10
        )

        reasons.append(
            "Marker di watermark rilevato."
        )

    return {
        "score": max(
            0,
            min(
                100,
                int(score)
            )
        ),
        "reasons": reasons
    }


# ============================================================
# 11. COMPLIANCE ENGINE
# ============================================================

def evaluate_compliance(
    c2pa_result,
    ai_result,
    risk_result
):
    c2pa_status = c2pa_result.get(
        "status"
    )

    if c2pa_status == "trusted":
        return {
            "status": "compliant",
            "decision": "c2pa_trusted",
            "reason": (
                "Provenienza C2PA verificata e trusted. "
                "La verifica crittografica ha priorità "
                "rispetto alla classificazione probabilistica "
                "del detector AI."
            ),
            "decision_basis": (
                "C2PA trusted"
            )
        }

    if c2pa_status == "valid_untrusted":
        return {
            "status": "manual_review",
            "decision": "c2pa_valid_untrusted",
            "reason": (
                "Manifest C2PA valido, ma signing credential "
                "non presente nella trust list configurata. "
                "È richiesta revisione manuale."
            ),
            "decision_basis": (
                "C2PA valid but untrusted"
            )
        }

    if c2pa_status == "invalid":
        return {
            "status": "non_compliant",
            "decision": "c2pa_invalid",
            "reason": (
                "Manifest C2PA presente ma con errori "
                "di validazione."
            ),
            "decision_basis": (
                "C2PA invalid"
            )
        }

    ai_score = ai_result.get(
        "score"
    )

    if isinstance(
        ai_score,
        (int, float)
    ):

        if ai_score >= 0.90:
            return {
                "status": "non_compliant",
                "decision": "ai_high_confidence",
                "reason": (
                    "Il detector AI indica alta probabilità "
                    "di contenuto sintetico senza evidenza C2PA trusted."
                ),
                "decision_basis": (
                    "AI detector high confidence"
                )
            }

        if ai_score >= 0.70:
            return {
                "status": "manual_review",
                "decision": "ai_significant_probability",
                "reason": (
                    "Il detector AI indica una probabilità significativa "
                    "di contenuto sintetico."
                ),
                "decision_basis": (
                    "AI detector significant probability"
                )
            }

    if c2pa_status == "not_detected":
        return {
            "status": "non_compliant",
            "decision": "no_provenance",
            "reason": (
                "Nessuna provenienza C2PA verificabile rilevata."
            ),
            "decision_basis": (
                "No C2PA provenance"
            )
        }

    return {
        "status": "manual_review",
        "decision": "insufficient_evidence",
        "reason": (
            "Le evidenze disponibili non consentono "
            "una valutazione automatica definitiva."
        ),
        "decision_basis": (
            "Insufficient evidence"
        )
    }


# ============================================================
# 12. AUDIT PERSISTENCE
# ============================================================

def update_audit(
    audit_id: str,
    payload: dict
):
    # Supabase schema may contain fewer columns than the analyzer payload.
    # Retry by removing only the exact column rejected by PostgREST.
    # This keeps valid audit fields such as compliance_status/details.
    safe_payload = dict(payload)
    safe_payload.pop("status", None)

    while safe_payload:
        try:
            (
                supabase
                .table("audits")
                .update(safe_payload)
                .eq(
                    "id",
                    audit_id
                )
                .execute()
            )
            return
        except Exception as e:
            message = str(e)
            import re
            match = re.search(
                r"Could not find the '([^']+)' column",
                message
            )
            if not match:
                match = re.search(
                    r"column '([^']+)' does not exist",
                    message
                )
            if not match:
                match = re.search(
                    r"column ([A-Za-z0-9_]+) does not exist",
                    message
                )
            if not match:
                raise

            bad_column = match.group(1)
            if bad_column not in safe_payload:
                raise

            log(
                f"Audit update: rimuovo colonna non presente nello schema: {bad_column}"
            )
            safe_payload.pop(bad_column, None)


# ============================================================
# 13. C2PA FIXER
# ============================================================

def _get_signing_algorithm():
    algorithm_map = {
        "ES256": C2paSigningAlg.ES256,
        "ES384": C2paSigningAlg.ES384,
        "ES512": C2paSigningAlg.ES512,
        "PS256": C2paSigningAlg.PS256,
        "PS384": C2paSigningAlg.PS384,
        "PS512": C2paSigningAlg.PS512,
        "ED25519": C2paSigningAlg.ED25519
    }

    key = C2PA_SIGNING_ALGORITHM.upper()

    if key not in algorithm_map:
        raise ValueError(
            "C2PA_SIGNING_ALGORITHM non supportato: "
            f"{C2PA_SIGNING_ALGORITHM}"
        )

    return algorithm_map[key]


def apply_c2pa_fix(
    file_bytes: bytes,
    audit_id: str,
    mime_type: str,
    file_name: str
):
    if not C2PA_SIGNING_ENABLED:
        raise RuntimeError(
            "C2PA signing non abilitato."
        )

    if not C2PA_SIGNING_CERT_PEM.strip():
        raise RuntimeError(
            "C2PA_SIGNING_CERT_PEM non configurato."
        )

    if not C2PA_SIGNING_PRIVATE_KEY_PEM.strip():
        raise RuntimeError(
            "C2PA_SIGNING_PRIVATE_KEY_PEM non configurato."
        )

    signer_info = C2paSignerInfo(
        cert_pem=C2PA_SIGNING_CERT_PEM,
        private_key_pem=C2PA_SIGNING_PRIVATE_KEY_PEM,
        algorithm=_get_signing_algorithm()
    )

    if C2PA_TIMESTAMP_URL.strip():
        signer_info.timestamp_url = (
            C2PA_TIMESTAMP_URL.strip()
        )

    signer = Signer.from_info(
        signer_info
    )

    builder = Builder(
        {
            "claim_generator": (
                "AI Act Shield"
            ),
            "claim_generator_info": [
                {
                    "name": "AI Act Shield",
                    "version": ENGINE_VERSION
                }
            ],
            "title": file_name,
            "format": mime_type,
            "instance_id": (
                f"ai-act-shield:{audit_id}"
            )
        }
    )

    builder.set_intent(
        C2paBuilderIntent.CREATE
    )

    input_stream = io.BytesIO(
        file_bytes
    )

    output_stream = io.BytesIO()

    builder.sign(
        signer,
        mime_type,
        input_stream,
        output_stream
    )

    fixed_bytes = output_stream.getvalue()

    if not fixed_bytes:
        raise RuntimeError(
            "C2PA signer ha prodotto un file vuoto."
        )

    return upload_fixed_file(
        fixed_bytes,
        audit_id,
        file_name,
        mime_type
    )


# ============================================================
# 14. AUDIT PROCESSING
# ============================================================

def process_single_audit(
    audit: dict
):
    audit_id = audit.get(
        "id"
    )

    if not audit_id:
        return

    file_url = audit.get(
        "file_url"
    )

    if not file_url:
        update_audit(
            audit_id,
            {
                "compliance_status": "manual_review",
                "recommendation": (
                    "File URL mancante"
                )
            }
        )
        return

    try:
        update_audit(
            audit_id,
            {
                "status": "processing"
            }
        )

        file_bytes, storage_path = (
            download_file_from_storage(
                file_url
            )
        )

        file_name = os.path.basename(
            storage_path
        )

        mime_type = detect_mime_type(
            storage_path,
            file_bytes
        )

        if not is_supported_media(
            mime_type
        ):
            raise RuntimeError(
                "Tipo file non supportato: "
                f"{mime_type}"
            )

        file_hash = sha256_hex(
            file_bytes
        )

        metadata_result = analyze_metadata(
            file_bytes,
            mime_type
        )

        c2pa_result = check_c2pa_metadata(
            file_bytes,
            mime_type
        )

        ai_result = check_ai_detection(
            file_bytes,
            mime_type,
            file_name
        )

        risk_result = evaluate_risk(
            c2pa_result,
            ai_result,
            metadata_result
        )

        compliance_result = evaluate_compliance(
            c2pa_result,
            ai_result,
            risk_result
        )

        decision_basis = (
            compliance_result.get(
                "decision_basis"
            )
            or
            compliance_result.get(
                "reason"
            )
        )

        recommendation = (
            compliance_result.get(
                "reason"
            )
        )

        # ----------------------------------------------------
        # Fixer MANUALE
        # ----------------------------------------------------
        #
        # Il fixer NON viene eseguito automaticamente
        # durante l'analisi.
        #
        # Viene attivato esclusivamente tramite:
        #
        # POST /fixer/c2pa
        #
        # Questo evita di modificare il file originale
        # senza consenso esplicito dell'utente.
        # ----------------------------------------------------

        fixed_url = None
        fixer_attempted = False

        update_audit(
            audit_id,
            {
                "status": "completed",
                "compliance_status": (
                    compliance_result["status"]
                ),
                "decision": (
                    compliance_result["decision"]
                ),
                "decision_basis": decision_basis,
                "recommendation": recommendation,
                "risk_score": risk_result["score"],
                "file_hash": file_hash,
                "mime_type": mime_type,
                "file_size": len(file_bytes),
                "c2pa_detected": (
                    c2pa_result["detected"]
                ),
                "c2pa_valid": (
                    c2pa_result["valid"]
                ),
                "c2pa_trusted": (
                    c2pa_result["trusted"]
                ),
                "c2pa_status": (
                    c2pa_result["status"]
                ),
                "c2pa_validation_state": (
                    c2pa_result["validation_state"]
                ),
                "c2pa_issuer": (
                    c2pa_result["issuer"]
                ),
                "c2pa_validation_status": (
                    c2pa_result[
                        "validation_status"
                    ]
                ),
                "c2pa_validation_errors": (
                    c2pa_result[
                        "validation_errors"
                    ]
                ),
                "c2pa_signing_credential": (
                    c2pa_result[
                        "signing_credential"
                    ]
                ),

                "ai_generated": (
                    ai_result["ai_generated"]
                ),
                "ai_score": (
                    ai_result["score"]
                ),
                "ai_detector_provider": (
                    ai_result["provider"]
                ),
                "metadata_markers": (
                    metadata_result["markers"]
                ),
                "evidence": {
                    "c2pa": c2pa_result,
                    "ai_detector": ai_result,
                    "metadata": metadata_result,
                    "risk": risk_result,
                    "recommendation": recommendation,
                    "fixer_attempted": fixer_attempted,
                    "fixed_file_url": fixed_url
                }
            }
        )

        log(
            f"Audit {audit_id} completed: "
            f"{compliance_result['status']}"
        )

    except Exception as e:
        log(
            f"Audit {audit_id} error: {e}"
        )

        update_audit(
            audit_id,
            {
                "compliance_status": "manual_review",
                "recommendation": str(e)
            }
        )


# ============================================================
# 15. WORKER LOOP
# ============================================================

def audit_loop():
    log(
        "Audit worker avviato."
    )

    while True:
        try:
            audits = fetch_pending_audits()

            if not audits:
                log(
                    "Nessun audit pending."
                )

            for audit in audits:
                process_single_audit(
                    audit
                )

        except Exception as e:
            log(
                f"Errore audit loop: {e}"
            )

        time.sleep(
            WORKER_INTERVAL_SECONDS
        )


# ============================================================
# 16. RENDER SERVER
# ============================================================

def run_http_server():
    port = int(
        os.environ.get(
            "PORT",
            "10000"
        )
    )

    server = HTTPServer(
        ("0.0.0.0", port),
        SimpleHTTPRequestHandler
    )

    log(
        f"HTTP server listening on port {port}"
    )

    server.serve_forever()


# ============================================================
# 17. MAIN
# ============================================================

def main():
    log(
        "AI Act Shield Analyzer "
        f"v{ENGINE_VERSION}"
    )

    initialize_c2pa_context()

    log(
        "C2PA trust configuration ready."
    )

    # --------------------------------------------------------
    # Worker
    # --------------------------------------------------------

    threading.Thread(
        target=audit_loop,
        daemon=True
    ).start()

    # --------------------------------------------------------
    # Render HTTP server
    # --------------------------------------------------------

    run_http_server()


if __name__ == "__main__":
    main()
