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
from c2pa import Context

from ai_detector import analyze_image


# ============================================================
# AI ACT SHIELD
# ANALYZER ENGINE 3.0
#
# Pipeline:
#
# Supabase audits
#       â†“
# media-to-check
#       â†“
# Analyzer
#       â”œâ”€â”€ File engine
#       â”œâ”€â”€ SHA-256
# ANALYZER ENGINE 3.0
#       â”œâ”€â”€ Metadata engine
#       â”œâ”€â”€ Watermark engine
#       â”œâ”€â”€ AI detection engine
#       â”œâ”€â”€ Evidence engine
#       â””â”€â”€ Risk engine
#       â†“
# Supabase audits
#       â†“
# Fixer AI-act shield
#
# IMPORTANT:
# - Nessuno score AI viene inventato.
# - Nessuna firma C2PA falsa viene generata.
# - "compliant" indica conformitÃ  tecnica rispetto alle
#   regole attualmente implementate, NON certificazione
#   legale definitiva di conformitÃ  all'AI Act.
#
# C2PA v2.2:
#
# detected:
#   Manifest C2PA rilevato.
#
# valid:
#   IntegritÃ /validazione tecnica del manifest considerata
#   valida, anche se il certificato di firma non Ã¨ trusted.
#
# trusted:
#   Signing credential trusted rispetto alla trust list
#   C2PA configurata.
#
# signingCredential.untrusted:
#   NON viene trattato come una firma/hash corrotta.
#   Viene distinto da un failure reale di integritÃ .
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
#       sufficientemente validitÃ /trust.
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
# PuÃ² essere sovrascritta tramite Environment Variable.
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
# Deve contenere uno o piÃ¹ certificati PEM:
#
# -----BEGIN CERTIFICATE-----
# ...
# -----END CERTIFICATE-----
#
C2PA_TRUST_ANCHORS_PEM = os.environ.get(
    "C2PA_TRUST_ANCHORS_PEM",
    ""
)

C2PA_CONTEXT = None

C2PA_TRUST_SOURCE = None


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
            "La trust list C2PA Ã¨ vuota."
        )

    if "BEGIN CERTIFICATE" not in pem:

        raise RuntimeError(
            "La trust list C2PA scaricata non contiene "
            "certificati PEM."
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

    # --------------------------------------------------------
    # Context C2PA
    #
    # trust_anchors:
    #   usa esplicitamente la trust list configurata.
    #
    # verify_trust:
    #   abilita la verifica del signing credential.
    #
    # verify_after_reading:
    #   mantiene attiva la verifica durante la lettura.
    #
    # remote_manifest_fetch:
    #   mantiene la possibilitÃ  di recuperare manifest
    #   remoti referenziati dal contenuto.
    # --------------------------------------------------------

    config = {

        "trust": {

            "trust_anchors":
                anchors
        },

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

    log(
        "C2PA trust source: "
        f"{C2PA_TRUST_SOURCE}"
    )


# ============================================================
# 4. HTTP SERVER PER RENDER
# ============================================================

class SimpleHTTPRequestHandler(
    BaseHTTPRequestHandler
):

    def do_GET(self):

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.end_headers()

        response = {

            "service":
                WORKER_NAME,

            "engine_version":
                ENGINE_VERSION,

            "status":
                "running",

            "worker_interval_seconds":
                WORKER_INTERVAL_SECONDS,

            "media_bucket":
                MEDIA_BUCKET,

            "fixer_bucket":
                FIXER_BUCKET,

            "c2pa_trust_enabled":
                C2PA_CONTEXT is not None,

            "c2pa_trust_source":
                C2PA_TRUST_SOURCE
        }

        self.wfile.write(
            json.dumps(
                response
            ).encode("utf-8")
        )

    def do_HEAD(self):

        self.send_response(200)

        self.send_header(
            "Content-Type",
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
# 5. NORMALIZZAZIONE STORAGE PATH
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
    # Path giÃ  relativo
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
# 6. DOWNLOAD FILE
# ============================================================

def download_file_from_storage(
    file_url: str
) -> tuple[bytes, str]:

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
            f"Limite: {MAX_FILE_SIZE_MB} MB."
        )

    return (
        file_bytes,
        storage_path
    )


# ============================================================
# 7. MIME TYPE
# ============================================================

def detect_mime_type(
    file_url: str,
    file_bytes: bytes
) -> str:

    """
    Prima usa i magic bytes.
    Solo successivamente prova l'estensione.
    """

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
        file_bytes.startswith(
            b"GIF87a"
        )
        or
        file_bytes.startswith(
            b"GIF89a"
        )
    ):

        return "image/gif"

    # --------------------------------------------------------
    # WEBP
    # --------------------------------------------------------

    if (
        len(file_bytes) >= 12
        and file_bytes[:4] == b"RIFF"
        and file_bytes[8:12] == b"WEBP"
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
        file_bytes.startswith(
            b"ID3"
        )
        or
        file_bytes.startswith(
            b"\xff\xfb"
        )
    ):

        return "audio/mpeg"

    # --------------------------------------------------------
    # MP4 / ISO BMFF
    # --------------------------------------------------------

    if (
        len(file_bytes) >= 12
        and file_bytes[4:8] == b"ftyp"
    ):

        return "video/mp4"

    # --------------------------------------------------------
    # Fallback: estensione
    # --------------------------------------------------------

    mime_type, _ = mimetypes.guess_type(
        file_url
    )

    if mime_type:

        return mime_type

    return "application/octet-stream"


# ============================================================
# 8. FILE ENGINE
# ============================================================

def analyze_file(
    file_bytes: bytes,
    storage_path: str,
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

        "file_name":
            file_name,

        "mime_type":
            mime_type,

        "extension":
            extension,

        "size_bytes":
            len(file_bytes),

        "sha256":
            sha256,

        "storage_path":
            storage_path
    }


# ============================================================
# 9. C2PA VALIDATION HELPERS
# ============================================================

def _flatten_validation_status(
    validation_status
) -> list:

    """
    Normalizza i diversi formati restituiti da C2PA.

    Formato possibile:

        [
            {
                "code": "...",
                "explanation": "..."
            }
        ]

    oppure:

        {
            "success": [...],
            "informational": [...],
            "failure": [...]
        }
    """

    flattened = []

    if isinstance(
        validation_status,
        list
    ):

        for item in validation_status:

            if not isinstance(
                item,
                dict
            ):

                continue

            flattened.append(
                {
                    "code":
                        item.get(
                            "code"
                        ),

                    "explanation":
                        item.get(
                            "explanation"
                        ),

                    "success":
                        item.get(
                            "success"
                        ),

                    "category":
                        None
                }
            )

        return flattened

    if isinstance(
        validation_status,
        dict
    ):

        for category in (
            "success",
            "informational",
            "failure"
        ):

            entries = (
                validation_status.get(
                    category,
                    []
                )
            )

            if not isinstance(
                entries,
                list
            ):

                continue

            for item in entries:

                if not isinstance(
                    item,
                    dict
                ):

                    continue

                flattened.append(
                    {
                        "code":
                            item.get(
                                "code"
                            ),

                        "explanation":
                            item.get(
                                "explanation"
                            ),

                        "success":
                            item.get(
                                "success"
                            ),

                        "category":
                            category
                    }
                )

    return flattened


def _extract_validation_errors(
    validation_status
) -> list:

    """
    Restituisce esclusivamente failure REALI.

    IMPORTANTE:

    signingCredential.untrusted viene escluso
    dagli errori di integritÃ .

    Questo codice significa:

        il certificato del signer non Ã¨ trusted

    e NON significa automaticamente:

        hash/signature/manifest corrotti.
    """

    errors = []

    statuses = _flatten_validation_status(
        validation_status
    )

    for item in statuses:

        code = item.get(
            "code"
        )

        if not code:

            continue

        category = item.get(
            "category"
        )

        success = item.get(
            "success"
        )

        # ----------------------------------------------------
        # UNTRUSTED
        # ----------------------------------------------------

        if code == (
            "signingCredential.untrusted"
        ):

            continue

        # ----------------------------------------------------
        # Failure esplicito
        # ----------------------------------------------------

        if category == "failure":

            errors.append(
                {
                    "code":
                        code,

                    "explanation":
                        item.get(
                            "explanation"
                        )
                }
            )

            continue

        # ----------------------------------------------------
        # CompatibilitÃ  con formati legacy
        # ----------------------------------------------------

        if success is False:

            errors.append(
                {
                    "code":
                        code,

                    "explanation":
                        item.get(
                            "explanation"
                        )
                }
            )

    return errors


def _extract_untrusted_credentials(
    validation_status
) -> list:

    untrusted = []

    statuses = _flatten_validation_status(
        validation_status
    )

    for item in statuses:

        if item.get(
            "code"
        ) == "signingCredential.untrusted":

            untrusted.append(
                {
                    "code":
                        item.get(
                            "code"
                        ),

                    "explanation":
                        item.get(
                            "explanation"
                        )
                }
            )

    return untrusted


def _extract_success_codes(
    validation_status
) -> list:

    codes = []

    statuses = _flatten_validation_status(
        validation_status
    )

    for item in statuses:

        code = item.get(
            "code"
        )

        if not code:

            continue

        category = item.get(
            "category"
        )

        success = item.get(
            "success"
        )

        if (
            category == "success"
            or
            success is True
        ):

            codes.append(
                code
            )

    return codes


# ============================================================
# 10. C2PA ENGINE
# ============================================================

def check_c2pa_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    result = {

        # ----------------------------------------------------
        # Distinzione fondamentale
        # ----------------------------------------------------

        "detected":
            False,

        "valid":
            False,

        "trusted":
            False,

        # ----------------------------------------------------
        # Stato C2PA
        # ----------------------------------------------------

        "status":
            "not_detected",

        "validation_state":
            None,

        # ----------------------------------------------------
        # Trust
        # ----------------------------------------------------

        "trust_source":
            C2PA_TRUST_SOURCE,

        "trust_verification_enabled":
            C2PA_CONTEXT is not None,

        # ----------------------------------------------------
        # Manifest
        # ----------------------------------------------------

        "claim_generator":
            None,

        "title":
            None,

        "active_manifest":
            None,

        "manifest_count":
            0,

        "assertion_count":
            0,

        "ingredient_count":
            0,

        "manifests":
            {},

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        "validation_status":
            [],

        "validation_results":
            None,

        "validation_errors":
            [],

        "untrusted_credentials":
            [],

        "success_codes":
            [],

        # ----------------------------------------------------
        # Error
        # ----------------------------------------------------

        "error":
            None
    }

    try:

        # ----------------------------------------------------
        # Context
        # ----------------------------------------------------

        if C2PA_CONTEXT is None:

            raise RuntimeError(
                "C2PA Context non inizializzato."
            )

        # ----------------------------------------------------
        # Reader
        # ----------------------------------------------------

        stream = io.BytesIO(
            file_bytes
        )

        reader = c2pa.Reader(
            mime_type,
            stream,
            context=C2PA_CONTEXT
        )

        raw_json = reader.json()

        manifest_store = json.loads(
            raw_json
        )

        if not isinstance(
            manifest_store,
            dict
        ):

            raise RuntimeError(
                "C2PA Reader ha restituito "
                "un manifest store non valido."
            )

        # ----------------------------------------------------
        # Manifest store
        # ----------------------------------------------------

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

        result["active_manifest"] = (
            active_manifest
        )

        result["manifests"] = (
            manifests
        )

        result["manifest_count"] = (
            len(manifests)
        )

        # ----------------------------------------------------
        # DETECTED
        # ----------------------------------------------------

        result["detected"] = bool(
            manifests
            or
            active_manifest
        )

        if not result["detected"]:

            result["status"] = (
                "not_detected"
            )

            log(
                "C2PA: "
                "detected=False | "
                "valid=False | "
                "trusted=False | "
                "status=not_detected"
            )

            return result

        # ----------------------------------------------------
        # Active manifest assente
        # ----------------------------------------------------

        if not active_manifest:

            result["status"] = (
                "manifest_not_active"
            )

            log(
                "C2PA: "
                "detected=True | "
                "valid=False | "
                "trusted=False | "
                "status=manifest_not_active"
            )

            return result

        # ----------------------------------------------------
        # Manifest attivo
        # ----------------------------------------------------

        manifest = manifests.get(
            active_manifest
        )

        if not isinstance(
            manifest,
            dict
        ):

            result["status"] = (
                "active_manifest_missing"
            )

            log(
                "C2PA: "
                "detected=True | "
                "valid=False | "
                "trusted=False | "
                "status=active_manifest_missing"
            )

            return result

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
        # Assertions
        # ----------------------------------------------------

        assertions = manifest.get(
            "assertions",
            []
        )

        if isinstance(
            assertions,
            list
        ):

            result["assertion_count"] = (
                len(assertions)
            )

        # ----------------------------------------------------
        # Ingredients
        # ----------------------------------------------------

        ingredients = manifest.get(
            "ingredients",
            []
        )

        if isinstance(
            ingredients,
            list
        ):

            result["ingredient_count"] = (
                len(ingredients)
            )

        # ----------------------------------------------------
        # validation_state
        # ----------------------------------------------------

        validation_state = (
            manifest_store.get(
                "validation_state"
            )
        )

        result["validation_state"] = (
            validation_state
        )

        # ----------------------------------------------------
        # validation_status
        #
        # Legacy / aggregate C2PA output.
        # ----------------------------------------------------

        validation_status = (
            manifest_store.get(
                "validation_status",
                []
            )
        )

        result["validation_status"] = (
            validation_status
        )

        # ----------------------------------------------------
        # validation_results
        #
        # Output moderno:
        #
        # {
        #   "activeManifest": {
        #       "success": [],
        #       "informational": [],
        #       "failure": []
        #   },
        #   "ingredientDeltas": [...]
        # }
        # ----------------------------------------------------

        validation_results = (
            manifest_store.get(
                "validation_results"
            )
        )

        result["validation_results"] = (
            validation_results
        )

        # ----------------------------------------------------
        # Active manifest validation
        # ----------------------------------------------------

        active_validation = None

        if isinstance(
            validation_results,
            dict
        ):

            active_validation = (
                validation_results.get(
                    "activeManifest"
                )
            )

        if active_validation is not None:

            active_statuses = (
                active_validation
            )

        else:

            active_statuses = (
                validation_status
            )

        # ----------------------------------------------------
        # Errori reali
        # ----------------------------------------------------

        validation_errors = (
            _extract_validation_errors(
                active_statuses
            )
        )

        # ----------------------------------------------------
        # signingCredential.untrusted
        # ----------------------------------------------------

        untrusted_credentials = (
            _extract_untrusted_credentials(
                active_statuses
            )
        )

        # ----------------------------------------------------
        # Success codes
        # ----------------------------------------------------

        success_codes = (
            _extract_success_codes(
                active_statuses
            )
        )

        # ----------------------------------------------------
        # Ingredient deltas
        #
        # Un failure reale in un ingrediente viene mantenuto
        # come failure della provenance chain.
        # ----------------------------------------------------

        ingredient_delta_errors = []

        ingredient_delta_untrusted = []

        if isinstance(
            validation_results,
            dict
        ):

            ingredient_deltas = (
                validation_results.get(
                    "ingredientDeltas",
                    []
                )
            )

            if isinstance(
                ingredient_deltas,
                list
            ):

                for delta in ingredient_deltas:

                    if not isinstance(
                        delta,
                        dict
                    ):

                        continue

                    delta_status = (
                        delta.get(
                            "validationDeltas"
                        )
                    )

                    if not delta_status:

                        continue

                    ingredient_delta_errors.extend(
                        _extract_validation_errors(
                            delta_status
                        )
                    )

                    ingredient_delta_untrusted.extend(
                        _extract_untrusted_credentials(
                            delta_status
                        )
                    )

        validation_errors.extend(
            ingredient_delta_errors
        )

        untrusted_credentials.extend(
            ingredient_delta_untrusted
        )

        # ----------------------------------------------------
        # Deduplica errori
        # ----------------------------------------------------

        unique_errors = []

        seen_errors = set()

        for error in validation_errors:

            code = error.get(
                "code"
            )

            explanation = error.get(
                "explanation"
            )

            key = (
                str(code),
                str(explanation)
            )

            if key in seen_errors:

                continue

            seen_errors.add(
                key
            )

            unique_errors.append(
                error
            )

        validation_errors = (
            unique_errors
        )

        # ----------------------------------------------------
        # Deduplica untrusted
        # ----------------------------------------------------

        unique_untrusted = []

        seen_untrusted = set()

        for item in untrusted_credentials:

            code = item.get(
                "code"
            )

            explanation = item.get(
                "explanation"
            )

            key = (
                str(code),
                str(explanation)
            )

            if key in seen_untrusted:

                continue

            seen_untrusted.add(
                key
            )

            unique_untrusted.append(
                item
            )

        untrusted_credentials = (
            unique_untrusted
        )

        # ----------------------------------------------------
        # Salvataggio risultati
        # ----------------------------------------------------

        result["validation_errors"] = (
            validation_errors
        )

        result["untrusted_credentials"] = (
            untrusted_credentials
        )

        result["success_codes"] = (
            success_codes
        )

        # ----------------------------------------------------
        # TRUST
        #
        # Trusted solo se:
        #
        # 1. signingCredential.trusted presente
        #    oppure validation_state=Trusted
        #
        # 2. non ci sono failure reali.
        # ----------------------------------------------------

        trusted_from_success = (
            "signingCredential.trusted"
            in success_codes
        )

        trusted_from_state = (
            str(
                validation_state
            ).lower()
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

        # ----------------------------------------------------
        # VALID
        #
        # IMPORTANTE:
        #
        # validation_state puÃ² essere "Invalid" quando
        # l'unico failure Ã¨ signingCredential.untrusted.
        #
        # Per il nostro analyzer:
        #
        #   signingCredential.untrusted
        #
        # non viene considerato una corruzione della firma.
        #
        # valid=True significa quindi che non sono stati
        # rilevati failure REALI di integritÃ /validazione.
        # ----------------------------------------------------

        state_lower = str(
            validation_state
        ).lower()

        # ----------------------------------------------------
        # Trusted
        # ----------------------------------------------------

        if result["trusted"]:

            result["valid"] = True

        # ----------------------------------------------------
        # validation_state = Valid
        # ----------------------------------------------------

        elif (
            state_lower == "valid"
            and
            not validation_errors
        ):

            result["valid"] = True

        # ----------------------------------------------------
        # validation_state = Invalid
        #
        # Se l'unico problema Ã¨ untrusted:
        #
        #   valid=True
        #   trusted=False
        #
        # altrimenti:
        #
        #   valid=False
        # ----------------------------------------------------

        elif state_lower == "invalid":

            result["valid"] = bool(
                (
                    len(
                        validation_errors
                    ) == 0
                )
                and
                (
                    len(
                        untrusted_credentials
                    ) > 0
                )
                and
                (
                    "claimSignature.validated"
                    in success_codes
                )
            )

        # ----------------------------------------------------
        # Fallback per SDK/versioni che non espongono
        # validation_state.
        # ----------------------------------------------------

        else:

            claim_signature_validated = (
                "claimSignature.validated"
                in success_codes
            )

            result["valid"] = bool(
                claim_signature_validated
                and
                not validation_errors
            )

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        if result["trusted"]:

            result["status"] = (
                "trusted"
            )

        elif (
            result["valid"]
            and
            untrusted_credentials
        ):

            result["status"] = (
                "valid_untrusted"
            )

        elif (
            result["valid"]
        ):

            result["status"] = (
                "valid"
            )

        elif validation_errors:

            result["status"] = (
                "invalid"
            )

        else:

            result["status"] = (
                "detected_unverified"
            )

        # ----------------------------------------------------
        # LOGGING
        # ----------------------------------------------------

        log(
            "C2PA summary: "
            f"detected={result['detected']} | "
            f"valid={result['valid']} | "
            f"trusted={result['trusted']} | "
            f"status={result['status']} | "
            f"validation_state={validation_state}"
        )

        if untrusted_credentials:

            log(
                "C2PA signer: "
                "PRESENT BUT NOT TRUSTED"
            )

            log(
                "C2PA untrusted details: "
                f"{untrusted_credentials}"
            )

        if validation_errors:

            log(
                "C2PA integrity/validation: "
                "INVALID"
            )

            log(
                "C2PA real validation failures: "
                f"{validation_errors}"
            )

        if result["trusted"]:

            log(
                "C2PA signer: "
                "TRUSTED"
            )

        return result

      except Exception as e:

        error_message = str(e)

        # ----------------------------------------------------
        # Nessun manifest C2PA
        # ----------------------------------------------------
        # Alcune versioni dell'SDK C2PA sollevano
        # ManifestNotFound quando il file non contiene
        # alcun manifest.
        #
        # Questo NON è un errore del file:
        # significa semplicemente C2PA non rilevato.
        # ----------------------------------------------------

        if (
            "ManifestNotFound" in error_message
            or
            "no JUMB data found" in error_message
        ):

            result["detected"] = False
            result["valid"] = False
            result["trusted"] = False
            result["status"] = "not_detected"
            result["error"] = None

            log(
                "C2PA: nessun manifest rilevato."
            )

            return result

        # ----------------------------------------------------
        # Errore reale del motore C2PA
        # ----------------------------------------------------

        result["status"] = (
            "error"
        )

        result["error"] = (
            error_message
        )

        result["valid"] = False

        result["trusted"] = False

        log(
            "C2PA engine ERROR: "
            f"mime={mime_type} "
            f"error={error_message}"
        )

        return result


# ============================================================
# 11. JPEG METADATA ENGINE
# ============================================================

def analyze_jpeg_metadata(
    file_bytes: bytes
) -> dict:

    result = {

        "format":
            "jpeg",

        "exif_present":
            False,

        "xmp_present":
            False,

        "iptc_present":
            False,

        "software":
            None,

        "creator":
            None,

        "description":
            None,

        "raw_markers":
            []
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

        # ----------------------------------------------------
        # SOI / EOI / restart markers
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # APP1
        # ----------------------------------------------------

        if marker == 0xE1:

            if segment.startswith(
                b"Exif\x00\x00"
            ):

                result[
                    "exif_present"
                ] = True

            if (
                b"http://ns.adobe.com/xap/"
                in segment
            ):

                result[
                    "xmp_present"
                ] = True

            if b"<x:xmpmeta" in segment:

                result[
                    "xmp_present"
                ] = True

        # ----------------------------------------------------
        # APP13
        # ----------------------------------------------------

        if marker == 0xED:

            result[
                "iptc_present"
            ] = True

        result[
            "raw_markers"
        ].append(
            hex(marker)
        )

        position = segment_end

    return result


# ============================================================
# 12. PNG METADATA ENGINE
# ============================================================

def analyze_png_metadata(
    file_bytes: bytes
) -> dict:

    result = {

        "format":
            "png",

        "text_chunks":
            [],

        "xmp_present":
            False,

        "software":
            None,

        "creator":
            None,

        "description":
            None
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
                data_start
                + length
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

            # ------------------------------------------------
            # PNG textual chunks
            # ------------------------------------------------

            if chunk_type in (
                b"tEXt",
                b"zTXt",
                b"iTXt"
            ):

                text = data.decode(
                    "latin-1",
                    errors="ignore"
                )

                if text:

                    result[
                        "text_chunks"
                    ].append(
                        {
                            "chunk":
                                chunk_name,

                            "text":
                                text[:1000]
                        }
                    )

                    text_lower = (
                        text.lower()
                    )

                    # XMP
                    if (
                        "xmp" in text_lower
                        or
                        "xmpmeta"
                        in text_lower
                    ):

                        result[
                            "xmp_present"
                        ] = True

                    # Software
                    if (
                        "software"
                        in text_lower
                    ):

                        if not result[
                            "software"
                        ]:

                            result[
                                "software"
                            ] = text[:500]

                    # Creator
                    if (
                        "creator"
                        in text_lower
                    ):

                        if not result[
                            "creator"
                        ]:

                            result[
                                "creator"
                            ] = text[:500]

                    # Description
                    if (
                        "description"
                        in text_lower
                    ):

                        if not result[
                            "description"
                        ]:

                            result[
                                "description"
                            ] = text[:500]

            position = (
                data_end + 4
            )

            if chunk_type == b"IEND":

                break

        except Exception as e:

            log(
                f"PNG metadata parser error: {e}"
            )

            break

    return result


# ============================================================
# 13. GENERIC METADATA ENGINE
# ============================================================

def analyze_metadata(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    result = {

        "available":
            True,

        "format":
            mime_type,

        "exif_present":
            False,

        "xmp_present":
            False,

        "iptc_present":
            False,

        "software":
            None,

        "creator":
            None,

        "description":
            None,

        "signals":
            []
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
    # Signals
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

    if result.get(
        "software"
    ):

        result[
            "signals"
        ].append(
            "software_metadata_present"
        )

    if result.get(
        "creator"
    ):

        result[
            "signals"
        ].append(
            "creator_metadata_present"
        )

    return result


# ============================================================
# 14. WATERMARK ENGINE
# ============================================================

def check_watermark(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    """
    Il detector visuale non Ã¨ ancora collegato.

    NON dichiariamo detected=False soltanto perchÃ©
    non troviamo una stringa nei metadata.
    """

    result = {

        "available":
            False,

        "detected":
            None,

        "status":
            "not_implemented",

        "method":
            None,

        "signals":
            [],

        "detail":
            (
                "Watermark detection visuale "
                "non ancora collegato."
            )
    }

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
# 15. AI DETECTION ENGINE
# ============================================================

def run_ai_detection(
    file_bytes: bytes,
    mime_type: str
) -> dict:

    """
    AI detection tramite Sightengine.

    Nessuno score viene inventato.

    Se Sightengine non produce uno score numerico
    valido, score rimane None.
    """

    result = {

        "available":
            False,

        "provider":
            "sightengine",

        "score":
            None,

        "confidence":
            None,

        "status":
            "not_available",

        "model":
            "genai",

        "model_version":
            None,

        "signals":
            [],

        "detail":
            None
    }

    supported_mimes = (
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif"
    )

    if mime_type not in supported_mimes:

        result["status"] = (
            "unsupported_mime"
        )

        result["detail"] = (
            "AI detection non eseguito "
            f"per mime type {mime_type}."
        )

        log(
            "AI detector skipped: "
            f"unsupported MIME {mime_type}"
        )

        return result

    temp_path = None

    try:

        # ----------------------------------------------------
        # Temporary file
        # ----------------------------------------------------

        suffix_map = {

            "image/jpeg":
                ".jpg",

            "image/png":
                ".png",

            "image/webp":
                ".webp",

            "image/gif":
                ".gif"
        }

        suffix = suffix_map.get(
            mime_type,
            ".bin"
        )

        with tempfile.NamedTemporaryFile(
            suffix=suffix,
            delete=False
        ) as temp_file:

            temp_file.write(
                file_bytes
            )

            temp_path = (
                temp_file.name
            )

        log(
            "AI detector: temporary "
            "file created"
        )

        # ----------------------------------------------------
        # Sightengine
        # ----------------------------------------------------

        sightengine_result = analyze_image(
            temp_path
        )

        if not isinstance(
            sightengine_result,
            dict
        ):

            result["status"] = (
                "invalid_result"
            )

            result["detail"] = (
                "AI detector ha restituito "
                "un risultato non valido."
            )

            return result

        available = bool(
            sightengine_result.get(
                "available"
            )
        )

        ai_score = (
            sightengine_result.get(
                "ai_score"
            )
        )

        if not available:

            result["status"] = (
                "unavailable"
            )

            result["detail"] = (
                "Sightengine non ha restituito "
                "uno score AI valido."
            )

            return result

        # ----------------------------------------------------
        # Validazione score
        # ----------------------------------------------------

        if not isinstance(
            ai_score,
            (int, float)
        ):

            result["status"] = (
                "invalid_score"
            )

            result["detail"] = (
                "Sightengine ha restituito "
                "uno score non numerico."
            )

            return result

        ai_score = float(
            ai_score
        )

        if not 0.0 <= ai_score <= 1.0:

            result["status"] = (
                "invalid_score"
            )

            result["detail"] = (
                "Score AI fuori dal range 0-1."
            )

            return result

        # ----------------------------------------------------
        # Risultato valido
        # ----------------------------------------------------

        result["available"] = True

        result["score"] = (
            ai_score
        )

        result["status"] = (
            "success"
        )

        result["detail"] = (
            "AI-generated detection "
            "eseguito tramite Sightengine."
        )

        result["signals"].append(
            "sightengine_genai"
        )

        log(
            f"AI detector: "
            f"Sightengine score={ai_score}"
        )

        return result

    except Exception as e:

        log(
            f"AI detector error: {e}"
        )

        result["status"] = (
            "error"
        )

        result["detail"] = (
            str(e)
        )

        return result

    finally:

        if temp_path:

            try:

                os.remove(
                    temp_path
                )

            except OSError:

                pass


# ============================================================
# 16. EVIDENCE ENGINE
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
                "type":
                    "c2pa",

                "result":
                    "present",

                "status":
                    c2pa_result.get(
                        "status"
                    ),

                "valid":
                    c2pa_result.get(
                        "valid"
                    ),

                "trusted":
                    c2pa_result.get(
                        "trusted"
                    ),

                "validation_state":
                    c2pa_result.get(
                        "validation_state"
                    ),

                "untrusted_credentials":
                    c2pa_result.get(
                        "untrusted_credentials",
                        []
                    ),

                "validation_errors":
                    c2pa_result.get(
                        "validation_errors",
                        []
                    ),

                "confidence":
                    1.0
            }
        )

    else:

        signals.append(
            {
                "type":
                    "c2pa",

                "result":
                    "not_detected",

                "status":
                    c2pa_result.get(
                        "status"
                    ),

                "valid":
                    False,

                "trusted":
                    False,

                "confidence":
                    None
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
                "type":
                    "metadata",

                "result":
                    signal,

                "confidence":
                    None
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
                "type":
                    "ai_detection",

                "result":
                    "available",

                "score":
                    ai_result.get(
                        "score"
                    ),

                "confidence":
                    ai_result.get(
                        "confidence"
                    ),

                "provider":
                    ai_result.get(
                        "provider"
                    ),

                "status":
                    ai_result.get(
                        "status"
                    )
            }
        )

    else:

        signals.append(
            {
                "type":
                    "ai_detection",

                "result":
                    "unavailable",

                "status":
                    ai_result.get(
                        "status"
                    ),

                "confidence":
                    None
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
                "type":
                    "watermark",

                "result":
                    watermark_result.get(
                        "status"
                    ),

                "detected":
                    watermark_result.get(
                        "detected"
                    )
            }
        )

    else:

        signals.append(
            {
                "type":
                    "watermark",

                "result":
                    "unavailable",

                "status":
                    watermark_result.get(
                        "status"
                    )
            }
        )

    # --------------------------------------------------------
    # File integrity
    # --------------------------------------------------------

    signals.append(
        {
            "type":
                "file_integrity",

            "result":
                "sha256_calculated",

            "sha256":
                file_analysis.get(
                    "sha256"
                )
        }
    )

    return {

        "signal_count":
            len(signals),

        "signals":
            signals
    }


# ============================================================
# 17. RISK ENGINE
# ============================================================

def calculate_risk(
    c2pa_result: dict,
    metadata_result: dict,
    watermark_result: dict,
    ai_result: dict
) -> dict:

    """
    Risk engine trasparente.

    Non usa ML.

    Non inventa probabilitÃ .

    Punteggio:
        C2PA assente       +40
        AI >= 0.80         +40
        AI >= 0.50         +20
        AI metadata        +20

    Massimo: 100
    """

    risk_points = 0

    reasons = []

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    if c2pa_result.get(
        "detected"
    ):

        # ----------------------------------------------------
        # Manifest presente.
        #
        # Non aggiungiamo automaticamente rischio.
        # Lo status valid/trusted viene conservato nei
        # dettagli e nella compliance.
        # ----------------------------------------------------

        pass

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
                    "alta probabilitÃ  di "
                    "contenuto AI."
                )

            elif score >= 0.50:

                risk_points += 20

                reasons.append(
                    "AI detector indica "
                    "segnali intermedi di "
                    "contenuto AI."
                )

    else:

        reasons.append(
            "AI detector non disponibile."
        )

    # --------------------------------------------------------
    # Metadata software
    # --------------------------------------------------------

    software = (
        metadata_result.get(
            "software"
        )
    )

    if software:

        software_lower = (
            str(
                software
            ).lower()
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
                    "un indicatore compatibile "
                    f"con generative AI: {term}."
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

    # --------------------------------------------------------
    # Level
    # --------------------------------------------------------

    if risk_points >= 70:

        risk_level = "high"

    elif risk_points >= 40:

        risk_level = "medium"

    else:

        risk_level = "low"

    return {

        "score":
            risk_points,

        "level":
            risk_level,

        "reasons":
            reasons
    }


# ============================================================
# 18. COMPLIANCE ENGINE â€” ANALYZER 3.0
# ============================================================
def evaluate_compliance(
    c2pa_result: dict,
    ai_result: dict,
    risk_result: dict
) -> dict:
    """
    AI ACT SHIELD - ANALYZER 3.0

    ATTENZIONE:
    Questo non Ã¨ un parere legale.

    Il sistema valuta esclusivamente evidenze tecniche
    secondo le regole implementate nel motore.

    PRIORITÃ€ DELLE EVIDENZE:

    1. C2PA trusted
       -> COMPLIANT

    2. C2PA valido ma non trusted
       -> MANUAL_REVIEW

    3. C2PA assente/non valido + AI score molto alto
       -> NON_COMPLIANT

    4. C2PA assente/non valido + AI score intermedio
       -> MANUAL_REVIEW

    5. C2PA assente/non valido + AI score basso
       -> NON_COMPLIANT

    IMPORTANTE:
    Un AI score Ã¨ un'indicazione probabilistica e non viene
    trattato come prova definitiva.

    Un manifest C2PA viene considerato automaticamente
    sufficiente solo quando risulta trusted.
    """

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    c2pa_detected = bool(
        c2pa_result.get("detected")
    )

    c2pa_valid = bool(
        c2pa_result.get("valid")
    )

    c2pa_trusted = bool(
        c2pa_result.get("trusted")
    )

    c2pa_status = (
        c2pa_result.get("status")
    )

    # --------------------------------------------------------
    # AI DETECTOR
    # --------------------------------------------------------

    ai_available = bool(
        ai_result.get("available")
    )

    ai_score = ai_result.get(
        "score"
    )

    if (
        ai_score is not None
        and isinstance(
            ai_score,
            (int, float)
        )
    ):
        ai_score = float(ai_score)

    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    risk_level = (
        risk_result.get("level")
        if isinstance(risk_result, dict)
        else None
    )

    risk_score = (
        risk_result.get("score")
        if isinstance(risk_result, dict)
        else None
    )

    # ========================================================
    # 1. C2PA TRUSTED
    # ========================================================
    #
    # Questa Ã¨ la prioritÃ  massima.
    #
    # Se il manifest Ã¨ realmente trusted, un AI score elevato
    # NON deve sovrascrivere la provenance verificata.
    #

    if (
        c2pa_detected
        and c2pa_valid
        and c2pa_trusted
    ):
        return {
            "status": "compliant",
            "decision": "c2pa_trusted",
            "reason": (
                "Manifest C2PA rilevato, "
                "tecnicamente valido e trusted. "
                "La provenance verificata ha "
                "prioritÃ  rispetto al punteggio "
                "probabilistico del detector AI."
            ),
            "c2pa": {
                "detected": True,
                "valid": True,
                "trusted": True,
                "status": c2pa_status
            },
            "ai": {
                "available": ai_available,
                "score": ai_score
            },
            "risk": {
                "level": risk_level,
                "score": risk_score
            }
        }

    # ========================================================
    # 2. C2PA PRESENTE MA NON TRUSTED
    # ========================================================
    #
    # Non dichiariamo automaticamente compliant.
    #
    # Esiste una provenance tecnica, ma la catena di trust
    # non Ã¨ stata verificata.
    #
    # Questo Ã¨ un caso da revisione manuale.
    #

    if (
        c2pa_detected
        and c2pa_valid
        and not c2pa_trusted
    ):
        return {
            "status": "manual_review",
            "decision": "c2pa_valid_untrusted",
            "reason": (
                "Manifest C2PA rilevato e tecnicamente "
                "valido, ma la catena di trust non "
                "risulta verificata. Ãˆ richiesta "
                "una revisione manuale."
            ),
            "c2pa": {
                "detected": True,
                "valid": True,
                "trusted": False,
                "status": c2pa_status
            },
            "ai": {
                "available": ai_available,
                "score": ai_score
            },
            "risk": {
                "level": risk_level,
                "score": risk_score
            }
        }

    # ========================================================
    # 3. C2PA PRESENTE MA INVALIDO
    # ========================================================
    #
    # Un manifest rilevato ma non valido non viene considerato
    # una prova affidabile.
    #

    if (
        c2pa_detected
        and not c2pa_valid
    ):
        if (
            ai_available
            and isinstance(
                ai_score,
                (int, float)
            )
            and ai_score >= 0.80
        ):
            return {
                "status": "non_compliant",
                "decision": "invalid_c2pa_high_ai",
                "reason": (
                    "Manifest C2PA rilevato ma non valido "
                    "e il detector AI indica un'elevata "
                    "probabilitÃ  di contenuto AI."
                ),
                "c2pa": {
                    "detected": True,
                    "valid": False,
                    "trusted": False,
                    "status": c2pa_status
                },
                "ai": {
                    "available": True,
                    "score": ai_score
                },
                "risk": {
                    "level": risk_level,
                    "score": risk_score
                }
            }

        return {
            "status": "manual_review",
            "decision": "invalid_c2pa",
            "reason": (
                "Manifest C2PA rilevato ma non valido. "
                "La provenance non puÃ² essere considerata "
                "affidabile senza una revisione manuale."
            ),
            "c2pa": {
                "detected": True,
                "valid": False,
                "trusted": False,
                "status": c2pa_status
            },
            "ai": {
                "available": ai_available,
                "score": ai_score
            },
            "risk": {
                "level": risk_level,
                "score": risk_score
            }
        }

    # ========================================================
    # 4. NESSUN C2PA + AI SCORE MOLTO ALTO
    # ========================================================

    if (
        ai_available
        and isinstance(
            ai_score,
            (int, float)
        )
        and ai_score >= 0.80
    ):
        return {
            "status": "non_compliant",
            "decision": "no_c2pa_high_ai",
            "reason": (
                "Nessun manifest C2PA verificabile "
                "e il detector AI indica un'elevata "
                "probabilitÃ  di contenuto AI."
            ),
            "c2pa": {
                "detected": False,
                "valid": False,
                "trusted": False,
                "status": c2pa_status
            },
            "ai": {
                "available": True,
                "score": ai_score
            },
            "risk": {
                "level": risk_level,
                "score": risk_score
            }
        }

    # ========================================================
    # 5. NESSUN C2PA + AI SCORE INTERMEDIO
    # ========================================================

    if (
        ai_available
        and isinstance(
            ai_score,
            (int, float)
        )
        and 0.50 <= ai_score < 0.80
    ):
        return {
            "status": "manual_review",
            "decision": "no_c2pa_medium_ai",
            "reason": (
                "Nessun manifest C2PA verificabile "
                "e il detector AI ha rilevato segnali "
                "intermedi. Il risultato non Ã¨ "
                "sufficientemente determinante per "
                "una decisione automatica."
            ),
            "c2pa": {
                "detected": False,
                "valid": False,
                "trusted": False,
                "status": c2pa_status
            },
            "ai": {
                "available": True,
                "score": ai_score
            },
            "risk": {
                "level": risk_level,
                "score": risk_score
            }
        }

    # ========================================================
    # 6. NESSUN C2PA + AI SCORE BASSO / NON DISPONIBILE
    # ========================================================

    if ai_available:
        reason = (
            "Nessun manifest C2PA verificabile "
            "e il detector AI non ha rilevato "
            "un'elevata probabilitÃ  di contenuto AI."
        )
    else:
        reason = (
            "Nessun manifest C2PA verificabile. "
            "Il detector AI non Ã¨ disponibile."
        )

    return {
        "status": "non_compliant",
        "decision": "no_c2pa",
        "reason": reason,
        "c2pa": {
            "detected": False,
            "valid": False,
            "trusted": False,
            "status": c2pa_status
        },
        "ai": {
            "available": ai_available,
            "score": ai_score
        },
        "risk": {
            "level": risk_level,
            "score": risk_score
        }
    }

# ============================================================
# 19. FIXER ENGINE
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

    Quando il signer sarÃ  disponibile, questa funzione
    produrrÃ  il file remediato e lo caricherÃ  nel bucket:

        Fixer AI-act shield
    """

    log(
        f"Fixer richiesto per audit {audit_id}"
    )

    log(
        "Fixer C2PA non ancora attivo: "
        "nessuna firma falsa verrÃ  applicata."
    )

    return None


# ============================================================
# 20. UPLOAD FIXER
# ============================================================

def upload_fixed_file(
    file_bytes: bytes,
    audit_id: str,
    file_name: str,
    mime_type: str
) -> str | None:

    safe_name = (
        file_name
        .replace(
            "/",
            "_"
        )
        .replace(
            "\\",
            "_"
        )
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
                    "content-type":
                        mime_type,

                    "upsert":
                        "true"
                }
            )
        )

        log(
            f"File fixer caricato: "
            f"{FIXER_BUCKET}/{storage_path}"
        )

        return storage_path

    except Exception as e:

        log(
            f"Errore upload fixer: {e}"
        )

        return None


# ============================================================
# 21. DATABASE UPDATE
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
# 22. AUDIT ERROR
# ============================================================

def mark_audit_error(
    audit_id: str,
    error_message: str,
    extra_details: dict | None = None
):

    details = {

        "worker":
            WORKER_NAME,

        "engine_version":
            ENGINE_VERSION,

        "status":
            "error",

        "error":
            error_message
    }

    if extra_details:

        details.update(
            extra_details
        )

    update_audit(
        audit_id,
        {
            "compliance_status":
                "non_compliant",

            "details":
                details
        }
    )


# ============================================================
# 23. SINGOLO AUDIT
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

        file_bytes, storage_path = (
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
            (
                "Impossibile scaricare "
                "il file da Supabase Storage"
            ),
            {
                "reason":
                    str(e),

                "file_url":
                    file_url,

                "bucket":
                    MEDIA_BUCKET
            }
        )

        return

    # --------------------------------------------------------
    # MIME
    # --------------------------------------------------------

    mime_type = detect_mime_type(
        storage_path,
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
        storage_path,
        file_name,
        mime_type
    )

    log(
        "File size: "
        f"{file_analysis['size_bytes']} bytes"
    )

    log(
        "SHA-256: "
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
        "C2PA summary: "
        f"detected={c2pa_result.get('detected')} | "
        f"valid={c2pa_result.get('valid')} | "
        f"trusted={c2pa_result.get('trusted')} | "
        f"status={c2pa_result.get('status')} | "
        f"validation_state="
        f"{c2pa_result.get('validation_state')}"
    )

    if c2pa_result.get(
        "untrusted_credentials"
    ):

        log(
            "C2PA signer status: "
            "PRESENT BUT NOT TRUSTED"
        )

    if c2pa_result.get(
        "validation_errors"
    ):

        log(
            "C2PA integrity status: "
            "INVALID"
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

    ai_score = (
        ai_result.get(
            "score"
        )
    )

    log(
        f"AI score: {ai_score}"
    )

    log(
        f"AI detector status: "
        f"{ai_result.get('status')}"
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
        "Risk: "
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

    decision = (
        compliance_result.get(
            "decision"
        )
    )

    decision_basis = (
        compliance_result.get(
            "decision_basis"
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
    log(
        f"Decision: "
        f"{decision}"
    )

    log(
        f"Decision basis: "
        f"{decision_basis}"
    )
    log(
        f"Compliance reason: "
        f"{recommendation}"
    )

    # ---------------------------------------------------------
    # FIXER
    # ---------------------------------------------------------

    fixed_url = None

    fixer_attempted = (
        compliance_status
        == "non_compliant"
    )

    if fixer_attempted:
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

        "worker":
            WORKER_NAME,

        "engine_version":
            "3.0",

        "file":
            file_analysis,

        "storage": {

            "input_bucket":
                MEDIA_BUCKET,

            "input_path":
                storage_path,

            "fixer_bucket":
                FIXER_BUCKET
        },

        "c2pa":
            c2pa_result,

        "metadata":
            metadata_result,

        "watermark":
            watermark_result,

        "ai_detection":
            ai_result,

        "evidence":
            evidence_result,

        "risk":
            risk_result,

        "compliance":
            compliance_result,

        "decision":
            decision,

        "decision_basis":
            decision_basis,

        "recommendation":
            recommendation,
        "fixer": {

            "attempted":
                fixer_attempted,

            "fixed_file":
                fixed_url is not None
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
        "C2PA: "
        f"detected={c2pa_result.get('detected')} | "
        f"valid={c2pa_result.get('valid')} | "
        f"trusted={c2pa_result.get('trusted')} | "
        f"status={c2pa_result.get('status')}"
    )

    log(
        f"AI score: {ai_score}"
    )

    log(
        f"Watermark: {watermark_detected}"
    )

    log(
        "Risk: "
        f"{risk_result.get('level')} "
        f"({risk_result.get('score')}/100)"
    )

    log(
        "============================================================"
    )


# ============================================================
# 24. PENDING AUDITS
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
                        (
                            "Errore interno "
                            "durante l'elaborazione"
                        ),
                        {
                            "reason":
                                str(e)
                        }
                    )

    except Exception as e:

        log(
            "ERRORE ELABORAZIONE AUDIT: "
            f"{e}"
        )


# ============================================================
# 25. WORKER LOOP
# ============================================================

def audit_loop():

    log(
        "WORKER LOOP ATTIVO"
    )

    log(
        f"Engine version: "
        f"{ENGINE_VERSION}"
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

    log(
        "C2PA trust verification: "
        f"{C2PA_CONTEXT is not None}"
    )

    log(
        "C2PA trust source: "
        f"{C2PA_TRUST_SOURCE}"
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
# 26. STARTUP
# ============================================================

if __name__ == "__main__":

    log(
        "============================================================"
    )

    log(
        "AI ACT SHIELD ANALYZER STARTING"
    )

    log(
        f"Engine version: "
        f"{ENGINE_VERSION}"
    )

    log(
        f"Supabase: "
        f"{SUPABASE_URL}"
    )

    log(
        f"Media bucket: "
        f"{MEDIA_BUCKET}"
    )

    log(
        f"Fixer bucket: "
        f"{FIXER_BUCKET}"
    )

    log(
        f"Worker interval: "
        f"{WORKER_INTERVAL_SECONDS}s"
    )

    log(
        "============================================================"
    )

    # --------------------------------------------------------
    # C2PA
    # --------------------------------------------------------

    log(
        "Initializing C2PA trust configuration..."
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
