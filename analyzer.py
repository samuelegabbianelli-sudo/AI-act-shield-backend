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
            "La trust list C2PA Ã¨ vuota."
        )

    if "BEGIN CERTIFICATE" not in pem:

        raise RuntimeError(
            "La trust list C2PA scaricata "
            "non contiene certificati PEM validi."
        )

    return (
        pem,
        "official"
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
    #   mantiene la possibilitÃ  di recuperare manifest
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
