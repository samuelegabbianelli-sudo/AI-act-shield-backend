from pathlib import Path

path = Path("analyzer.py")
text = path.read_text(encoding="utf-8")

# 1. Add the separate internal-policy context.
old_globals = """C2PA_CONTEXT = None

C2PA_TRUST_SOURCE = None"""
new_globals = """C2PA_CONTEXT = None

# Separate context used only for the AI Act Shield internal policy.
# The primary C2PA context remains official-trust-only.
C2PA_POLICY_CONTEXT = None

C2PA_TRUST_SOURCE = None"""

if "C2PA_POLICY_CONTEXT = None" not in text:
    if old_globals not in text:
        raise SystemExit("Expected C2PA globals block not found.")
    text = text.replace(old_globals, new_globals, 1)

# 2. Replace the C2PA initialization with two explicit contexts.
start = text.index("def initialize_c2pa_context():")
end = text.index("\n\n# ============================================================\n# AUTHENTICATION", start)

new_initialize = '''def initialize_c2pa_context():

    global C2PA_CONTEXT
    global C2PA_POLICY_CONTEXT
    global C2PA_TRUST_SOURCE

    anchors, source = load_c2pa_trust_anchors()

    user_anchors = C2PA_USER_ANCHORS_PEM.strip()
    signer_cert = C2PA_SIGNING_CERT_PEM.strip()

    if user_anchors and "BEGIN CERTIFICATE" not in user_anchors:
        raise RuntimeError(
            "C2PA_USER_ANCHORS_PEM configurata ma non contiene "
            "certificati PEM validi."
        )

    if signer_cert and "BEGIN CERTIFICATE" not in signer_cert:
        raise RuntimeError(
            "C2PA_SIGNING_CERT_PEM configurato ma non contiene "
            "un certificato PEM valido."
        )

    verify_config = {
        "verify_after_reading": True,
        "verify_trust": True,
        "verify_timestamp_trust": True,
        "ocsp_fetch": False,
        "remote_manifest_fetch": True,
    }

    # Official C2PA trust context: internal policy anchors are excluded.
    try:
        C2PA_CONTEXT = Context.from_dict({
            "trust": {"trust_anchors": anchors},
            "verify": verify_config,
        })
    except Exception as e:
        raise RuntimeError(
            "Impossibile inizializzare il Context C2PA ufficiale: "
            f"{e}"
        ) from e

    # AI Act Shield Policy context: explicit internal trust only.
    policy_trust = {}
    if user_anchors:
        policy_trust["user_anchors"] = user_anchors
    if signer_cert:
        policy_trust["allowed_list"] = signer_cert

    if policy_trust:
        try:
            C2PA_POLICY_CONTEXT = Context.from_dict({
                "trust": policy_trust,
                "verify": verify_config,
            })
        except Exception as e:
            raise RuntimeError(
                "Impossibile inizializzare il Context AI Act Shield Policy: "
                f"{e}"
            ) from e
    else:
        C2PA_POLICY_CONTEXT = None

    C2PA_TRUST_SOURCE = source

    log("C2PA context ufficiale inizializzato.")
    log("C2PA trust verification: ENABLED")
    log(
        "AI Act Shield Policy trust context: "
        + ("ENABLED" if C2PA_POLICY_CONTEXT is not None else "DISABLED")
    )
    log(f"C2PA trust source: {C2PA_TRUST_SOURCE}")'''

text = text[:start] + new_initialize + text[end:]

# 3. Replace the old internal-trust branch with a separate policy re-check.
old_status_block = '''    if result["trusted"]:
        if C2PA_USER_ANCHORS_PEM.strip():
            result["trust_source"] = "ai_act_shield_policy"
            result["status"] = "trusted_internal"
        else:
            result["trust_source"] = "c2pa_official"
            result["status"] = "trusted"
'''

new_status_block = '''    # Re-check technically valid, officially-untrusted manifests
    # against the separate AI Act Shield internal policy context.
    if not result["trusted"] and C2PA_POLICY_CONTEXT is not None:
        try:
            policy_reader = c2pa.Reader(
                mime_type,
                io.BytesIO(file_bytes),
                context=C2PA_POLICY_CONTEXT,
            )

            policy_raw_json = policy_reader.json()
            policy_data = (
                json.loads(policy_raw_json)
                if isinstance(policy_raw_json, str)
                else policy_raw_json
            )

            # Safe diagnostics: log only validation state/codes/trust booleans.
            # Never log certificates, private keys, or raw manifest contents.
            policy_codes = []
            policy_trusted_values = []

            def collect_policy_diagnostics(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        key_text = str(key).lower()
                        if key_text == "code" and isinstance(item, str):
                            policy_codes.append(item)
                        if key_text in {
                            "trusted",
                            "signingcredential.trusted",
                            "signing_credential.trusted",
                        } and isinstance(item, bool):
                            policy_trusted_values.append(item)
                        collect_policy_diagnostics(item)
                elif isinstance(value, list):
                    for item in value:
                        collect_policy_diagnostics(item)

            collect_policy_diagnostics(policy_data)

            policy_state_for_log = ""
            if isinstance(policy_data, dict):
                policy_state_for_log = str(
                    policy_data.get("validation_state")
                    or policy_data.get("validationState")
                    or ""
                )

            log(
                "AI Act Shield Policy diagnostic: "
                f"validation_state={policy_state_for_log!r}; "
                f"trusted_values={policy_trusted_values!r}; "
                f"codes={policy_codes!r}"
            )

            def contains_trusted(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        key_text = str(key).lower()
                        if key_text in {
                            "signingcredential.trusted",
                            "signing_credential.trusted",
                        } and item is True:
                            return True
                        if contains_trusted(item):
                            return True
                elif isinstance(value, list):
                    return any(contains_trusted(item) for item in value)
                return False

            policy_state = ""
            if isinstance(policy_data, dict):
                policy_state = str(
                    policy_data.get("validation_state")
                    or policy_data.get("validationState")
                    or ""
                ).lower()

            if contains_trusted(policy_data) or policy_state == "trusted":
                result["trusted"] = True
                result["trust_source"] = "ai_act_shield_policy"
                result["status"] = "trusted_internal"
                return result

        except Exception as policy_error:
            log(
                "AI Act Shield Policy verification skipped: "
                f"{policy_error}"
            )

    if result["trusted"]:
        result["trust_source"] = "c2pa_official"
        result["status"] = "trusted"
'''

if old_status_block in text:
    text = text.replace(old_status_block, new_status_block, 1)
elif 'result["status"] = "trusted_internal"' not in text:
    raise SystemExit("Expected C2PA trusted status block not found.")

# 4. Add the policy diagnostic block to already-patched analyzer.py if it is not present.
diagnostic_marker = '"AI Act Shield Policy diagnostic: "'
if diagnostic_marker not in text:
    anchor = '''            policy_data = (
                json.loads(policy_raw_json)
                if isinstance(policy_raw_json, str)
                else policy_raw_json
            )
'''
    diagnostic = '''            policy_data = (
                json.loads(policy_raw_json)
                if isinstance(policy_raw_json, str)
                else policy_raw_json
            )

            # Safe diagnostics: log only validation state/codes/trust booleans.
            # Never log certificates, private keys, or raw manifest contents.
            policy_codes = []
            policy_trusted_values = []

            def collect_policy_diagnostics(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        key_text = str(key).lower()
                        if key_text == "code" and isinstance(item, str):
                            policy_codes.append(item)
                        if key_text in {
                            "trusted",
                            "signingcredential.trusted",
                            "signing_credential.trusted",
                        } and isinstance(item, bool):
                            policy_trusted_values.append(item)
                        collect_policy_diagnostics(item)
                elif isinstance(value, list):
                    for item in value:
                        collect_policy_diagnostics(item)

            collect_policy_diagnostics(policy_data)

            policy_state_for_log = ""
            if isinstance(policy_data, dict):
                policy_state_for_log = str(
                    policy_data.get("validation_state")
                    or policy_data.get("validationState")
                    or ""
                )

            log(
                "AI Act Shield Policy diagnostic: "
                f"validation_state={policy_state_for_log!r}; "
                f"trusted_values={policy_trusted_values!r}; "
                f"codes={policy_codes!r}"
            )
'''
    if anchor not in text:
        raise SystemExit("Policy data anchor not found for diagnostics.")
    text = text.replace(anchor, diagnostic, 1)

# 5. Add an EARLY C2PA diagnostic before the trust/validity gates.
# This tells us why the internal-policy branch may be skipped.
early_marker = '"AI Act Shield C2PA pre-policy diagnostic: "'
if early_marker not in text:
    anchor = '''    # --------------------------------------------------------
    # IMPORTANT C2PA TRUST LOGIC
    # --------------------------------------------------------
'''
    early_diagnostic = '''    # Safe diagnostic before any early return caused by validation errors.
    # Never log certificates, private keys, or raw manifest contents.
    pre_policy_codes = list(all_codes)
    pre_policy_error_codes = [
        item.get("code")
        for item in validation_errors
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    ]
    pre_policy_state = str(validation_state or "")

    log(
        "AI Act Shield C2PA pre-policy diagnostic: "
        f"validation_state={pre_policy_state!r}; "
        f"codes={pre_policy_codes!r}; "
        f"error_codes={pre_policy_error_codes!r}; "
        f"policy_context_enabled={C2PA_POLICY_CONTEXT is not None}"
    )

    # --------------------------------------------------------
    # IMPORTANT C2PA TRUST LOGIC
    # --------------------------------------------------------
'''
    if anchor not in text:
        raise SystemExit("C2PA trust logic anchor not found for early diagnostic.")
    text = text.replace(anchor, early_diagnostic, 1)

compile(text, "analyzer.py", "exec")
path.write_text(text, encoding="utf-8")
print("Internal policy recognition patch/diagnostics applied.")
print("analyzer.py syntax check: PASSED")
