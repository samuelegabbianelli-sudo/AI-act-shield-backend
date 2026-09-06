from pathlib import Path

p = Path("analyzer.py")
s = p.read_text(encoding="utf-8")

old1 = '''    result["trusted"] = bool(
        (
            trusted_from_success
            or
            trusted_from_state
        )
        and
        not validation_errors
    )

    if result["trusted"]:
        if C2PA_USER_ANCHORS_PEM.strip():
            result["trust_source"] = "ai_act_shield_policy"
            result["status"] = "trusted_internal"
        else:
            result["trust_source"] = "c2pa_official"
'''
new1 = '''    result["trusted"] = bool(
        (
            trusted_from_success
            or
            trusted_from_state
        )
        and
        not validation_errors
    )
'''

old2 = '''    if result["trusted"]:
        result["status"] = "trusted"

    elif (
        "signingCredential.untrusted"
        in all_codes
    ):
'''
new2 = '''    if result["trusted"]:
        if C2PA_USER_ANCHORS_PEM.strip():
            result["trust_source"] = "ai_act_shield_policy"
            result["status"] = "trusted_internal"
        else:
            result["trust_source"] = "c2pa_official"
            result["status"] = "trusted"

    elif (
        "signingCredential.untrusted"
        in all_codes
    ):
'''

old3 = '''    if c2pa_status == "trusted_internal":
        return {
            "status": "compliant",
            "decision": "c2pa_internal_policy",
            "reason": (
                "Manifest C2PA valido e signing credential verificato "
                "secondo la policy interna di AI Act Shield. "
                "Questa verifica non equivale a trusted ufficiale C2PA."
            ),
            "decision_basis": (
                "C2PA trusted via AI Act Shield Policy"
            ),
            "trust_source": "ai_act_shield_policy"
        }

    if c2pa_status == "trusted":
'''
new3 = '''    if c2pa_status == "trusted_internal":
        return {
            "status": "compliant",
            "decision": "c2pa_internal_policy",
            "reason": (
                "Manifest C2PA valido e signing credential verificato "
                "secondo la policy interna di AI Act Shield. "
                "Questa verifica non equivale a trusted ufficiale C2PA."
            ),
            "decision_basis": (
                "C2PA trusted via AI Act Shield Policy"
            ),
            "trust_source": "ai_act_shield_policy"
        }

    if c2pa_status == "trusted":
'''

if s.count(old1) != 1:
    raise SystemExit(f"Expected one trust block, found {s.count(old1)}")
if s.count(old2) != 1:
    raise SystemExit(f"Expected one valid-status block, found {s.count(old2)}")
if s.count(old3) != 1:
    raise SystemExit(f"Expected one internal compliance block, found {s.count(old3)}")

s = s.replace(old1, new1, 1)
s = s.replace(old2, new2, 1)
s = s.replace(old3, new3, 1)
compile(s, "analyzer.py", "exec")
p.write_text(s, encoding="utf-8")
print("C2PA policy classification corrected")
print("analyzer.py syntax check: PASSED")
