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

    if result["trusted"]:
        if C2PA_USER_ANCHORS_PEM.strip():
            result["trust_source"] = "ai_act_shield_policy"
            result["status"] = "trusted_internal"
        else:
            result["trust_source"] = "c2pa_official"
'''

old2 = '''    if c2pa_status == "trusted":
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
'''
new2 = '''    if c2pa_status == "trusted_internal":
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
            ),
            "trust_source": "c2pa_official"
        }
'''

if s.count(old1) != 1:
    raise SystemExit(f"Expected one trust block, found {s.count(old1)}")
if s.count(old2) != 1:
    raise SystemExit(f"Expected one compliance block, found {s.count(old2)}")

s = s.replace(old1, new1, 1)
s = s.replace(old2, new2, 1)
compile(s, "analyzer.py", "exec")
p.write_text(s, encoding="utf-8")
print("C2PA policy classification added")
print("analyzer.py syntax check: PASSED")
