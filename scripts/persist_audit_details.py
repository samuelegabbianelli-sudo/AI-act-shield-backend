from pathlib import Path

path = Path("analyzer.py")
text = path.read_text(encoding="utf-8")

needle = '''                "recommendation": recommendation,\n                "risk_score": risk_result["score"],'''

replacement = '''                "recommendation": recommendation,\n                "details": {\n                    "c2pa": c2pa_result,\n                    "ai": ai_result,\n                    "metadata": metadata_result,\n                    "risk": risk_result,\n                    "decision": compliance_result["decision"],\n                    "decision_basis": decision_basis,\n                    "recommendation": recommendation,\n                    "trust_source": compliance_result.get("trust_source"),\n                    "status": c2pa_result.get("status"),\n                },\n                "risk_score": risk_result["score"],'''

if '"details": {' in text:
    raise SystemExit("Audit details block already exists; refusing to modify analyzer.py.")

if text.count(needle) != 1:
    raise SystemExit(f"Expected exactly one audit update block, found {text.count(needle)}")

text = text.replace(needle, replacement, 1)
compile(text, "analyzer.py", "exec")
path.write_text(text, encoding="utf-8")
print("Persisted structured audit details.")
print("analyzer.py syntax check: PASSED")
