import time
import requests
from supabase import create_client, Client
import c2pa

# 1. Configurazione Credenziali Supabase
import os

SUPABASE_URL = "https://ulvlohhszcmdzqvipvan.supabase.co"
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "INCOLLA_QUI_SE_SERVE")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)

def check_c2pa_metadata(file_bytes: bytes) -> dict:
    """Verifica se il file contiene metadati crittografici C2PA"""
    try:
        # Usa il Reader integrato della libreria c2pa
        reader = c2pa.Reader("image/jpeg", file_bytes)
        manifest = reader.active_manifest()
        if manifest:
            return {
                "detected": True,
                "claim_generator": getattr(manifest, 'claim_generator', 'C2PA Validated'),
                "title": getattr(manifest, 'title', None)
            }
    except Exception:
        pass
        
    return {"detected": False, "claim_generator": None}

def process_pending_audits():
    """Recupera gli audit in sospeso da Supabase, analizza il file e aggiorna lo stato"""
    try:
        # Recupera gli audit con stato 'pending'
        response = supabase.table("audits").select("*").eq("status", "pending").execute()
        pending_audits = response.data

        if not pending_audits:
            print("🔍 Controllo nuovi audit in coda...")
            return

        for audit in pending_audits:
            audit_id = audit.get("id")
            file_url = audit.get("file_url")
            print(f"⚡ Analisi in corso per audit ID: {audit_id}")

            if not file_url:
                supabase.table("audits").update({
                    "status": "error",
                    "details": {"error": "URL file mancante"}
                }).eq("id", audit_id).execute()
                continue

            # Scarica il file dal bucket Supabase Storage
            file_res = requests.get(file_url)
            if file_res.status_code != 200:
                supabase.table("audits").update({
                    "status": "error",
                    "details": {"error": "Impossibile scaricare il file"}
                }).eq("id", audit_id).execute()
                continue

            file_bytes = file_res.content

            # Analisi C2PA / Watermark
            c2pa_result = check_c2pa_metadata(file_bytes)

            # Determina la conformità (non_compliant se non ha metadati C2PA)
            status = "compliant" if c2pa_result["detected"] else "non_compliant"

            # Aggiorna il record su Supabase
            supabase.table("audits").update({
                "status": status,
                "details": {
                    "generator": c2pa_result.get("claim_generator", "Sconosciuto"),
                    "c2pa_info": c2pa_result
                }
            }).eq("id", audit_id).execute()

            print(f"✅ Audit {audit_id} completato! Stato: {status}")

    except Exception as e:
        print(f"❌ Errore nell'elaborazione degli audit: {e}")

# Ciclo continuo di ascolto (Polling)
if __name__ == "__main__":
    print("🚀 Servizio di Analisi AI Act Shield Avviato...")
    while True:
        process_pending_audits()
        time.sleep(3) # Controllo nuovi file ogni 3 secondi
