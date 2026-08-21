import time
import os
import io
import threading
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from supabase import create_client, Client
import c2pa

# 1. Configurazione Credenziali Supabase
SUPABASE_URL = "https://ulvlohhszcmdzqvipvan.supabase.co"
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "INCOLLA_QUI_LA_TUA_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)

# 2. Server Dummy per il Port Check di Render
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"AI Act Shield Worker is Running!")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

def run_http_server():
    port = int(os.environ.get("PORT", 10000))
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"🌐 Server HTTP fittizio avviato sulla porta {port}")
    httpd.serve_forever()

# 3. Rilevazione Tipo MIME (Immagini, Video, Audio)
def detect_mime_type(file_url: str, file_bytes: bytes) -> str:
    """Rileva il tipo di file (Immagine, Video o Audio)"""
    mime_type, _ = mimetypes.guess_type(file_url)
    if not mime_type:
        # Fallback basato sui primi byte se l'estensione manca
        if file_bytes.startswith(b'\xFF\xFB') or file_bytes.startswith(b'ID3'):
            return "audio/mp3"
        elif len(file_bytes) >= 8 and file_bytes[4:8] == b'ftyp':
            return "video/mp4"
        return "image/jpeg"
    return mime_type

# 4. Controllo Metadati C2PA Universale
def check_c2pa_metadata(file_bytes: bytes, mime_type: str) -> dict:
    """Verifica metadati C2PA per Immagini, Video e Audio"""
    try:
        reader = c2pa.Reader(mime_type, file_bytes)
        manifest = reader.active_manifest()
        if manifest:
            return {
                "detected": True,
                "claim_generator": getattr(manifest, 'claim_generator', 'C2PA Validated'),
                "title": getattr(manifest, 'title', None)
            }
    except Exception as e:
        print(f"Lettura C2PA non riuscita per {mime_type}: {e}")
        
    return {"detected": False, "claim_generator": None}

# 5. Iniezione Metadati C2PA (Auto-Fix)
def apply_c2pa_fix(file_bytes: bytes, audit_id: str, mime_type: str) -> str:
    """Inietta metadati C2PA di conformità e carica il file sanato su Supabase Storage"""
    try:
        target_mime = mime_type if ("image" in mime_type) else "image/jpeg"
        
        manifest_json = """{
            "claim_generator": "AI_Act_Shield_v1.0",
            "title": "EU AI Act Compliant Asset",
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.edited",
                                "parameters": {
                                    "description": "Metadati di trasparenza AI Act aggiunti da AI Act Shield"
                                }
                            }
                        ]
                    }
                }
            ]
        }"""

        input_stream = io.BytesIO(file_bytes)
        output_stream = io.BytesIO()

        # Iniezione del manifesto tramite c2pa-python
        builder = c2pa.Builder(manifest_json)
        builder.sign(target_mime, input_stream, output_stream)
        fixed_bytes = output_stream.getvalue()

        # Determinazione estensione
        ext = "jpg"
        if "png" in target_mime:
            ext = "png"
        elif "mp4" in target_mime:
            ext = "mp4"
        elif "mp3" in target_mime:
            ext = "mp3"

        # Carica il file sanato nel bucket Supabase Storage ("audits_fixed")
        fixed_filename = f"fixed_{audit_id}.{ext}"
        supabase.storage.from_("audits_fixed").upload(
            file=fixed_bytes,
            path=fixed_filename,
            file_options={"content-type": target_mime, "upsert": "true"}
        )

        fixed_url = supabase.storage.from_("audits_fixed").get_public_url(fixed_filename)
        return fixed_url
    except Exception as e:
        print(f"⚠️ Errore durante l'auto-fix C2PA: {e}")
        return None

# 6. Elaborazione degli Audit in Coda
def process_pending_audits():
    try:
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

            file_res = requests.get(file_url)
            if file_res.status_code != 200:
                supabase.table("audits").update({
                    "status": "error",
                    "details": {"error": "Impossibile scaricare il file"}
                }).eq("id", audit_id).execute()
                continue

            file_bytes = file_res.content

            # --- RILEVAZIONE FORMATO ED ESECUZIONE AUDIT C2PA ---
            mime_type = detect_mime_type(file_url, file_bytes)
            c2pa_result = check_c2pa_metadata(file_bytes, mime_type)

            # Se NON contiene metadati C2PA -> NON CONFORME (Richiede Fix)
            if not c2pa_result["detected"]:
                status = "non_compliant"
                score_generativo = 85
                fixed_url = apply_c2pa_fix(file_bytes, audit_id, mime_type)
            else:
                status = "compliant"
                score_generativo = 10
                fixed_url = None

            supabase.table("audits").update({
                "status": status,
                "fixed_file_url": fixed_url,
                "details": {
                    "mime_type": mime_type,
                    "generative_score": score_generativo,
                    "generator": c2pa_result.get("claim_generator", "AI Act Shield Auto-Fix"),
                    "c2pa_info": c2pa_result,
                    "recommendation": "File privo di metadati C2PA. Applicata firma di trasparenza." if fixed_url else "File conforme."
                }
            }).eq("id", audit_id).execute()

            print(f"✅ Audit {audit_id} completato! Stato: {status}")

    except Exception as e:
        print(f"❌ Errore nell'elaborazione degli audit: {e}")

def audit_loop():
    print("🚀 Servizio di Analisi & Auto-Fix AI Act Shield Avviato...")
    while True:
        process_pending_audits()
        time.sleep(3)

if __name__ == "__main__":
    threading.Thread(target=audit_loop, daemon=True).start()
    run_http_server()
