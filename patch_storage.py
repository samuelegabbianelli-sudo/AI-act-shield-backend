from pathlib import Path

path = Path("analyzer.py")
text = path.read_text(encoding="utf-8")

start = text.index("def parse_storage_ref(file_url: str):")
end = text.index("\n\n# ============================================================\n# 6. FILE UTILITIES", start)

replacement = '''def normalize_storage_path(file_url: str):
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
'''

text = text[:start] + replacement + text[end:]

compile(text, "analyzer.py", "exec")
path.write_text(text, encoding="utf-8")
print("analyzer.py storage patch syntax OK")
