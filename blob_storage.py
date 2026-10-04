"""Small Vercel Blob adapter used by the Flask app on Vercel.

It stores the SQLite database as one private blob. Each connection downloads the
latest database and conditionally writes it back with its ETag, preserving the
existing application model while avoiding an ephemeral serverless filesystem.
"""
import os
import sqlite3
import mimetypes
import requests

BLOB_API = "https://blob.vercel-storage.com"
DB_PATHNAME = "state/portfolio.sqlite"


class StorageConflict(RuntimeError):
    pass


def enabled():
    return bool(os.environ.get("BLOB_READ_WRITE_TOKEN"))


def _token():
    value = os.environ.get("BLOB_READ_WRITE_TOKEN")
    if not value:
        raise RuntimeError("BLOB_READ_WRITE_TOKEN is not configured")
    return value


def _headers(**extra):
    headers = {
        "Authorization": f"Bearer {_token()}",
        "x-api-version": "12",
    }
    headers.update(extra)
    return headers


def list_blobs(prefix):
    response = requests.get(
        BLOB_API,
        headers=_headers(),
        params={"prefix": prefix, "limit": "100"},
        timeout=20,
    )
    response.raise_for_status()
    return response.json().get("blobs", [])


def blob_info(pathname):
    return next((item for item in list_blobs(pathname) if item["pathname"] == pathname), None)


def get_blob(pathname):
    info = blob_info(pathname)
    if not info:
        return None, None, None
    response = requests.get(
        info["url"],
        headers={"Authorization": f"Bearer {_token()}"},
        timeout=30,
    )
    response.raise_for_status()
    return response.content, info.get("etag"), info


def put_blob(pathname, data, content_type=None, etag=None):
    headers = _headers(
        **{
            "x-vercel-blob-access": "private",
            "x-add-random-suffix": "0",
            "x-allow-overwrite": "1",
            "x-content-type": content_type or mimetypes.guess_type(pathname)[0] or "application/octet-stream",
            "x-cache-control-max-age": "60",
        }
    )
    if etag:
        headers["x-if-match"] = etag
    response = requests.put(
        BLOB_API,
        params={"pathname": pathname},
        headers=headers,
        data=data,
        timeout=30,
    )
    if response.status_code == 412:
        raise StorageConflict("The portfolio changed in another request. Please retry.")
    response.raise_for_status()
    return response.json()


class BlobConnection(sqlite3.Connection):
    _starting_changes = 0
    _source_etag = None
    _temporary_path = None

    def __enter__(self):
        super().__enter__()
        self._starting_changes = self.total_changes
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        result = super().__exit__(exc_type, exc_value, traceback)
        if exc_type is None and self.total_changes != self._starting_changes:
            self._sync()
        return result

    def _sync(self):
        self.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        stored = put_blob(
            DB_PATHNAME,
            open(self._temporary_path, "rb").read(),
            "application/vnd.sqlite3",
            self._source_etag,
        )
        self._source_etag = stored.get("etag")
        self._starting_changes = self.total_changes

    def close(self):
        path = self._temporary_path
        try:
            super().close()
        finally:
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass


def connect_blob():
    import tempfile
    raw, etag, _ = get_blob(DB_PATHNAME)
    handle = tempfile.NamedTemporaryFile(prefix="portfolio-", suffix=".sqlite", delete=False)
    path = handle.name
    if raw:
        handle.write(raw)
    handle.close()
    connection = sqlite3.connect(path, factory=BlobConnection)
    connection.row_factory = sqlite3.Row
    connection._source_etag = etag
    connection._temporary_path = path
    return connection