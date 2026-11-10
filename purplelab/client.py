"""Small HTTPS client: strict certificate verification and bounded retries."""

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path


class ApiError(RuntimeError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(f"API returned {status}: {message[:1500]}")


def secret(name):
    return (Path(os.environ.get("PURPLELAB_STATE", "/state")) / name).read_text().strip()


class Client:
    def __init__(self, service="es", username="elastic"):
        self.url = os.environ.get(
            "ELASTICSEARCH_URL" if service == "es" else "KIBANA_URL",
            "https://elasticsearch:9200" if service == "es" else "https://kibana:5601",
        ).rstrip("/")
        if not self.url.startswith("https://"):
            raise ValueError("Only verified HTTPS endpoints are supported")
        auth = base64.b64encode(f"{username}:{secret(username)}".encode()).decode()
        self.headers = {"Authorization": f"Basic {auth}", "kbn-xsrf": "purplelab"}
        self.context = ssl.create_default_context(cafile=os.environ.get("PURPLELAB_CA", "/certs/ca/ca.crt"))

    def request(self, method, path, body=None, content_type="application/json", retries=3):
        payload = json.dumps(body).encode() if body is not None and not isinstance(body, bytes) else body
        request = urllib.request.Request(
            self.url + path, data=payload, method=method,
            headers={**self.headers, "Content-Type": content_type},
        )
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                    data = response.read()
                    return json.loads(data) if data else {}
            except urllib.error.HTTPError as exc:
                message = exc.read().decode(errors="replace")
                if exc.code not in (429, 502, 503, 504) or attempt == retries:
                    raise ApiError(exc.code, message) from exc
            except (urllib.error.URLError, TimeoutError):
                if attempt == retries:
                    raise
            time.sleep(2 ** attempt)
        raise RuntimeError("Unreachable retry state")

    def bulk(self, events, index):
        lines = []
        for event in events:
            lines.extend([json.dumps({"create": {"_index": index, "_id": event["event"]["id"]}}),
                          json.dumps(event)])
        result = self.request("POST", "/_bulk?refresh=wait_for", ("\n".join(lines) + "\n").encode(),
                              "application/x-ndjson", retries=0)
        if result.get("errors"):
            failures = [item for item in result["items"] if item["create"].get("error")]
            raise RuntimeError(f"Bulk ingestion failed: {failures[:3]}")
        return len(events)
