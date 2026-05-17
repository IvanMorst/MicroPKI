import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
import sys
import time
from threading import Lock
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .ocsp import build_ocsp_response

logger = logging.getLogger(__name__)

# Simple in-memory cache
_cache: Dict[str, Tuple[bytes, float]] = {}
_cache_lock = Lock()


class OCSPHandler(BaseHTTPRequestHandler):
    db_path = None
    ca_cert = None
    responder_cert = None
    responder_key = None
    cache_ttl = 60

    def log_message(self, format, *args):
        logger.info(f"[OCSP] {self.address_string()} - {format % args}")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != '/':
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('application/ocsp-request'):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Expected Content-Type: application/ocsp-request")
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        if content_length == 0:
            self.send_response(400)
            self.end_headers()
            return

        request_data = self.rfile.read(content_length)

        start = time.time()
        try:
            cache_key = request_data.hex()
            with _cache_lock:
                if cache_key in _cache:
                    cached_response, expiry = _cache[cache_key]
                    if time.time() < expiry:
                        self._send_ocsp_response(cached_response)
                        elapsed = (time.time() - start) * 1000
                        logger.info(f"OCSP cache hit, processing time {elapsed:.2f}ms")
                        return

            response_der = build_ocsp_response(
                db_path=self.__class__.db_path,
                ca_cert=self.__class__.ca_cert,
                responder_cert=self.__class__.responder_cert,
                responder_key=self.__class__.responder_key,
                request_data=request_data,
                cache_ttl=self.__class__.cache_ttl
            )

            if self.__class__.cache_ttl > 0:
                with _cache_lock:
                    _cache[cache_key] = (response_der, time.time() + self.__class__.cache_ttl)

            self._send_ocsp_response(response_der)
            elapsed = (time.time() - start) * 1000
            logger.info(f"OCSP request processed in {elapsed:.2f}ms")

        except Exception as e:
            logger.error(f"OCSP request processing failed: {e}", exc_info=True)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal server error")

    def _send_ocsp_response(self, response_der: bytes):
        self.send_response(200)
        self.send_header('Content-Type', 'application/ocsp-response')
        self.send_header('Content-Length', str(len(response_der)))
        self.end_headers()
        self.wfile.write(response_der)


def serve_ocsp(
    host: str,
    port: int,
    db_path: Path,
    responder_cert_path: Path,
    responder_key_path: Path,
    ca_cert_path: Path,
    cache_ttl: int,
):
    """Start OCSP responder HTTP server."""
    db_path = Path(db_path).resolve()
    if not db_path.exists():
        logger.error(f"Database not found: {db_path}")
        sys.exit(1)

    try:
        with open(responder_cert_path, 'rb') as f:
            responder_cert = x509.load_pem_x509_certificate(f.read())
        with open(responder_key_path, 'rb') as f:
            responder_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        logger.error(f"Failed to load certificates/keys: {e}")
        sys.exit(1)

    OCSPHandler.db_path = db_path
    OCSPHandler.ca_cert = ca_cert
    OCSPHandler.responder_cert = responder_cert
    OCSPHandler.responder_key = responder_key
    OCSPHandler.cache_ttl = cache_ttl

    server = HTTPServer((host, port), OCSPHandler)
    logger.info(f"Starting OCSP responder at http://{host}:{port}")
    logger.info(f"Database: {db_path}")
    logger.info(f"CA certificate: {ca_cert_path}")
    logger.info(f"Responder certificate: {responder_cert_path}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("OCSP responder stopped by user")
        server.shutdown()