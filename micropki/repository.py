import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
import sys

from .database import get_certificate_by_serial

logger = logging.getLogger(__name__)

class RepositoryHandler(BaseHTTPRequestHandler):
    db_path = None
    cert_dir = None

    def log_message(self, format, *args):
        logger.info(f"[HTTP] {self.address_string()} - {format % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith('/certificate/'):
            serial = path.split('/')[-1]
            self._handle_get_certificate(serial)
        elif path == '/ca/root':
            self._handle_get_ca('root')
        elif path == '/ca/intermediate':
            self._handle_get_ca('intermediate')
        elif path == '/crl':
            self._handle_crl()
        else:
            self.send_error(404, "Not Found")

    def _handle_get_certificate(self, serial):
        try:
            int(serial, 16)
        except ValueError:
            self.send_error(400, "Invalid serial number format (must be hexadecimal)")
            return

        cert_data = get_certificate_by_serial(self.__class__.db_path, serial)
        if cert_data is None:
            self.send_error(404, "Certificate not found")
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/x-pem-file')
        self.end_headers()
        self.wfile.write(cert_data['cert_pem'].encode('utf-8'))

    def _handle_get_ca(self, level):
        filename = 'ca.cert.pem' if level == 'root' else 'intermediate.cert.pem'
        cert_path = self.__class__.cert_dir / filename
        if not cert_path.exists():
            self.send_error(404, f"{level.capitalize()} CA certificate not found")
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/x-pem-file')
        self.end_headers()
        with open(cert_path, 'rb') as f:
            self.wfile.write(f.read())

    def _handle_crl(self):
        self.send_response(501)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"CRL generation not yet implemented")

def serve_repository(host, port, db_path, cert_dir):
    db_path = Path(db_path).resolve()
    cert_dir = Path(cert_dir).resolve()

    if not db_path.exists():
        logger.error(f"Database file {db_path} does not exist. Run 'micropki db init' first.")
        sys.exit(1)

    RepositoryHandler.db_path = db_path
    RepositoryHandler.cert_dir = cert_dir

    server = HTTPServer((host, port), RepositoryHandler)
    logger.info(f"Starting repository server at http://{host}:{port}")
    logger.info(f"Database: {db_path}")
    logger.info(f"Certificate directory: {cert_dir}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.shutdown()