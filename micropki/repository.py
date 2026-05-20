import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import sys
import hashlib
from datetime import datetime, timezone

from .database import get_certificate_by_serial

logger = logging.getLogger(__name__)


class RepositoryHandler(BaseHTTPRequestHandler):
    db_path = None
    cert_dir = None
    crl_dir = None

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
            self._handle_crl(parsed.query)
        elif path.startswith('/crl/'):
            filename = path.split('/')[-1]
            self._handle_crl_file(filename)
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

    def _handle_crl(self, query_string):
        params = parse_qs(query_string)
        ca_type = params.get('ca', ['intermediate'])[0]

        if ca_type == 'root':
            crl_path = self.__class__.crl_dir / 'root.crl.pem'
        elif ca_type == 'intermediate':
            crl_path = self.__class__.crl_dir / 'intermediate.crl.pem'
        else:
            self.send_error(400, f"Invalid CA type: {ca_type}")
            return

        self._serve_crl_file(crl_path)

    def _handle_crl_file(self, filename):
        if filename == 'root.crl' or filename == 'root.crl.pem':
            crl_path = self.__class__.crl_dir / 'root.crl.pem'
        elif filename == 'intermediate.crl' or filename == 'intermediate.crl.pem':
            crl_path = self.__class__.crl_dir / 'intermediate.crl.pem'
        else:
            self.send_error(404, "CRL not found")
            return

        self._serve_crl_file(crl_path)

    def _serve_crl_file(self, crl_path):
        if not crl_path.exists():
            self.send_error(404, "CRL not found")
            return

        stat = crl_path.stat()
        last_modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        with open(crl_path, 'rb') as f:
            etag = hashlib.md5(f.read()).hexdigest()

        self.send_response(200)
        self.send_header('Content-Type', 'application/pkix-crl')
        self.send_header('Last-Modified', last_modified.strftime('%a, %d %b %Y %H:%M:%S GMT'))
        self.send_header('Cache-Control', 'max-age=3600')
        self.send_header('ETag', f'"{etag}"')
        self.end_headers()

        with open(crl_path, 'rb') as f:
            self.wfile.write(f.read())


def serve_repository(host, port, db_path, cert_dir, crl_dir):
    db_path = Path(db_path).resolve()
    cert_dir = Path(cert_dir).resolve()
    crl_dir = Path(crl_dir).resolve()

    if not db_path.exists():
        logger.error(f"Database file {db_path} does not exist. Run 'micropki db init' first.")
        sys.exit(1)

    RepositoryHandler.db_path = db_path
    RepositoryHandler.cert_dir = cert_dir
    RepositoryHandler.crl_dir = crl_dir

    server = HTTPServer((host, port), RepositoryHandler)
    logger.info(f"Starting repository server at http://{host}:{port}")
    logger.info(f"Database: {db_path}")
    logger.info(f"Certificate directory: {cert_dir}")
    logger.info(f"CRL directory: {crl_dir}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.shutdown()

def do_POST(self):
    parsed = urlparse(self.path)
    if parsed.path == '/request-cert':
        self._handle_request_cert(parsed.query)
    else:
        self.send_error(404, "Not Found")

def _handle_request_cert(self, query_string):
    from urllib.parse import parse_qs
    from argparse import Namespace
    import tempfile
    from . import ca

    params = parse_qs(query_string)
    template = params.get('template', [''])[0]
    if not template or template not in ['server', 'client', 'code_signing']:
        self.send_error(400, "Missing or invalid template parameter")
        return

    content_length = int(self.headers.get('Content-Length', 0))
    if content_length == 0:
        self.send_error(400, "Empty request body")
        return
    csr_data = self.rfile.read(content_length)

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.csr', delete=False) as tmp:
        tmp.write(csr_data)
        csr_path = tmp.name

    out_dir = Path(self.cert_dir).parent / 'certs'
    out_dir.mkdir(parents=True, exist_ok=True)

    pass_file = Path(self.cert_dir).parent.parent / 'secrets' / 'intermediate.pass'
    if not pass_file.exists():
        self.send_error(500, "CA passphrase file not found")
        return

    args = Namespace(
        csr=csr_path,
        ca_cert=str(self.cert_dir / 'intermediate.cert.pem'),
        ca_key=str(self.cert_dir.parent / 'private' / 'intermediate.key.pem'),
        ca_pass_file=str(pass_file),
        template=template,
        subject='',
        san=None,
        out_dir=str(out_dir),
        validity_days=365,
        db_path=str(self.db_path),
        key_type='rsa',
        key_size=2048
    )

    try:
        ca.issue_certificate(args)
        cert_files = sorted(out_dir.glob('*.cert.pem'), key=lambda p: p.stat().st_mtime, reverse=True)
        if not cert_files:
            raise Exception("No certificate generated")
        cert_pem = cert_files[0].read_bytes()
        self.send_response(201)
        self.send_header('Content-Type', 'application/x-pem-file')
        self.end_headers()
        self.wfile.write(cert_pem)
    except Exception as e:
        logger.error(f"CSR issuance failed: {e}")
        self.send_error(500, f"Internal error: {e}")
    finally:
        Path(csr_path).unlink(missing_ok=True)