#!/usr/bin/env python3
import argparse
import sys
import logging
from pathlib import Path

from . import logger
from . import ca
from .database import init_db, list_certificates, get_certificate_by_serial
from .repository import serve_repository

def main():
    parser = argparse.ArgumentParser(description="MicroPKI - Minimal PKI", prog="micropki")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Sprint 1: ca init
    ca_init = subparsers.add_parser('init', help='Initialize Root CA')
    ca_init.add_argument('--subject', required=True)
    ca_init.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    ca_init.add_argument('--key-size', type=int, default=4096)
    ca_init.add_argument('--passphrase-file', required=True)
    ca_init.add_argument('--out-dir', default='./pki')
    ca_init.add_argument('--validity-days', type=int, default=3650)
    ca_init.add_argument('--db-path', help='SQLite database path (default: <out-dir>/micropki.db)')
    ca_init.add_argument('--log-file')

    # Sprint 2: issue-intermediate
    ca_inter = subparsers.add_parser('issue-intermediate', help='Create Intermediate CA')
    ca_inter.add_argument('--root-cert', required=True)
    ca_inter.add_argument('--root-key', required=True)
    ca_inter.add_argument('--root-pass-file', required=True)
    ca_inter.add_argument('--subject', required=True)
    ca_inter.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    ca_inter.add_argument('--key-size', type=int, default=4096)
    ca_inter.add_argument('--passphrase-file', required=True)
    ca_inter.add_argument('--out-dir', default='./pki')
    ca_inter.add_argument('--validity-days', type=int, default=1825)
    ca_inter.add_argument('--pathlen', type=int, default=0)
    ca_inter.add_argument('--db-path', help='SQLite database path')
    ca_inter.add_argument('--log-file')

    # Sprint 2: issue-cert
    ca_issue = subparsers.add_parser('issue-cert', help='Issue end-entity certificate')
    ca_issue.add_argument('--ca-cert', required=True)
    ca_issue.add_argument('--ca-key', required=True)
    ca_issue.add_argument('--ca-pass-file', required=True)
    ca_issue.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    ca_issue.add_argument('--subject', required=True)
    ca_issue.add_argument('--san', action='append')
    ca_issue.add_argument('--out-dir', default='./pki/certs')
    ca_issue.add_argument('--validity-days', type=int, default=365)
    ca_issue.add_argument('--db-path', help='SQLite database path')
    ca_issue.add_argument('--log-file')

    # Sprint 3: db init
    db_init = subparsers.add_parser('db', help='Database commands')
    db_sub = db_init.add_subparsers(dest='db_command', required=True)
    db_init_cmd = db_sub.add_parser('init', help='Initialise database')
    db_init_cmd.add_argument('--db-path', default='./pki/micropki.db')
    db_init_cmd.add_argument('--force', action='store_true', help='Force reinitialisation')
    db_init_cmd.add_argument('--log-file')

    # Sprint 3: ca list-certs
    list_certs = subparsers.add_parser('list-certs', help='List issued certificates')
    list_certs.add_argument('--status', choices=['valid', 'revoked', 'expired'])
    list_certs.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    list_certs.add_argument('--db-path', default='./pki/micropki.db')
    list_certs.add_argument('--log-file')

    # Sprint 3: ca show-cert
    show_cert = subparsers.add_parser('show-cert', help='Show certificate by serial')
    show_cert.add_argument('serial', help='Serial number in hex')
    show_cert.add_argument('--db-path', default='./pki/micropki.db')
    show_cert.add_argument('--log-file')

    # Sprint 3: repo serve
    repo_serve = subparsers.add_parser('repo', help='Repository server')
    repo_sub = repo_serve.add_subparsers(dest='repo_command', required=True)
    repo_serve_cmd = repo_sub.add_parser('serve', help='Start HTTP server')
    repo_serve_cmd.add_argument('--host', default='127.0.0.1')
    repo_serve_cmd.add_argument('--port', type=int, default=8080)
    repo_serve_cmd.add_argument('--db-path', default='./pki/micropki.db')
    repo_serve_cmd.add_argument('--cert-dir', default='./pki/certs')
    repo_serve_cmd.add_argument('--crl-dir', default='./pki/crl')
    repo_serve_cmd.add_argument('--log-file')

    # Sprint 4: ca revoke
    ca_revoke = subparsers.add_parser('revoke', help='Revoke a certificate')
    ca_revoke.add_argument('serial', help='Certificate serial number in hex')
    ca_revoke.add_argument('--reason', default='unspecified',
                          choices=['unspecified', 'keyCompromise', 'cACompromise',
                                  'affiliationChanged', 'superseded', 'cessationOfOperation',
                                  'certificateHold', 'removeFromCRL', 'privilegeWithdrawn',
                                  'aACompromise'])
    ca_revoke.add_argument('--force', action='store_true', help='Skip confirmation')
    ca_revoke.add_argument('--db-path', default='./pki/micropki.db')
    ca_revoke.add_argument('--log-file')

    # Sprint 4: ca gen-crl
    ca_gencrl = subparsers.add_parser('gen-crl', help='Generate CRL for a CA')
    ca_gencrl.add_argument('--ca', required=True, choices=['root', 'intermediate'],
                          help='CA type (root or intermediate)')
    ca_gencrl.add_argument('--next-update', type=int, default=7,
                          help='Days until next CRL update (default: 7)')
    ca_gencrl.add_argument('--out-file', help='Output file path (default: auto)')
    ca_gencrl.add_argument('--out-dir', default='./pki', help='Output directory')
    ca_gencrl.add_argument('--db-path', help='SQLite database path')
    ca_gencrl.add_argument('--passphrase-file', help='Passphrase file for CA key')
    ca_gencrl.add_argument('--log-file')

    # Sprint 4: ca check-revoked (optional)
    ca_check = subparsers.add_parser('check-revoked', help='Check certificate revocation status')
    ca_check.add_argument('serial', help='Certificate serial number in hex')
    ca_check.add_argument('--db-path', default='./pki/micropki.db')
    ca_check.add_argument('--log-file')

    # Sprint 4: ca validate-chain
    ca_validate = subparsers.add_parser('validate-chain', help='Validate certificate chain')
    ca_validate.add_argument('--leaf', required=True, help='Path to leaf certificate')
    ca_validate.add_argument('--intermediate', action='append', help='Path to intermediate certificate')
    ca_validate.add_argument('--root', required=True, help='Path to root certificate')
    ca_validate.add_argument('--log-file')

    # Sprint 5: ca issue-ocsp-cert
    ca_ocsp_cert = subparsers.add_parser('issue-ocsp-cert', help='Issue OCSP responder certificate')
    ca_ocsp_cert.add_argument('--ca-cert', required=True)
    ca_ocsp_cert.add_argument('--ca-key', required=True)
    ca_ocsp_cert.add_argument('--ca-pass-file', required=True)
    ca_ocsp_cert.add_argument('--subject', required=True)
    ca_ocsp_cert.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    ca_ocsp_cert.add_argument('--key-size', type=int, default=2048)
    ca_ocsp_cert.add_argument('--san', action='append')
    ca_ocsp_cert.add_argument('--out-dir', default='./pki/certs')
    ca_ocsp_cert.add_argument('--validity-days', type=int, default=365)
    ca_ocsp_cert.add_argument('--db-path', help='SQLite database path')
    ca_ocsp_cert.add_argument('--log-file')

    # Sprint 5: ocsp serve
    ocsp_serve = subparsers.add_parser('ocsp', help='OCSP responder commands')
    ocsp_sub = ocsp_serve.add_subparsers(dest='ocsp_command', required=True)
    ocsp_serve_cmd = ocsp_sub.add_parser('serve', help='Start OCSP responder')
    ocsp_serve_cmd.add_argument('--host', default='127.0.0.1')
    ocsp_serve_cmd.add_argument('--port', type=int, default=8081)
    ocsp_serve_cmd.add_argument('--db-path', default='./pki/micropki.db')
    ocsp_serve_cmd.add_argument('--responder-cert', required=True)
    ocsp_serve_cmd.add_argument('--responder-key', required=True)
    ocsp_serve_cmd.add_argument('--ca-cert', required=True)
    ocsp_serve_cmd.add_argument('--cache-ttl', type=int, default=60)
    ocsp_serve_cmd.add_argument('--log-file')

    # Sprint 6: client subcommands
    client_parser = subparsers.add_parser('client', help='Client tools')
    client_sub = client_parser.add_subparsers(dest='client_command', required=True)

    gen_csr = client_sub.add_parser('gen-csr', help='Generate private key and CSR')
    gen_csr.add_argument('--subject', required=True)
    gen_csr.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    gen_csr.add_argument('--key-size', type=int, default=2048)
    gen_csr.add_argument('--san', action='append')
    gen_csr.add_argument('--out-key', default='./key.pem')
    gen_csr.add_argument('--out-csr', default='./request.csr.pem')
    gen_csr.add_argument('--log-file')

    req_cert = client_sub.add_parser('request-cert', help='Submit CSR to CA')
    req_cert.add_argument('--csr', required=True)
    req_cert.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    req_cert.add_argument('--ca-url', required=True)
    req_cert.add_argument('--api-key', help='API key for authentication')
    req_cert.add_argument('--out-cert', default='./cert.pem')
    req_cert.add_argument('--log-file')

    validate = client_sub.add_parser('validate', help='Validate certificate chain')
    validate.add_argument('--cert', required=True)
    validate.add_argument('--untrusted', action='append')
    validate.add_argument('--trusted', default='./pki/certs/ca.cert.pem')
    validate.add_argument('--crl-url', help='CRL URL')
    validate.add_argument('--ocsp-url', help='OCSP URL')
    validate.add_argument('--mode', choices=['chain', 'full'], default='full')
    validate.add_argument('--validation-time', help='ISO timestamp for validation (testing)')
    validate.add_argument('--log-file')

    check_status = client_sub.add_parser('check-status', help='Check revocation status')
    check_status.add_argument('--cert', required=True)
    check_status.add_argument('--ca-cert', required=True)
    check_status.add_argument('--crl-url')
    check_status.add_argument('--ocsp-url')
    check_status.add_argument('--log-file')

    # Добавить --csr флаг к существующему issue-cert
    ca_issue.add_argument('--csr', help='Sign an external CSR instead of generating new key')
    args = parser.parse_args()
    log_file = getattr(args, 'log_file', None)
    logger.setup_logger(log_file)
    log = logging.getLogger(__name__)

    try:
        if args.command == 'init':
            _validate_init_args(args)
            ca.init_ca(args)
        elif args.command == 'issue-intermediate':
            _validate_intermediate_args(args)
            ca.issue_intermediate(args)
        elif args.command == 'issue-cert':
            _validate_issue_args(args)
            ca.issue_certificate(args)
        elif args.command == 'db' and args.db_command == 'init':
            db_path = Path(args.db_path)
            init_db(db_path, force=args.force)
            print(f"Database initialised at {db_path}")
        elif args.command == 'list-certs':
            _do_list_certs(args)
        elif args.command == 'show-cert':
            _do_show_cert(args)
        elif args.command == 'repo' and args.repo_command == 'serve':
            serve_repository(args.host, args.port, args.db_path, args.cert_dir, args.crl_dir)
        elif args.command == 'revoke':
            ca.revoke_certificate_cmd(args)
        elif args.command == 'gen-crl':
            ca.generate_crl_cmd(args)
        elif args.command == 'check-revoked':
            _do_check_revoked(args)
        elif args.command == 'validate-chain':
            _do_validate_chain(args)
        elif args.command == 'issue-ocsp-cert':
            ca.issue_ocsp_cert(args)
        elif args.command == 'client':
            if args.client_command == 'gen-csr':
                from .client import client_gen_csr
                client_gen_csr(args)
            elif args.client_command == 'request-cert':
                from .client import client_request_cert
                client_request_cert(args)
            elif args.client_command == 'validate':
                from .client import client_validate
                client_validate(args)
            elif args.client_command == 'check-status':
                from .client import client_check_status
                client_check_status(args)
        elif args.command == 'ocsp' and args.ocsp_command == 'serve':
            from .ocsp_responder import serve_ocsp
            serve_ocsp(
                host=args.host,
                port=args.port,
                db_path=Path(args.db_path),
                responder_cert_path=Path(args.responder_cert),
                responder_key_path=Path(args.responder_key),
                ca_cert_path=Path(args.ca_cert),
                cache_ttl=args.cache_ttl
            )
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as e:
        log.exception("Command failed")
        sys.exit(1)


def _validate_init_args(args):
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384")
    if not Path(args.passphrase_file).exists():
        raise ValueError(f"Passphrase file not found: {args.passphrase_file}")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def _validate_intermediate_args(args):
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384")
    for f in [args.root_cert, args.root_key, args.root_pass_file, args.passphrase_file]:
        if not Path(f).exists():
            raise ValueError(f"File not found: {f}")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def _validate_issue_args(args):
    for f in [args.ca_cert, args.ca_key, args.ca_pass_file]:
        if not Path(f).exists():
            raise ValueError(f"File not found: {f}")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def _do_list_certs(args):
    db_path = Path(args.db_path)
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        sys.exit(1)
    certs = list_certificates(db_path, args.status)
    if args.format == 'table':
        print(f"{'Serial':<20} {'Subject':<40} {'Expiration':<25} {'Status':<10}")
        print("-" * 95)
        for c in certs:
            print(f"{c['serial_hex']:<20} {c['subject'][:40]:<40} {c['not_after'][:25]:<25} {c['status']:<10}")
    elif args.format == 'json':
        import json
        print(json.dumps(certs, indent=2))
    elif args.format == 'csv':
        import csv
        writer = csv.DictWriter(sys.stdout, fieldnames=['serial_hex', 'subject', 'not_after', 'status'])
        writer.writeheader()
        writer.writerows(certs)


def _do_show_cert(args):
    db_path = Path(args.db_path)
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        sys.exit(1)
    cert_data = get_certificate_by_serial(db_path, args.serial)
    if not cert_data:
        print(f"Certificate with serial {args.serial} not found")
        sys.exit(1)
    print(cert_data['cert_pem'])


def _do_check_revoked(args):
    from .revocation import validate_reason
    db_path = Path(args.db_path)
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        sys.exit(1)
    cert_data = get_certificate_by_serial(db_path, args.serial)
    if not cert_data:
        print(f"Certificate with serial {args.serial} not found")
        sys.exit(1)
    if cert_data['status'] == 'revoked':
        print(f"REVOKED - Reason: {cert_data['revocation_reason']}, Date: {cert_data['revocation_date']}")
    else:
        print("VALID")


def _do_validate_chain(args):
    from cryptography import x509
    from . import chain

    leaf = x509.load_pem_x509_certificate(Path(args.leaf).read_bytes())
    root = x509.load_pem_x509_certificate(Path(args.root).read_bytes())
    intermediates = []
    if args.intermediate:
        for int_path in args.intermediate:
            cert = x509.load_pem_x509_certificate(Path(int_path).read_bytes())
            intermediates.append(cert)

    if chain.validate_chain(leaf, intermediates, root):
        print("Chain validation: SUCCESS")
        chain.print_chain_info(leaf, intermediates, root)
    else:
        print("Chain validation: FAILED")
        sys.exit(1)


if __name__ == '__main__':
    main()