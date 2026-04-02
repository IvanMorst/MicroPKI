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
    repo_serve_cmd.add_argument('--log-file')

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
            init_db(db_path)
            print(f"Database initialised at {db_path}")
        elif args.command == 'list-certs':
            _do_list_certs(args)
        elif args.command == 'show-cert':
            _do_show_cert(args)
        elif args.command == 'repo' and args.repo_command == 'serve':
            serve_repository(args.host, args.port, args.db_path, args.cert_dir)
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

if __name__ == '__main__':
    main()