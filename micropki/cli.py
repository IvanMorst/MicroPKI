#!/usr/bin/env python3
import argparse
import sys
import logging
from pathlib import Path
import os

from . import logger
from . import ca

# Экспортируем функции валидации для тестов
__all__ = ['main', 'validate_args', 'validate_intermediate_args', 'validate_issue_args', 'validate_chain_args']


def main():
    parser = argparse.ArgumentParser(
        description="MicroPKI - Minimal Public Key Infrastructure",
        prog="micropki"
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Sprint 1: ca init
    ca_init = subparsers.add_parser('init', help='Initialize a self-signed Root CA')
    ca_init.add_argument('--subject', required=True,
                         help='Distinguished Name (e.g., "/CN=My Root CA" or "CN=My Root CA,O=Demo")')
    ca_init.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa',
                         help='Key algorithm (default: rsa)')
    ca_init.add_argument('--key-size', type=int, default=4096,
                         help='Key size in bits (RSA: 4096, ECC: 384)')
    ca_init.add_argument('--passphrase-file', required=True,
                         help='Path to file containing passphrase for private key encryption')
    ca_init.add_argument('--out-dir', default='./pki',
                         help='Output directory (default: ./pki)')
    ca_init.add_argument('--validity-days', type=int, default=3650,
                         help='Validity period in days (default: 3650)')
    ca_init.add_argument('--log-file',
                         help='Optional log file (default: stderr)')

    # Sprint 2: ca issue-intermediate
    ca_inter = subparsers.add_parser('issue-intermediate',
                                     help='Create and sign an Intermediate CA certificate')
    ca_inter.add_argument('--root-cert', required=True,
                          help='Path to Root CA certificate (PEM)')
    ca_inter.add_argument('--root-key', required=True,
                          help='Path to Root CA encrypted private key (PEM)')
    ca_inter.add_argument('--root-pass-file', required=True,
                          help='File containing passphrase for Root CA key')
    ca_inter.add_argument('--subject', required=True,
                          help='Distinguished Name for Intermediate CA')
    ca_inter.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa',
                          help='Key algorithm (default: rsa)')
    ca_inter.add_argument('--key-size', type=int, default=4096,
                          help='Key size (RSA: 4096, ECC: 384)')
    ca_inter.add_argument('--passphrase-file', required=True,
                          help='File containing passphrase for Intermediate CA key')
    ca_inter.add_argument('--out-dir', default='./pki',
                          help='Output directory (default: ./pki)')
    ca_inter.add_argument('--validity-days', type=int, default=1825,
                          help='Validity period in days (default: 1825)')
    ca_inter.add_argument('--pathlen', type=int, default=0,
                          help='Path length constraint (default: 0)')
    ca_inter.add_argument('--log-file',
                          help='Optional log file (default: stderr)')

    # Sprint 2: ca issue-cert
    ca_issue = subparsers.add_parser('issue-cert',
                                     help='Issue an end-entity certificate')
    ca_issue.add_argument('--ca-cert', required=True,
                          help='Path to CA certificate (PEM)')
    ca_issue.add_argument('--ca-key', required=True,
                          help='Path to CA encrypted private key (PEM)')
    ca_issue.add_argument('--ca-pass-file', required=True,
                          help='File containing passphrase for CA key')
    ca_issue.add_argument('--template', required=True,
                          choices=['server', 'client', 'code_signing'],
                          help='Certificate template')
    ca_issue.add_argument('--subject', required=True,
                          help='Distinguished Name for the certificate')
    ca_issue.add_argument('--san', action='append',
                          help='Subject Alternative Name (format: type:value). Can be repeated.')
    ca_issue.add_argument('--out-dir', default='./pki/certs',
                          help='Output directory (default: ./pki/certs)')
    ca_issue.add_argument('--validity-days', type=int, default=365,
                          help='Validity period in days (default: 365)')
    ca_issue.add_argument('--log-file',
                          help='Optional log file (default: stderr)')

    # Sprint 2: chain validation
    ca_validate = subparsers.add_parser('validate-chain',
                                        help='Validate a certificate chain')
    ca_validate.add_argument('--leaf', required=True,
                             help='Path to leaf certificate (PEM)')
    ca_validate.add_argument('--intermediate', action='append',
                             help='Path to intermediate certificate (PEM). Can be repeated.')
    ca_validate.add_argument('--root', required=True,
                             help='Path to root certificate (PEM)')
    ca_validate.add_argument('--log-file',
                             help='Optional log file (default: stderr)')

    args = parser.parse_args()

    # Set up logging
    log_file = getattr(args, 'log_file', None)
    logger.setup_logger(log_file)
    log = logging.getLogger(__name__)

    # Validate arguments
    try:
        if args.command == 'init':
            validate_args(args)
        elif args.command == 'issue-intermediate':
            validate_intermediate_args(args)
        elif args.command == 'issue-cert':
            validate_issue_args(args)
        elif args.command == 'validate-chain':
            validate_chain_args(args)
    except ValueError as e:
        log.error(f"Validation error: {e}")
        sys.exit(1)

    # Execute command
    try:
        if args.command == 'init':
            ca.init_ca(args)
        elif args.command == 'issue-intermediate':
            ca.issue_intermediate(args)
        elif args.command == 'issue-cert':
            ca.issue_certificate(args)
        elif args.command == 'validate-chain':
            do_chain_validation(args)
    except Exception as e:
        log.exception("Command failed")
        sys.exit(1)


def validate_args(args):
    """Validate arguments for init command."""
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384 (P-384)")

    passphrase_file = Path(args.passphrase_file)
    if not passphrase_file.exists():
        raise ValueError(f"Passphrase file does not exist: {args.passphrase_file}")
    if not os.access(passphrase_file, os.R_OK):
        raise ValueError(f"Passphrase file not readable: {args.passphrase_file}")

    out_dir = Path(args.out_dir)
    # Проверяем, что путь не указывает на существующий файл
    if out_dir.exists() and out_dir.is_file():
        raise ValueError(f"Output path exists and is a file, not a directory: {args.out_dir}")

    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")

def validate_intermediate_args(args):
    """Validate arguments for issue-intermediate."""
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096 for Intermediate CA")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384 for Intermediate CA")

    for path_attr in ['root_cert', 'root_key', 'root_pass_file', 'passphrase_file']:
        path = Path(getattr(args, path_attr))
        if not path.exists():
            raise ValueError(f"File not found: {path}")

    if args.pathlen < 0:
        raise ValueError("Path length cannot be negative")

    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def validate_issue_args(args):
    """Validate arguments for issue-cert."""
    for path_attr in ['ca_cert', 'ca_key', 'ca_pass_file']:
        path = Path(getattr(args, path_attr))
        if not path.exists():
            raise ValueError(f"File not found: {path}")

    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def validate_chain_args(args):
    """Validate arguments for validate-chain."""
    leaf = Path(args.leaf)
    if not leaf.exists():
        raise ValueError(f"Leaf certificate not found: {leaf}")

    root = Path(args.root)
    if not root.exists():
        raise ValueError(f"Root certificate not found: {root}")

    if args.intermediate:
        for int_path in args.intermediate:
            int_path = Path(int_path)
            if not int_path.exists():
                raise ValueError(f"Intermediate certificate not found: {int_path}")


def do_chain_validation(args):
    """Execute chain validation command."""
    from cryptography import x509
    from . import chain

    leaf_cert = x509.load_pem_x509_certificate(Path(args.leaf).read_bytes())
    root_cert = x509.load_pem_x509_certificate(Path(args.root).read_bytes())

    intermediates = []
    if args.intermediate:
        for int_path in args.intermediate:
            cert = x509.load_pem_x509_certificate(Path(int_path).read_bytes())
            intermediates.append(cert)

    if chain.validate_chain(leaf_cert, intermediates, root_cert):
        print("Chain validation: SUCCESS")
        chain.print_chain_info(leaf_cert, intermediates, root_cert)
    else:
        print("Chain validation: FAILED")
        sys.exit(1)


if __name__ == '__main__':
    main()