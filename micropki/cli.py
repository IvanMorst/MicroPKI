#!/usr/bin/env python3
import argparse
import sys
import os
import logging
from pathlib import Path

from . import logger
from . import ca

def main():
    parser = argparse.ArgumentParser(
        description="MicroPKI - Minimal Public Key Infrastructure",
        prog="micropki"
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # ca init subcommand
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

    args = parser.parse_args()

    # Set up logging early
    logger.setup_logger(args.log_file)
    log = logging.getLogger(__name__)

    # Validation
    try:
        _validate_args(args)
    except ValueError as e:
        log.error(f"Validation error: {e}")
        sys.exit(1)

    # Execute command
    try:
        if args.command == 'init':
            ca.init_ca(args)
    except Exception as e:
        log.exception("Command failed")
        sys.exit(1)

def _validate_args(args):
    """Perform input validation."""
    if args.command != 'init':
        return  # no other commands yet

    # Key type and size consistency
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384 (P-384)")

    # Passphrase file existence and readability (checked later)
    passphrase_file = Path(args.passphrase_file)
    if not passphrase_file.exists():
        raise ValueError(f"Passphrase file does not exist: {args.passphrase_file}")
    if not os.access(passphrase_file, os.R_OK):
        raise ValueError(f"Passphrase file not readable: {args.passphrase_file}")

    # Out-dir writability (will be created if needed, but check if exists and not writable)
    out_dir = Path(args.out_dir)
    if out_dir.exists() and not os.access(out_dir, os.W_OK):
        raise ValueError(f"Output directory not writable: {args.out_dir}")

    # Validity days positive
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")

if __name__ == '__main__':
    main()