"""
Module for comprehensive SSL/TLS analysis of a given host.

Combines certificate details fetching with active protocol scanning
to provide a robust security overview. Can be used as a library or a standalone CLI tool.
"""

import socket
import ssl
import warnings
from datetime import datetime, timezone
from OpenSSL import crypto
import argparse
import sys

def get_certificate_details(hostname, port=443):
    """
    Fetches and parses the SSL/TLS certificate from a given host.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert_der = sslsock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                subject = {comp[0].decode(): comp[1].decode() for comp in x509.get_subject().get_components()}
                issuer = {comp[0].decode(): comp[1].decode() for comp in x509.get_issuer().get_components()}
                not_after_str = x509.get_notAfter().decode('ascii')
                expiration_date = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')
                is_expired = expiration_date < datetime.now(timezone.utc).replace(tzinfo=None)
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": x509.get_serial_number(),
                    "version": x509.get_version(),
                    "expiration_date": expiration_date.isoformat(),
                    "is_expired": is_expired,
                    "signature_algorithm": x509.get_signature_algorithm().decode('utf-8'),
                }
    except Exception as e:
        return {"error": str(e)}

def scan_supported_protocols(hostname, port=443):
    """
    Scans a host to determine which SSL/TLS protocols are supported.
    Uses deprecated constants for broad compatibility but suppresses warnings.
    """
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    supported_protocols = {}
    protocols_to_test = {
        "TLSv1": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
    }
    for name, version_const in protocols_to_test.items():
        context = ssl.SSLContext(version_const)
        try:
            with socket.create_connection((hostname, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    supported_protocols[name] = True
        except (ssl.SSLError, socket.timeout, ConnectionResetError):
            supported_protocols[name] = False
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                if sslsock.version() == "TLSv1.3":
                    supported_protocols["TLSv1.3"] = True
                else:
                    if "TLSv1.3" not in supported_protocols:
                         supported_protocols["TLSv1.3"] = False
    except (ssl.SSLError, socket.timeout, ConnectionResetError):
        supported_protocols["TLSv1.3"] = False
    weak_protocols_found = [
        name for name, is_supported in supported_protocols.items()
        if is_supported and name in ["TLSv1", "TLSv1.1"]
    ]
    return {
        "protocols": supported_protocols,
        "weak_protocols_found": weak_protocols_found
    }

def analyze_host(hostname, port=443):
    """
    Orchestrates the analysis of a host, combining certificate details and protocol scan.
    This is the main entry point for using the module as a library.
    """
    cert_details = get_certificate_details(hostname, port)
    protocol_info = scan_supported_protocols(hostname, port)

    return {
        "certificate_details": cert_details,
        "protocol_analysis": protocol_info
    }

def main():
    """
    Handles CLI execution, argument parsing, and result printing.
    """
    parser = argparse.ArgumentParser(description="Analyze SSL/TLS configuration for a given host.")
    parser.add_argument("hostname", help="The hostname to analyze (e.g., google.com)")
    args = parser.parse_args()

    results = analyze_host(args.hostname)

    # Print Certificate Details
    print(f"--- Analyzing certificate for: {args.hostname} ---")
    details = results["certificate_details"]
    if "error" in details:
        print(f"An error occurred while fetching the certificate: {details['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"  Subject: {details['subject'].get('CN')}")
    print(f"  Issuer: {details['issuer'].get('CN')}")
    print(f"  Expires on: {details['expiration_date']}")
    print(f"  Expired: {'Yes' if details['is_expired'] else 'No'}")

    # Print Protocol Analysis
    print(f"\n--- Scanning supported protocols for: {args.hostname} ---")
    protocol_info = results["protocol_analysis"]
    if not any(protocol_info["protocols"].values()):
        print("Could not determine supported protocols. Host may be down or blocking scans.", file=sys.stderr)
        sys.exit(1)

    for protocol, is_supported in sorted(protocol_info["protocols"].items()):
        status = "Supported" if is_supported else "Not Supported"
        print(f"  {protocol}: {status}")

    if protocol_info["weak_protocols_found"]:
        print(f"\n[!] WARNING: Weak protocols found: {', '.join(protocol_info['weak_protocols_found'])}")
    else:
        print("\n[+] No weak protocols detected.")

if __name__ == "__main__":
    main()
