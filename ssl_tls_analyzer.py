"""
Module for comprehensive SSL/TLS analysis of a given host.

Combines certificate details fetching and protocol scanning
to provide a robust security overview. Can be used as a library or a standalone CLI tool.
"""
import argparse
import sys
from datetime import datetime

import pytz
from cryptography.x509.oid import NameOID
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner.models import ScanCommand, ServerScanRequest
from sslyze.scanner.scanner import Scanner
from sslyze.server_connectivity import ServerNetworkLocation

def analyze_host(hostname, port=443):
    """
    Orchestrates the analysis of a host, combining certificate details and protocol scan.
    """
    try:
        server_location = ServerNetworkLocation(hostname, port)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        result = next(scanner.get_results())

        if isinstance(result, ConnectionToServerFailed):
            return {
                "certificate_details": {"error": f"Could not connect to {hostname}: {result.error_message}", "trust_chain_valid": False},
                "protocol_analysis": {"error": "Connection failed."}
            }

        # Process certificate info
        cert_info_result = result.scan_result.certificate_info.result
        deployment = cert_info_result.certificate_deployments[0]
        leaf_cert = deployment.received_certificate_chain[0]
        trust_validation_result = deployment.path_validation_results[0]
        subject = {attr.oid._name: attr.value for attr in leaf_cert.subject}
        issuer = {attr.oid._name: attr.value for attr in leaf_cert.issuer}
        is_expired = datetime.now(pytz.utc) > leaf_cert.not_valid_after_utc

        cert_details = {
            "subject": subject,
            "issuer": issuer,
            "expiration_date": leaf_cert.not_valid_after_utc.isoformat(),
            "is_expired": is_expired,
            "trust_chain_valid": trust_validation_result.was_validation_successful,
            "validation_error": None if trust_validation_result.was_validation_successful else trust_validation_result.validation_error,
        }

        # Process protocol info
        supported_protocols = {
            "SSLv2": result.scan_result.ssl_2_0_cipher_suites.result is not None,
            "SSLv3": result.scan_result.ssl_3_0_cipher_suites.result is not None,
            "TLSv1": result.scan_result.tls_1_0_cipher_suites.result is not None,
            "TLSv1.1": result.scan_result.tls_1_1_cipher_suites.result is not None,
            "TLSv1.2": result.scan_result.tls_1_2_cipher_suites.result is not None,
            "TLSv1.3": result.scan_result.tls_1_3_cipher_suites.result is not None,
        }
        weak_protocols_found = [
            name for name, is_supported in supported_protocols.items()
            if is_supported and name in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        ]
        protocol_analysis = {
            "protocols": supported_protocols,
            "weak_protocols_found": weak_protocols_found
        }

        return {
            "certificate_details": cert_details,
            "protocol_analysis": protocol_analysis
        }

    except Exception as e:
        return {
            "certificate_details": {"error": f"An unexpected error occurred: {str(e)}", "trust_chain_valid": False},
            "protocol_analysis": {"error": str(e)}
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

    if details and details.get("trust_chain_valid"):
        print("  Trust Chain: Valid")
        print(f"  Subject CN: {details['subject'].get('common_name')}")
        print(f"  Issuer CN: {details['issuer'].get('common_name')}")
        print(f"  Expires on: {details['expiration_date']}")
        print(f"  Expired: {'Yes' if details['is_expired'] else 'No'}")
    elif details:
        print("  Trust Chain: INVALID")
        if "error" in details:
            print(f"  Error: {details['error']}", file=sys.stderr)
        if "validation_error" in details and details["validation_error"]:
             print(f"  Validation Reason: {details['validation_error']}", file=sys.stderr)

    # Print Protocol Analysis
    print(f"\n--- Scanning supported protocols for: {args.hostname} ---")
    protocol_info = results["protocol_analysis"]
    if "error" in protocol_info:
        print(f"Could not scan protocols: {protocol_info['error']}", file=sys.stderr)
    elif not any(protocol_info["protocols"].values()):
        print("No supported protocols found.", file=sys.stderr)
    else:
        for protocol, is_supported in sorted(protocol_info["protocols"].items()):
            status = "Supported" if is_supported else "Not Supported"
            print(f"  {protocol}: {status}")

        if protocol_info["weak_protocols_found"]:
            print(f"\n[!] WARNING: Weak protocols found: {', '.join(protocol_info['weak_protocols_found'])}")
        else:
            print("\n[+] No weak protocols detected.")

if __name__ == "__main__":
    main()
