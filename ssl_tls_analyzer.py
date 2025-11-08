"""
Module for comprehensive SSL/TLS analysis of a given host.
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
from messages import MESSAGES

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
                "certificate_details": {"error": "Connection failed", "trust_chain_valid": False, "is_connectivity_error": True},
                "protocol_analysis": {"error": "Connection failed."}
            }

        # Process certificate info
        cert_info = result.scan_result.certificate_info
        if cert_info.status != 'COMPLETED':
             return {
                "certificate_details": {"error": "Certificate scan failed", "trust_chain_valid": False},
                "protocol_analysis": {"error": "Certificate scan failed."}
            }

        cert_info_result = cert_info.result
        deployment = cert_info_result.certificate_deployments[0]
        leaf_cert = deployment.received_certificate_chain[0]
        trust_validation_result = deployment.path_validation_results[0]

        subject_attributes = {attr.oid: attr.value for attr in leaf_cert.subject}
        issuer_attributes = {attr.oid: attr.value for attr in leaf_cert.issuer}

        is_expired = datetime.now(pytz.utc) > leaf_cert.not_valid_after_utc

        cert_details = {
            "subject": subject_attributes,
            "issuer": issuer_attributes,
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
            "certificate_details": {"error": str(e), "trust_chain_valid": False},
            "protocol_analysis": {"error": str(e)}
        }

def main():
    """
    Handles CLI execution, argument parsing, and result printing.
    """
    parser = argparse.ArgumentParser(description="Analyze SSL/TLS configuration for a given host.")
    parser.add_argument("hostname", help="The hostname to analyze (e.g., google.com)")
    parser.add_argument("--lang", help="Language for the output (en/fr)", default="fr", choices=['en', 'fr'])
    args = parser.parse_args()

    lang = args.lang
    msg = MESSAGES[lang]

    results = analyze_host(args.hostname)

    print(msg['analyzing_cert'].format(hostname=args.hostname))
    details = results["certificate_details"]

    if details and details.get("trust_chain_valid"):
        print(f"{msg['trust_chain']}: {msg['valid']}")
        print(f"{msg['subject_cn']}: {details['subject'].get(NameOID.COMMON_NAME)}")
        print(f"{msg['issuer_cn']}: {details['issuer'].get(NameOID.COMMON_NAME)}")
        print(f"{msg['expires_on']}: {details['expiration_date']}")
        print(f"{msg['expired']}: {msg['yes'] if details['is_expired'] else msg['no']}")
    elif details:
        is_connectivity_error = details.get("is_connectivity_error", False)
        if not is_connectivity_error and details.get("subject"):
            print(f"{msg['trust_chain']}: {msg['partially_valid']}")
            print(f"{msg['subject_cn']}: {details['subject'].get(NameOID.COMMON_NAME)}")
            print(f"{msg['unverified_issuer']}: {details['issuer'].get(NameOID.COMMON_NAME)}")
            if details['validation_error']:
                print(f"{msg['validation_reason']}: {details['validation_error']}", file=sys.stderr)
        else:
            print(f"{msg['trust_chain']}: {msg['invalid']}")
            if "error" in details:
                print(f"{msg['error']}: {details['error']}", file=sys.stderr)

    print(msg['scanning_protocols'].format(hostname=args.hostname))
    protocol_info = results["protocol_analysis"]
    if "error" in protocol_info:
        print(f"{msg['could_not_scan_protocols'].format(error=protocol_info['error'])}", file=sys.stderr)
    elif "protocols" in protocol_info and not any(protocol_info["protocols"].values()):
        print(f"{msg['no_supported_protocols']}", file=sys.stderr)
    elif "protocols" in protocol_info:
        for protocol, is_supported in sorted(protocol_info["protocols"].items()):
            status = msg['supported'] if is_supported else msg['not_supported']
            print(f"  {protocol}: {status}")

        if protocol_info["weak_protocols_found"]:
            print(msg['weak_protocols_warning'].format(protocols=', '.join(protocol_info['weak_protocols_found'])))
        else:
            print(msg['no_weak_protocols'])

if __name__ == "__main__":
    main()
