# -*- coding: utf-8 -*-

import argparse
from sslyze import (
    Scanner,
    ServerScanRequest,
    ScanCommand,
    ServerHostnameCouldNotBeResolved,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerNetworkLocation,
)

from messages import MESSAGES

def analyze_host(hostname, lang='fr'):
    """
    Analyzes the SSL/TLS configuration of a given host.
    """
    print(MESSAGES[lang]['scanning'].format(hostname=hostname))

    try:
        scan_requests = [ServerScanRequest(server_location=ServerNetworkLocation(hostname=hostname))]
        scanner = Scanner()
        scanner.queue_scans(scan_requests)

        # Retrieve the result
        for result in scanner.get_results():
            if result.scan_status != ServerScanStatusEnum.COMPLETED:
                print(MESSAGES[lang]['connectivity_error'].format(hostname=result.server_location.hostname, error=result.connectivity_error_trace))
                continue

            scan_result = result.scan_result

            # Certificate chain validation
            print(MESSAGES[lang]['certificate_chain'])
            certinfo_attempt = scan_result.certificate_info
            if certinfo_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                certinfo_result = certinfo_attempt.result
                # We will assume only one certificate deployment
                deployment_result = certinfo_result.certificate_deployments[0]
                path_validation_result = deployment_result.path_validation_results[0] # Using the first trust store

                if path_validation_result.was_validation_successful:
                    print(MESSAGES[lang]['valid_chain'])
                else:
                    # The exact error and unverified issuer are now within validation_error
                    # For simplicity, we'll just show a generic message
                    print(MESSAGES[lang]['partially_valid_chain'].format(unverified_issuer=path_validation_result.validation_error))
            else:
                print(f"  Certificate info scan failed: {certinfo_attempt.error_reason}")

            # Protocol scan
            print(MESSAGES[lang]['protocol_scan'])
            protocols = {
                'SSL 2.0': (scan_result.ssl_2_0_cipher_suites, True),
                'SSL 3.0': (scan_result.ssl_3_0_cipher_suites, True),
                'TLS 1.0': (scan_result.tls_1_0_cipher_suites, True),
                'TLS 1.1': (scan_result.tls_1_1_cipher_suites, True),
                'TLS 1.2': (scan_result.tls_1_2_cipher_suites, False),
                'TLS 1.3': (scan_result.tls_1_3_cipher_suites, False),
            }

            for protocol, (attempt, is_weak) in protocols.items():
                if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    supported = bool(attempt.result.accepted_cipher_suites)
                    status = MESSAGES[lang]['supported'] if supported else MESSAGES[lang]['not_supported']
                    weak_tag = MESSAGES[lang]['weak'] if supported and is_weak else ''
                    print(status.format(protocol=protocol) + weak_tag)
                else:
                     print(f"  {protocol} scan failed: {attempt.error_reason}")


    except ServerHostnameCouldNotBeResolved as e:
        print(MESSAGES[lang]['scan_error'].format(error=e.error_message))

def main():
    """
    Main function for the CLI.
    """
    parser = argparse.ArgumentParser(description="Analyse la configuration SSL/TLS d'un hôte.")
    parser.add_argument("hostname", help="Le nom d'hôte à analyser.")
    parser.add_argument("--lang", choices=['en', 'fr'], default='fr', help="La langue de sortie.")
    args = parser.parse_args()

    analyze_host(args.hostname, args.lang)

if __name__ == "__main__":
    main()
