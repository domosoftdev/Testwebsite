# -*- coding: utf-8 -*-

import io
import unittest
from unittest.mock import patch, MagicMock
from contextlib import redirect_stdout

from ssl_tls_analyzer import analyze_host, ServerScanStatusEnum, ScanCommandAttemptStatusEnum

class TestSslTlsAnalyzer(unittest.TestCase):

    @patch('ssl_tls_analyzer.Scanner')
    def test_analyze_host_successful_scan(self, MockScanner):
        # Arrange
        mock_scanner_instance = MockScanner.return_value
        mock_result = MagicMock()

        # We need to simulate the nested structure of the result objects
        mock_result.scan_status = ServerScanStatusEnum.COMPLETED

        mock_result.server_location.hostname = 'google.com'

        # Mock certificate validation
        path_validation_result = MagicMock()
        path_validation_result.was_validation_successful = True

        deployment_result = MagicMock()
        deployment_result.path_validation_results = [path_validation_result]

        certinfo_result = MagicMock()
        certinfo_result.certificate_deployments = [deployment_result]

        certinfo_attempt = MagicMock()
        certinfo_attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
        certinfo_attempt.result = certinfo_result

        # Mock protocol scan results
        def create_protocol_attempt(supported):
            attempt = MagicMock()
            attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
            attempt.result = MagicMock()
            attempt.result.accepted_cipher_suites = ['some_cipher'] if supported else []
            return attempt

        scan_result = MagicMock()
        scan_result.certificate_info = certinfo_attempt
        scan_result.ssl_2_0_cipher_suites = create_protocol_attempt(False)
        scan_result.ssl_3_0_cipher_suites = create_protocol_attempt(False)
        scan_result.tls_1_0_cipher_suites = create_protocol_attempt(True)
        scan_result.tls_1_1_cipher_suites = create_protocol_attempt(True)
        scan_result.tls_1_2_cipher_suites = create_protocol_attempt(True)
        scan_result.tls_1_3_cipher_suites = create_protocol_attempt(True)

        mock_result.scan_result = scan_result

        mock_scanner_instance.get_results.return_value = [mock_result]

        # Act
        f = io.StringIO()
        with redirect_stdout(f):
            analyze_host('google.com', lang='en')
        output = f.getvalue()

        # Assert
        self.assertIn("Scanning host: google.com", output)
        self.assertIn("The certificate chain is VALID.", output)
        self.assertIn("SSL 2.0 : Not Supported", output)
        self.assertIn("TLS 1.0 : Supported [WEAK]", output)
        self.assertIn("TLS 1.2 : Supported", output)


if __name__ == '__main__':
    unittest.main()
