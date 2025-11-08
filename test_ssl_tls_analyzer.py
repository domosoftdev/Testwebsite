import unittest
from unittest.mock import patch, MagicMock
from ssl_tls_analyzer import analyze_host
from datetime import datetime
import pytz
from cryptography.x509.oid import NameOID

class TestSSLAnalyzer(unittest.TestCase):

    @patch('ssl_tls_analyzer.Scanner')
    def test_analyze_host_success(self, MockScanner):
        # --- Arrange ---
        mock_scan_result = MagicMock()

        mock_scan_result.scan_result.certificate_info.status = 'COMPLETED'
        mock_scan_result.scan_result.certificate_info.result.certificate_deployments = [MagicMock()]
        deployment = mock_scan_result.scan_result.certificate_info.result.certificate_deployments[0]

        deployment.received_certificate_chain = [MagicMock()]
        leaf_cert = deployment.received_certificate_chain[0]
        leaf_cert.subject = [MagicMock(oid=NameOID.COMMON_NAME, value='test.com')]
        leaf_cert.issuer = [MagicMock(oid=NameOID.COMMON_NAME, value='Test CA')]
        leaf_cert.not_valid_after_utc = datetime(2099, 1, 1, tzinfo=pytz.utc)

        deployment.path_validation_results = [MagicMock()]
        trust_result = deployment.path_validation_results[0]
        trust_result.was_validation_successful = True

        mock_scan_result.scan_result.ssl_2_0_cipher_suites.result = None
        mock_scan_result.scan_result.tls_1_2_cipher_suites.result = MagicMock()
        mock_scan_result.scan_result.tls_1_3_cipher_suites.result = MagicMock()

        mock_scanner_instance = MockScanner.return_value
        mock_scanner_instance.get_results.return_value = iter([mock_scan_result])

        # --- Act ---
        results = analyze_host('test.com')

        # --- Assert ---
        self.assertTrue(results['certificate_details']['trust_chain_valid'])
        self.assertEqual(results['certificate_details']['subject'][NameOID.COMMON_NAME], 'test.com')
        self.assertFalse(results['certificate_details']['is_expired'])

    @patch('ssl_tls_analyzer.Scanner')
    def test_analyze_host_partial_chain(self, MockScanner):
        # --- Arrange ---
        mock_scan_result = MagicMock()

        mock_scan_result.scan_result.certificate_info.status = 'COMPLETED'
        mock_scan_result.scan_result.certificate_info.result.certificate_deployments = [MagicMock()]
        deployment = mock_scan_result.scan_result.certificate_info.result.certificate_deployments[0]

        deployment.received_certificate_chain = [MagicMock()]
        leaf_cert = deployment.received_certificate_chain[0]
        leaf_cert.subject = [MagicMock(oid=NameOID.COMMON_NAME, value='test.com')]
        leaf_cert.issuer = [MagicMock(oid=NameOID.COMMON_NAME, value='Intermediate CA')]
        leaf_cert.not_valid_after_utc = datetime(2099, 1, 1, tzinfo=pytz.utc)

        deployment.path_validation_results = [MagicMock()]
        trust_result = deployment.path_validation_results[0]
        trust_result.was_validation_successful = False
        trust_result.validation_error = "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"

        # Mock protocol info as empty for this test
        mock_scan_result.scan_result.ssl_2_0_cipher_suites.result = None
        mock_scan_result.scan_result.tls_1_2_cipher_suites.result = None
        mock_scan_result.scan_result.tls_1_3_cipher_suites.result = None

        mock_scanner_instance = MockScanner.return_value
        mock_scanner_instance.get_results.return_value = iter([mock_scan_result])

        # --- Act ---
        results = analyze_host('test.com')

        # --- Assert ---
        self.assertFalse(results['certificate_details']['trust_chain_valid'])
        self.assertIn('validation_error', results['certificate_details'])
        self.assertEqual(results['certificate_details']['subject'][NameOID.COMMON_NAME], 'test.com')
        self.assertEqual(results['certificate_details']['issuer'][NameOID.COMMON_NAME], 'Intermediate CA')

    @patch('ssl_tls_analyzer.Scanner')
    def test_analyze_host_connectivity_error(self, MockScanner):
        # --- Arrange ---
        from sslyze.errors import ConnectionToServerFailed
        mock_error = ConnectionToServerFailed("Connection error", "test.com", 443)

        mock_scanner_instance = MockScanner.return_value
        mock_scanner_instance.get_results.return_value = iter([mock_error])

        # --- Act ---
        results = analyze_host('test.com')

        # --- Assert ---
        self.assertFalse(results['certificate_details']['trust_chain_valid'])
        self.assertIn('error', results['certificate_details'])

if __name__ == '__main__':
    unittest.main()
