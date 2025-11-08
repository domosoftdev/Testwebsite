import unittest
from unittest.mock import patch, MagicMock
import ssl
import socket
from datetime import datetime
from ssl_tls_analyzer import get_certificate_details, scan_supported_protocols, analyze_host

class TestSSLAnalyzer(unittest.TestCase):

    @patch('ssl_tls_analyzer.crypto.load_certificate')
    @patch('ssl_tls_analyzer.ssl.create_default_context')
    @patch('ssl_tls_analyzer.socket.create_connection')
    def test_get_certificate_details_success(self, mock_create_connection, mock_create_context, mock_load_cert):
        mock_sslsock = MagicMock()
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsock
        mock_create_context.return_value = mock_context
        mock_sock = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        mock_x509 = MagicMock()
        mock_x509.get_subject().get_components.return_value = [(b'CN', b'test.com')]
        mock_x509.get_issuer().get_components.return_value = [(b'CN', b'Test CA')]
        mock_x509.get_notAfter.return_value = b'20990101000000Z'
        mock_x509.get_signature_algorithm.return_value = b'sha256WithRSAEncryption'
        mock_sslsock.getpeercert.return_value = b'der_encoded_cert'
        mock_load_cert.return_value = mock_x509

        details = get_certificate_details('test.com')

        self.assertNotIn('error', details)
        self.assertEqual(details['subject']['CN'], 'test.com')
        self.assertFalse(details['is_expired'])

    @patch('ssl_tls_analyzer.socket.create_connection', side_effect=socket.gaierror("Test error"))
    def test_get_certificate_details_failure(self, mock_create_connection):
        details = get_certificate_details('invalid.hostname')
        self.assertIn('error', details)
        self.assertEqual(details['error'], "Test error")

    @patch('ssl_tls_analyzer.socket.create_connection')
    @patch('ssl_tls_analyzer.ssl.SSLContext')
    @patch('ssl_tls_analyzer.ssl.create_default_context')
    def test_scan_supported_protocols_logic(self, mock_default_context, mock_ssl_context, mock_create_connection):
        def ssl_context_side_effect(protocol):
            mock_context = MagicMock()
            if protocol in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1]:
                mock_context.wrap_socket.side_effect = ssl.SSLError("Unsupported protocol")
            else:
                mock_sslsock = MagicMock()
                mock_sslsock.version.return_value = "TLSv1.2"
                mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsock
            return mock_context
        mock_ssl_context.side_effect = ssl_context_side_effect
        mock_default_sslsock = MagicMock()
        mock_default_sslsock.version.return_value = "TLSv1.3"
        mock_default_context.return_value.wrap_socket.return_value.__enter__.return_value = mock_default_sslsock

        results = scan_supported_protocols('test.com')

        self.assertFalse(results['protocols']['TLSv1'])
        self.assertFalse(results['protocols']['TLSv1.1'])
        self.assertTrue(results['protocols']['TLSv1.2'])
        self.assertTrue(results['protocols']['TLSv1.3'])
        self.assertEqual(len(results['weak_protocols_found']), 0)

    @patch('ssl_tls_analyzer.get_certificate_details')
    @patch('ssl_tls_analyzer.scan_supported_protocols')
    def test_analyze_host_integration(self, mock_scan_protocols, mock_get_details):
        # --- Arrange ---
        # Define the mock return values for the two functions
        mock_get_details.return_value = {"subject": {"CN": "test.com"}, "is_expired": False}
        mock_scan_protocols.return_value = {"protocols": {"TLSv1.3": True}, "weak_protocols_found": []}

        # --- Act ---
        result = analyze_host('test.com')

        # --- Assert ---
        # Check that the functions were called
        mock_get_details.assert_called_once_with('test.com', 443)
        mock_scan_protocols.assert_called_once_with('test.com', 443)

        # Check that the results are aggregated correctly
        self.assertIn('certificate_details', result)
        self.assertIn('protocol_analysis', result)
        self.assertEqual(result['certificate_details']['subject']['CN'], 'test.com')
        self.assertTrue(result['protocol_analysis']['protocols']['TLSv1.3'])

if __name__ == '__main__':
    unittest.main()
