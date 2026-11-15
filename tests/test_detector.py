import unittest
from types import SimpleNamespace
from scapy.all import TCP
from cups_detector import Detector

class CorrelationTests(unittest.TestCase):
    def detector(self, trusted=False):
        return Detector(SimpleNamespace(
            trusted_advertiser={'192.0.2.1'} if trusted else set(),
            trusted_printer={'192.0.2.3'}, pcap=True,
            ipp_ports={631, 8631}, threshold=3, window=10, callback_window=30))

    def advertise(self, d, host='192.0.2.3'):
        d.handle_browse(100, '192.0.2.1', '192.0.2.2',
            f'0 3 http://{host}:8631/printers/Test "Lab" "Test" "Model"\n'.encode())

    def connect(self, d, ts=101, src='192.0.2.2'):
        d.handle_tcp(ts, src, '192.0.2.3', TCP(sport=45000, dport=8631, flags='S'), b'')
        return [a['category'] for a in d.alerts]

    def test_untrusted_advertiser_callback_to_trusted_printer(self):
        d=self.detector(); self.advertise(d)
        self.assertIn('advertised_printer_callback', self.connect(d))

    def test_fully_trusted_callback(self):
        d=self.detector(True); self.advertise(d)
        self.assertEqual(self.connect(d), [])

    def test_expired_advertisement(self):
        d=self.detector(); self.advertise(d)
        self.assertNotIn('advertised_printer_callback', self.connect(d, ts=131))

    def test_wrong_recipient(self):
        d=self.detector(); self.advertise(d)
        self.assertNotIn('advertised_printer_callback', self.connect(d, src='192.0.2.99'))

    def test_malformed_burst(self):
        d=self.detector()
        for ts in (100,101,102): d.handle_browse(ts,'192.0.2.1','192.0.2.2',b'invalid')
        categories=[a['category'] for a in d.alerts]
        self.assertEqual(categories.count('malformed_discovery'),3)
        self.assertEqual(categories.count('repeated_discovery'),1)

    def test_offline_hostname_does_not_use_dns(self):
        from unittest.mock import patch
        d=self.detector(True)
        with patch('cups_detector.socket.gethostbyname', side_effect=AssertionError('DNS used')):
            self.advertise(d, 'historical-printer.invalid')
        self.assertEqual(d.alerts, [])

    def test_response_is_not_request(self):
        d=self.detector()
        d.handle_tcp(100,'192.0.2.3','192.0.2.2',TCP(sport=8631,dport=45000,flags='PA'),
                     b'HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\n\r\n')
        self.assertEqual(d.alerts, [])

if __name__ == '__main__': unittest.main()
