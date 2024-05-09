import unittest
import sys
from unittest.mock import patch
import socket

sys.path.append('../')
import generalSelection as gs


class TestGeneralSelection(unittest.TestCase):

  # Test valid ipv4 or ipv6 address
  def test_valid_ipv4(self):
    ip = '192.168.1.1'
    self.assertTrue(gs.check_ip(ip))

  def test_valid_ipv6(self):
    ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    self.assertTrue(gs.check_ip(ip))

  def test_invalid_ip(self):
    ip = 'redpanda'
    self.assertFalse(gs.check_ip(ip))

  # Test hostname conversions
  @patch('socket.gethostbyname')
  def test_check_hostname_or_ip_address_valid(self, mock_gethostbyname):
    """Test resolving a valid hostname."""
    mock_gethostbyname.return_value = '192.168.1.1'
    self.assertEqual(gs.check_hostname_or_ip_address('redpandasss.com'),
                     '192.168.1.1')
    mock_gethostbyname.assert_called_once_with('redpandasss.com')

  @patch('socket.gethostbyname')
  def test_check_hostname_or_ip_address_invalid(self, mock_gethostbyname):
    """Test resolving an invalid hostname."""
    mock_gethostbyname.side_effect = socket.error
    self.assertEqual(gs.check_hostname_or_ip_address('not_real'), '127.0.0.1')

  @patch('subprocess.run')
  def test_reachable_test(self, mock_run):
    """Test the reachable_test function."""
    mock_run.return_value.returncode = 0
    self.assertTrue(gs.reachable_test('192.168.1.1'))

    mock_run.return_value.returncode = 1
    self.assertFalse(gs.reachable_test('192.168.1.1'))

  def test_get_ports_known_order(self):
    """Test getting ports in known order."""
    ports = gs.get_ports('ordered', 'known')
    self.assertEqual(ports[0], 0)
    self.assertEqual(ports[-1], 1023)

  def test_get_ports_random_order(self):
    """Test getting ports in random order - mainly checks type and count."""
    ports = gs.get_ports('random', 'all')
    self.assertEqual(len(ports), 65536)


# python -m unittest tests.test_generalSelection
if __name__ == '__main__':
  unittest.main()
