import unittest
import sys
from unittest.mock import patch

sys.path.append('../')
import generalSelection as gs


class TestGeneralSelection(unittest.TestCase):

  # Test port selection based on well-known or all
  def test_get_port_selection_well_known(self):
    self.assertEqual(gs.get_port_selection("well-known"), list(range(0, 1024)))

  def test_get_port_selection_all(self):
    self.assertEqual(gs.get_port_selection("all"), list(range(0, 65535)))

  # Test port list based on ordered or random
  def test_ordered_mode(self):
    ports = [80, 443, 22, 8080]
    mode = 'ordered'
    ordered_ports = gs.get_port_order(ports, mode)
    self.assertEqual(ordered_ports, ports)

  def test_random_mode(self):
    ports = [80, 443, 22, 8080]
    mode = 'random'

    with patch('generalSelection.shuffle') as mock_shuffle:
      mock_shuffle.return_value = [443, 22, 8080, 80]

      shuffled_ports = gs.get_port_order(ports, mode)
      mock_shuffle.assert_called_once_with(ports)
      self.assertEqual(shuffled_ports, [443, 22, 8080, 80])

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
  @patch('generalSelection.check_ip')
  @patch('generalSelection.socket.gethostbyname')
  def test_hostname_conversion(self, mock_gethostbyname, mock_check_ip):
      address = 'redPandasAreAmazing.com'
      mock_check_ip.return_value = False
      mock_gethostbyname.return_value = '93.184.216.34'

      converted_address = gs.check_hostname_or_ip_address(address)
      mock_check_ip.assert_called_once_with(address)
      mock_gethostbyname.assert_called_once_with(address)
      self.assertEqual(converted_address, '93.184.216.34')

  @patch('generalSelection.check_ip')
  @patch('generalSelection.socket.gethostbyname')
  def test_invalid_hostname(self, mock_gethostbyname, mock_check_ip):
      address = 'InvalidPaolaIvalidLarissa'
      mock_check_ip.return_value = False
      mock_gethostbyname.side_effect = Exception("Invalid hostname")

      with patch('builtins.print') as mock_print:
          converted_address = gs.check_hostname_or_ip_address(address)
          mock_check_ip.assert_called_once_with(address)
          mock_gethostbyname.assert_called_once_with(address)
          mock_print.assert_called_once_with("Invalid hostname cannot find ip address... Will be using a loopback addressinstead.. teeheehee... D:")
          self.assertEqual(converted_address, gs.ipaddress.ip_address("127.0.0.1"))


# python -m unittest tests.test_generalSelection
if __name__ == '__main__':
  unittest.main()
