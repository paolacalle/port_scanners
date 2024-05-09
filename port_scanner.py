import TcpSynScan as syn
import TcpConnectScan as connect
import UdpScan as udp
import XmasScan as xmas
import TcpAckScan as ack 
import argparse
import generalSelection as gs


def main(mode, order, port, target):
  """
    Directs the port scanning based on the chosen mode and options.

    :param mode: The scanning mode (syn, connect, udp)
    :param order: The order to scan the ports (ordered, random)
    :param port: The type of ports to scan (all, well-known)
    :param target: The target IP address or hostname
  """

  gs.check_hostname_or_ip_address(target)

  scanner = {"syn": syn.scan, "ack": ack.scan, "connect": connect.scan, "udp": udp.scan, "xmas": xmas.scan}

  scan_function = scanner.get(mode)
  ports = gs.runChecks(order, port, target)

  if scan_function:
    results, elapsed =scan_function(target, ports)
    gs.print_scan_results(target, results, elapsed)
  else:
    print(f"Error: Unsupported scanning mode '{mode}'. "
      "Choose from 'syn', 'ack', 'connect', 'xmas' or 'udp'.")

if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='Scan for open ports using different methods.')

  parser.add_argument('-m',
                      '--mode',
                      type=str,
                      choices=['syn', 'ack', 'connect', 'udp', 'xmas'],
                      default='connect',
                      required=True,
                      help='Scanner mode [syn, ack, connect, udp, xmas]')

  parser.add_argument(
      '-o',
      '--order',
      type=str,
      choices=['ordered', 'random'],
      default='random',
      help='Specify the order of port scanning [ordered, random]')

  parser.add_argument('-p',
                      '--port',
                      type=str,
                      choices=['all', 'well-known'],
                      default='all',
                      help='Type of ports to scan [all, well-known]')

  parser.add_argument('target', type=str, help='Target IP address or hostname')

  args = parser.parse_args()

  main(args.mode, args.order, args.port, args.target)
