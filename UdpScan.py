import socket
import argparse
import generalSelection as gs
import scapy.all as scapy
import time


def scan(ip, ports):
  results = {}
  ip_layer = scapy.IP(dst=ip)
  start_time = time.time()

  for port in ports:

    packet = ip_layer / scapy.UDP(dport=port)

    reply = scapy.sr1(packet, timeout=.25, verbose=0)


    if reply is None:
      results[port]="Filtered"
    elif reply.haslayer(scapy.ICMP):
      icmp = reply.getlayer(scapy.ICMP)
      if icmp.type == 3 and icmp.code == 3:
        results[port]="closed"
        print("closed")
      elif icmp.type == 3 and icmp.code in [1, 2, 9, 10, 13]:
        results[port]="filtered"

    else:
        results[port]="Success"
  elapsed = time.time() - start_time  

  return results, elapsed


def main(order, port, target):
  ports = gs.run_checks(order, port, target)
  results, elapsed = scan(target, ports)
  gs.print_scan_results(target, results, elapsed )


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='Scan for open ports using UDP Scan.')

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

  main(args.order, args.port, args.target)
