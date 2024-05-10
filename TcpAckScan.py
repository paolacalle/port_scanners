import warnings
warnings.filterwarnings("ignore")

import time
import argparse
from scapy.all import IP, TCP, sr1,  ICMP, send
import generalSelection as gs
import sys

"""
TCP ACK Scanning: This scan only sends the ACK flag. "When scanning 
unfiltered systems, open and closed ports will both return a RST packet.
Nmap then labels them as unfiltered, meaning that they are reachable by the ACK 
packet, but whether they are open or closed is undetermined. Ports that don't
respond, or send certain ICMP error messages back, are labeled filtered."
Resource: https://nmap.org/book/scan-methods-ack-scan.html
"""

def scan(ip_dst, ports, timeout = .1):
    print(f"Starting TCP ACK Scan at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
    initial = time.time()
    results = {}

    for current_port in ports:
        sys.stdout.write(".")  # dot for each port being scanned
        sys.stdout.flush()  # ensure the dot is displayed immediately
        ack_pack = IP(dst = ip_dst) / TCP(dport=current_port, flags="A")
        response = sr1(ack_pack, timeout=timeout, verbose=0)  # Adjusted timeout

        if response is None:
            response = sr1(ack_pack, timeout=.2, verbose=0)  # Retransmission with longer timeout
            
            if response is None:
                results[current_port] = "filtered"
                continue

        if response.haslayer(TCP) and (response[TCP].flags == 'R'):  # RST flag
            results[current_port] = "unfiltered"
            continue
            
        if response.haslayer(ICMP):
            # specific ICMP messages can also indicate a filtered port
            icmp = response.getlayer(ICMP)
            
            if int(icmp.type) == 3 and int(icmp.code) in [1, 2, 3, 9, 10, 13]:
                results[current_port] = "filtered"
                
            else:
                results[current_port] = "ICMP Issue"
                
        else:
            results[current_port] = "unknown Issue"

    print("\n") 
    finished = time.time()
    elapsed = finished - initial  # end time
    return results, elapsed



def main(order, port, target):
  ports = gs.run_checks(order, port, target)
  results, elapsed = scan(target, ports)
  gs.print_scan_results(target, results, elapsed)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='Scan for open ports using Tcp ACK.')

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