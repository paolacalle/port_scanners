import time
import argparse
from scapy.all import IP, UDP, sr1,  ICMP, send
import generalSelection as gs
import sys

def scan(ip_dst, ports, timeout = .1):
  print(f"Starting UDP Scan at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
  results = {}
  start_time = time.time()

  for port in ports:
    sys.stdout.write(".")  # dot for each port being scanned
    sys.stdout.flush()  # ensure the dot is displayed immediately
    pkt = IP(dst = ip_dst) / UDP(dport = port)
    response = sr1(pkt, timeout = timeout, verbose=0)

    if response is None:
      # no response after timeout, re-check to confirm it's filtered or open
      response = sr1(pkt, timeout=timeout, verbose=0)
      
      if response is None:
        results[port] = "open|filtered"
      continue
    
    if response.haslayer(UDP):
        results[port] = "open"
        
    elif response.haslayer(ICMP):
        # specific ICMP messages can also indicate a filtered port
        if int(response[ICMP].type) == 3:
          if int(response[ICMP].code) == 3:
            results[port] = "closed"
          elif int(response[ICMP].code) in [1, 2, 9, 10, 13]:
            results[port] = "filtered"
          else: 
            results[port] = "ICMP Issue"
    else:
        results[port] = "unknown Issue"
        
  print("\n")
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
