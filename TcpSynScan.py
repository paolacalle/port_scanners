import time
import argparse
from scapy.all import IP, TCP, sr1,  ICMP, send
import generalSelection as gs
import sys
  
def scan(ip_dst, ports, timeout = .1):
    print(f"Starting TCP SYN Scan at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
    results = {}
    for port in ports:
        sys.stdout.write(".")  # dot for each port being scanned
        sys.stdout.flush()  # ensure the dot is displayed immediately
        pkt = IP(dst = ip_dst) / TCP(dport = port, flags="S")
        response = sr1(pkt, timeout= timeout, verbose=0)
        
        if response is None:
            # no response after timeout, re-check to confirm it's filtered
            response = sr1(pkt, timeout=timeout, verbose=0)
            
            if response is None:
                results[port] = "filtered"
            continue
        
        if response.haslayer(TCP):
            if response[TCP].flags & 0x12:  # SYN/ACK
                results[port] = "open"
                
                # send RST to close the half-open connection
                rst_pkt = IP(dst=ip_dst) / TCP(dport=port, flags="R")
                send(rst_pkt, verbose=0)
                
            elif response[TCP].flags & 0x14:  # RST/ACK
                results[port] = "closed"
        
        elif response.haslayer(ICMP):
          
            # specific ICMP messages can also indicate a filtered port
            if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                results[port] = "filtered"
    print("\n")           
    return results

def main(order, port, target):
    ports = gs.run_checks(order, port, target)
    results, elapsed = scan(target, ports)
    gs.print_scan_results(target, results, elapsed)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan for open ports using TCP SYN.')
    
    parser.add_argument('-o', '--order', type=str, choices=['ordered', 'random'],
                        default='random', help='Order of port scanning [ordered, random]')
    
    parser.add_argument('-p', '--port', type=str, choices=['all', 'well-known'],
                        default='all', help='Type of ports to scan [all, well-known]')
    
    parser.add_argument('target', type=str, help='Target IP address or hostname')
    
    args = parser.parse_args()
    main(args.order, args.port, args.target)