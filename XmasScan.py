    import socket
    import argparse
    import time
    import generalSelection as gs
    import scapy.all as scapy 

    """TCP XMAS Scanning: Sends packets with FIN, URG, and PUSH flags set. This type of scan is used for identifying 
    listening ports on the target system, particularly useful in Unix-like systems."""

    def scan(ip_dst, ports):
        print("Starting TCP XMAS Scan")
        initial = time.time()

        results={}

        ip = scapy.IP(dst=ip_dst)  # Create IP Packet
        for current_port in ports:
            print(current_port)
            xmas_pack = ip/scapy.TCP(dport=current_port, flags="FPU")
            reply = scapy.sr1(xmas_pack, timeout=0.2, verbose=0)

            if reply is None:
                print("Filtered or open")
                results[current_port]= "Filtered or Opened"
            elif reply.haslayer(scapy.TCP):
                if reply[scapy.TCP].flags == "RA":
                    print("Fail (closed)")
                    results[current_port]= "Fail"

                else:
                    print("Filtered or open")
                    results[current_port]= "Filtered or Opened"
            else:
                print("Filtered or open")
                results[current_port]= "Filtered or Opened"

        elapsed = time.time() - initial
        return results, elapsed

    def main(order, port, target):
      ports = gs.runChecks(order, port, target)
      results, elapsed =scan(target, ports)
      gs.print_scan_results(target,results, elapsed)

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