  import socket
  import time 
  import argparse
  import generalSelection as gs
  import scapy.all as scapy 

  """
  TCP SYN Scanning: This sends a start connection signal (SYN) and end the connection if the 
  host responds (with SYN/ACK), without fully connecting. 
  """

  def scan(ip_dst, ports):

    print("Starting TCP SYN Scan")
    initial=time.time()
    #time start
    results={}

    ip= scapy.IP(dst= ip_dst) #create IP Packet
    for current_port in ports:

      print(current_port)
      syn_pack = ip/scapy.TCP( dport=current_port, flags="S")
      reply=scapy.sr1(syn_pack, timeout= .1, verbose=0)

      if reply== None:
        reply =scapy.sr1(syn_pack, timeout= .1, verbose=0) #try again 

      if reply == None:
        print("Filtered: reply None")
        results[current_port]="Filtered"

      else:
        if reply[scapy.TCP].flags=="SA" :
          print("SA")
          results[current_port]='Success: SA'
          scapy.sr1(ip/scapy.TCP(dport=current_port, flags="R"), timeout= .1,verbose=0) #ctrl c when stuck??

        elif reply[scapy.TCP].flags=="S":
          print("S")
          results[current_port]='Success: S'
          scapy.sr1(ip/scapy.TCP(dport=current_port, flags="R"), timeout= .1,verbose=0) #ctrl c when stuck??

        elif reply[scapy.TCP].flags=="RA":
          print("FAIL")
          print(current_port)
          results[current_port]='closed'

    finished= time.time()
    elapsed= finished-initial #end time
    return results, elapsed, 



  def main(order, port, target):
    ports = gs.runChecks(order, port, target)
    results, elapsed = scan(target, ports)
    gs.print_scan_results(target, results, elapsed)

  if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Scan for open ports using Tcp SYN.')

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