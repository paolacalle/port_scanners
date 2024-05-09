import socket
import time 
import argparse
import generalSelection as gs
import scapy.all as scapy 

"""
TCP ACK Scanning: This scan only sends the ACK flag. "When scanning 
unfiltered systems, open and closed ports will both return a RST packet.
Nmap then labels them as unfiltered, meaning that they are reachable by the ACK 
packet, but whether they are open or closed is undetermined. Ports that don't
respond, or send certain ICMP error messages back, are labeled filtered."
Resource: https://nmap.org/book/scan-methods-ack-scan.html
"""

def scan(ip_dst, ports):

  print("Starting TCP ACK Scan")
  initial=time.time()
  #time start
  results={}

  ip= scapy.IP(dst= ip_dst) #create IP Packet
  for current_port in ports:
    results[current_port] =''
    print(current_port)
    syn_pack = ip/scapy.TCP( dport=current_port, flags="A")
    reply=scapy.sr1(syn_pack, timeout= .001, verbose=0)

    if reply == None:
      reply = scapy.sr1(syn_pack, timeout= .01, verbose=0) #try again 
      print("Retransmission")
      results[current_port] +="retransmission"

    if reply == None:  #no response = filtered
        results[current_port] = "Filtered"

    elif reply[scapy.TCP].flags == "R": ##Reset =unfiltered
        results[current_port] = "unfiltered"  + str(reply[scapy.TCP].flags)

    elif reply.haslayer(scapy.ICMP): #ICMP error = filtered
      icmp = reply.getlayer(scapy.ICMP)

      if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
        results[current_port]= "filtered"  + str(reply[scapy.TCP].flags)
      else:
        results[current_port] = "\tissue"  + str(reply[scapy.TCP].flags)

    else: 

      results[current_port] +="\tissue2 " + str(reply[scapy.TCP].flags)

  finished= time.time()
  elapsed= finished-initial #end time

  return results, elapsed 


def main(order, port, target):
  ports = gs.runChecks(order, port, target)
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