  import socket
  import time 
  import argparse
  import generalSelection as gs

  """TCP Connect Scanning: This method makes a full connection to each port.
  If the connection is established, the port is open. In this method, the scanner should 
  capture any initial information (e.g., banner) the server  sends back. """
  def scan(ip, ports):

    print("Starting TCP Connect Scan")
    initial=time.time()
    #time start
    results={}
    for current_port in ports:
      # if current_port==25:
      #   break
      try:
        with socket.create_connection((ip, current_port), timeout=.1) as sock:
          msg = sock.recv(1024)
          print("BANNER: ", msg)
          results[current_port]= "successes"
      except Exception as e:
        print("Fail Port: ", current_port)
        results[current_port] = "closed"
      print(".") #the progress dot...
      print("connect")
    #need to end the timer 
    finished= time.time()
    elapsed= finished-initial #end time

    return results, elapsed






  def main(order, port, target):
    ports = gs.runChecks(order, port, target)
    results, elapsed = scan(target, ports)
    gs.print_scan_results(target, results, elapsed)

  if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Scan for open ports using TCP Connect.')

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