from random import shuffle
import ipaddress
import socket
import subprocess as process

##### Step 1: Checking if Target is Valid Format #####
def check_ip(ip):
  """ 
    Check if the input is a valid IPv4 or IPv6 address.
    :param ip: The input IP address.
    :return: True if the input is a valid IP address, False otherwise.
    """
  try:
    ipaddress.ip_address(ip)
    return True
  except ValueError:
    return False


def check_hostname_or_ip_address(address):
  """
  If the target is a hostname, the scanner should convert it to an IP address.
  :param address: The target IP address.
  :return: The IP address if the target is a hostname, otherwise the target itself.
  """
  if check_ip(address):
    return address  #it is an ip
  else:
    try:
      return socket.gethostbyname(address)  #hostname address
    except Exception as e:
      print(
          "Invalid hostname cannot find ip address... Will be using a loopback address"
          "instead.. teeheehee... D:")
      return str(ipaddress.ip_address(
          "127.0.0.1"))  #Check later might be wrong how its written


#### Step 2: Check if the target is reachable (=alive) ####
def try_different_target():
  while True:
    response = input(
        "Would you like to try a different target? [Y/N]: ").strip().upper()

    if response == "Y":

      new_ip = input("Enter Target: ").strip()

      return new_ip

    elif response == "N":
      print("Till next time!")
      exit()

    else:
      print("I didn't understand that. Please enter Y or N.")

def reachable_test(ip):
  """
    Send a ping to the target. If you get a response time back, the target is reachable.
    :param address: The target IP address.
    :return: True/False if successful 
    """
  ping_command = ['ping','-c', '1', ip]

  try:
    output = (process.run(ping_command, capture_output=True))
    if output.returncode == 0:
      print("Ping code == 0")
      return True
    elif output.returncode < 0:
      print("Ping code < 0")
      return False
    else:  #see if it gets here ever...
      print("Ping code > 0")
      return False
  except Exception as e:
    print(f"An error occured while trying to ping: {e}")

def check_target_reachable(ip):
  if reachable_test(ip):
    print(f"Target: {ip} is reachable...")
    return True
  else:
    print(f"Target: {ip} is not reachable.")
    new_ip = try_different_target()
    if new_ip:
      check_target_reachable(new_ip)

#### Step 3: Prepaer Port scanning Methods ####
def get_port_order(ports, order):
  """
    Determine the order of ports based on the selected mode.

    :param ports: The list of ports to scan.
    :param order: The order of port scanning (ordered, random).
    :return: The ordered or shuffled list of ports.
    """
  if order == 'ordered':
    return ports
  else:
    return shuffle(ports)


def get_port_selection(select):
  """
    Select the type of ports to scan based on the user input.

    :param select: The selection of well-known or all ports.
    :return: The list of selected ports.
    """
  if select == "well-known":
    return list(range(0, 1024))
  elif select == "all":
    return list(range(0, 65535))
  else:
    print(
        "Selection options were all/well-known. Your input was an invalid option. Default All has been selected"
    )
    return list(range(0, 65535))


def get_port_list(select, order):
  """
    Generate a list of ports based on the selection and order mode.

    :param select: The selection of well-known or all ports.
    :param order: The order of port scanning (ordered, random).
    :return: The list of ports to scan.
    """
  ports = get_port_selection(select)
  ports = get_port_order(ports, order)
  return ports


#### Run Processes ### 

def runChecks(order, select, target):

  ### Step 1: Checking if Target is Valid Format ###
  target = check_hostname_or_ip_address(target)

  ### Step 2: Check if the target is reachable ###
  target_reached = check_target_reachable(target)

  ### Step 3: Setup Port Scanning Methods ###
  if target_reached:
    return get_port_list(select, order)


### Print Results ### (TENTATIVELY... like... very... its just like a thing... bro..)
def print_scan_results(ip, results, elapsed):

  print("Interesting ports on ", ip)

  unique_values = list(set(results.values())) #list of unique results (not ports)
  ##Get the counts for each unique resulting values from the port scan in order to 
  ## Customize the print for each type of scan used
  state_counts = {}
  for value in unique_values: 
    counter= 0

    for port, item in results.items(): 
      if value == item: 
        counter += 1

    state_counts[value] = counter

  #print("State Counts: ", state_counts)

  # The largest is not shown 
  max_state_count = sorted(state_counts.items(), key=lambda x:x[1])[-1] #Paola fix it!!! D:

  #print("Largest: ", max_state_count)

  print("Not Shown: ", max_state_count[1], " ", max_state_count[0], " ports")

  print("PORT\tSTATE\tSERVICE")
  # Remove largest from the count dic
  state_counts.pop(max_state_count[0])

  #print("State Counts after POP: ", state_counts)

  # results= results[results.values !=  max_state_count]
  # Do not show the largest
  # Show the rest (note may need to change if a scan ever has 4 types or specific cases)
  for port, item in results.items():
   ## print("ITEM: ", results.items())
    ##print("FOR LOOOP PORT: ", port)
    if item != max_state_count[0]:
      print(port, "\t", item, "\t",socket.getservbyport(port))
  # Tenative Edit later
  # if(filtered!=None):
  #  print( "Filtered: ", len(filtered), " ports that in some way had resolved none when receiving data ") #shouldnt need this later but for now
  # print("Opened ports ", len(successes), " opened ports")


  #   for port, msg in successes.items():
  #     print(port, "\tOPEN\t",socket.getservbyport(port) )
  # print("Scan complete! 1 IP address scanned in ", elapsed, "seconds")
