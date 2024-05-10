import warnings
warnings.filterwarnings("ignore")

from random import shuffle
import ipaddress
import socket
import subprocess as process


##### Step 1: Checking if Target is Valid Format #####
def check_ip(ip):
    """Check if the input is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_hostname_or_ip_address(address):
    """Resolve hostname to IP address or validate the IP address."""
    if check_ip(address):
        return address
    try:
        # all IP addresses associated with the address
        ip_addresses = socket.getaddrinfo(address, None)
        unique_ips = set()
        for addr in ip_addresses:
            ip = addr[4][0]
            unique_ips.add(ip)
        
        # primary IP address used by the system for this address
        ip_used = socket.gethostbyname(address)
        
        # filter and display additional IPs that are not the primary one used
        if len(unique_ips) > 1:
            other_ips = [ip for ip in unique_ips if ip != ip_used]
            if other_ips:
                print(f"Other addresses for {address} (not scanned): {', '.join(other_ips)}")
        
        return ip_used
      
    except socket.error:
        print("Invalid hostname or IP address. Using loopback address as fallback.")
        return "127.0.0.1"
      
def reachable_test(ip):
    """Check if the target IP address is reachable by sending a ping."""
    ping_command = ['ping','-c', '1', ip]

    try:
        output = (process.run(ping_command, capture_output=True))
        if output.returncode == 0:
            print(f"Host {ip} is up: Ping code is 0")
            return True
        elif output.returncode < 0:
            print("Ping code < 0")
            return False
        else:
            print("Ping code > 0")
            return False
    except Exception as e:
      print(f"Failed to ping {ip}: {e}")

#### Step 2: Check if the target is reachable (=alive) ####
def check_target_reachable(ip):
    """Continuously check if the target is reachable and prompt for a new target if not."""
    while not reachable_test(ip):
        response = input("Target unreachable. Try a different target? [Y/N]: ").strip().upper()
        if response == 'Y':
            ip = check_hostname_or_ip_address(input("Enter new target: ").strip())
        elif response == 'N':
            print("Exiting.")
            exit()
    return ip


#### Step 3: Prepare Port scanning Methods ####
def get_ports(order, selection):
    """Get a list of ports to scan based on user selection and order."""
    if selection == "known":
        ports = list(range(1024)) # 0 to 1023
    else:
        ports = list(range(65536)) # 0 to 65,535

    if order == "random":
        shuffle(ports)

    return ports


#### Run Processes ### 
def run_checks(order, selection, target):
    """Run pre-scan checks and return a list of ports to scan if the target is reachable."""
    target = check_hostname_or_ip_address(target)
    target = check_target_reachable(target)
    return get_ports(order, selection)

### Print Results ###
def print_scan_results(ip, results, elapsed, connection_protocol = 'tcp'):
    """Print the scan results in a formatted table."""
    print(f"Interesting ports on {ip}:")

    state_counts = {}
    for state in results.values(): 
        if state in state_counts:
            state_counts[state] += 1
        else:
            state_counts[state] = 1
      
    # The most common state
    most_common_state = max(state_counts, key=state_counts.get)
    most_common_count = state_counts[most_common_state]

    print("Not Shown: ", most_common_count, " ", most_common_state, " ports")

    print("PORT\tSTATE\tSERVICE")
    # Iterate over results and print details
    for port, state in results.items():
        if state != most_common_state:  # skip the most common state
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = 'Unknown'  # Handle ports with no known service
            print(f"{port}/{connection_protocol}\t{state}\t{service}")
            
    print(f"Scan done! 1 IP address (1 host up) scanned in {elapsed} seconds")