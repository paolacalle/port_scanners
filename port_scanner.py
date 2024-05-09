import argparse
import importlib
import generalSelection as gs

#### Change This As Needed ###
module_map = {
    "syn": "TcpSynScan",
    "ack": "TcpAckScan",
    "connect": "TcpConnectScan",
    "udp": "UdpScan",
    "xmas": "XmasScan"
}

def import_scanner(mode):
    """Dynamically import the scan module based on the mode."""
    module_name = module_map.get(mode)
    if module_name:
        return importlib.import_module(module_name)
    return None

def main(mode, order, port, target):
    """
    Directs the port scanning based on the chosen mode and options.

    :param mode: The scanning mode (syn, connect, udp, xmas, ack)
    :param order: The order to scan the ports (ordered, random)
    :param port: The type of ports to scan (all, well-known)
    :param target: The target IP address or hostname
    :param timeout: Timeout for each scan attempt
    """
    target = gs.check_hostname_or_ip_address(target)

    scanner_module = import_scanner(mode)
    if not scanner_module:
        print(f"Error: Unsupported scanning mode '{mode}'. Choose from {list(module_map.keys())}.")
        return

    scan_function = getattr(scanner_module, 'scan', None)
    ports = gs.run_checks(order, port, target)

    if scan_function:
        results, elapsed = scan_function(target, ports)
        gs.print_scan_results(target, results, elapsed)
    else:
        print("Scan function not found in the module.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan for open ports using different methods.')
    parser.add_argument('-m', '--mode', type=str, choices = list(module_map.keys()),
                        required=True, help='Scanner mode [syn, ack, connect, udp, xmas]')
    parser.add_argument('-o', '--order', type=str, choices=['ordered', 'random'],
                        default='random', help='Order of port scanning [ordered, random]')
    parser.add_argument('-p', '--port', type=str, choices=['all', 'known'],
                        default='all', help='Type of ports to scan [all, known]')
    parser.add_argument('target', type=str, help='Target IP address or hostname')

    args = parser.parse_args()

    main(args.mode, args.order, args.port, args.target)
