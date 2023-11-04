import nmap
import socket

def server_ip(url):
    target_ips = []
    try:
        # Perform the NSlookup to retrieve all IP addresses associated with the url
        addr_info = socket.getaddrinfo(url, None)
        ip_addresses = [info[4][0] for info in addr_info if info[0] == socket.AF_INET]

        # append ips to list
        for ip_address in ip_addresses:
            if ip_address not in target_ips:
                target_ips.append(ip_address)
        return target_ips
    except socket.gaierror:
        print(f"Could not resolve the hostname {url}")

def get_open_ports(target):
    open_ports = []
    scanner = nmap.PortScanner()
    scanner.scan(target)
        
    # Iterate through the scan results and extract open ports
    for host in scanner.all_hosts():
        for proto in scanner[host]['tcp']:
            port_info = scanner[host]['tcp'][proto]
            if port_info['state'] == 'open':
                open_ports.append(proto)
    return open_ports

if __name__ == "__main__":

    # Create a dictionary to store open ports for each IP address
    open_ports_dict = {}

    # Iterate through the list of IP addresses and scan for open ports
    url = "ENTER HOST NAME"
    target_ips = server_ip(url)

    for ip in target_ips:
        open_ports = get_open_ports(ip)
        open_ports_dict[ip] = open_ports

    print(open_ports_dict)