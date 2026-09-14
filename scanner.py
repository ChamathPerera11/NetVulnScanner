import nmap

def scan_target(target):
    scanner = nmap.PortScanner()

    print(f"Scanning {target}...")

    scanner.scan(
        target,
        arguments="-sV -T4"
    )

    results = []

    for host in scanner.all_hosts():

        for protocol in scanner[host].all_protocols():

            ports = scanner[host][protocol].keys()

            for port in sorted(ports):

                service = scanner[host][protocol][port]

                result = {
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "state": service.get("state", ""),
                    "service": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", "")
                }

                results.append(result)

    return results