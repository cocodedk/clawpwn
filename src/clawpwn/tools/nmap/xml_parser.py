"""Nmap XML output parser."""

from .scanner import HostResult, PortScanResult


def parse_nmap_xml(xml_data: str) -> list[HostResult]:
    """Parse nmap XML output into HostResult objects."""
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        # Fallback if xml parsing fails
        return []

    results = []

    try:
        root = ET.fromstring(xml_data)

        for host in root.findall("host"):
            host_result = _parse_host(host)
            if host_result:
                results.append(host_result)
    except ET.ParseError:
        pass

    return results


def _parse_host(host_elem) -> HostResult | None:
    """Parse a single host element from nmap XML."""

    # Get IP address
    address = host_elem.find("address[@addrtype='ipv4']")
    if address is None:
        address = host_elem.find("address")

    if address is None:
        return None

    ip = address.get("addr", "")

    # Get hostname
    hostnames = host_elem.find("hostnames")
    hostname = ""
    if hostnames is not None:
        hostname_elem = hostnames.find("hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")

    # Get status
    status_elem = host_elem.find("status")
    status = status_elem.get("state", "") if status_elem is not None else ""

    # Get ports
    ports = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port in ports_elem.findall("port"):
            port_result = _parse_port(port)
            if port_result:
                ports.append(port_result)

    # Get OS info
    os_info = {}
    os_elem = host_elem.find("os")
    if os_elem is not None:
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            os_info = {
                "name": osmatch.get("name", ""),
                "accuracy": osmatch.get("accuracy", ""),
            }

    return HostResult(
        ip=ip,
        hostname=hostname,
        status=status,
        ports=ports,
        os_info=os_info,
    )


def _parse_port(port_elem) -> PortScanResult | None:
    """Parse a single port element from nmap XML."""
    portid = port_elem.get("portid", "")
    protocol = port_elem.get("protocol", "")

    # Get state
    state_elem = port_elem.find("state")
    state = state_elem.get("state", "") if state_elem is not None else ""

    # Get service info
    service = ""
    version = ""
    product = ""
    extra_info = ""

    service_elem = port_elem.find("service")
    if service_elem is not None:
        service = service_elem.get("name", "")
        version = service_elem.get("version", "")
        product = service_elem.get("product", "")
        extra_info = service_elem.get("extrainfo", "")

    try:
        port_num = int(portid)
    except ValueError:
        return None

    return PortScanResult(
        port=port_num,
        protocol=protocol,
        state=state,
        service=service,
        version=version,
        product=product,
        extra_info=extra_info,
    )
