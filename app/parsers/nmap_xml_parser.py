from xml.etree import ElementTree


def parse_nmap_xml(xml_content: str) -> dict:
    try:
        root = ElementTree.fromstring(xml_content)
    except ElementTree.ParseError as exc:
        raise ValueError("Unable to parse Nmap XML file.") from exc

    host = root.find("host")
    if host is None:
        raise ValueError("Unable to parse Nmap XML file.")

    target = _extract_target(host)
    host_status = _extract_host_status(host)
    open_ports = _extract_open_ports(host)

    return {
        "target": target,
        "host_status": host_status,
        "open_ports": open_ports,
        "services": [open_port["service"] for open_port in open_ports],
        "duration": _extract_duration(root),
    }


def _extract_target(host: ElementTree.Element) -> str | None:
    address = host.find("address")
    if address is not None:
        return address.attrib.get("addr")

    hostname = host.find("hostnames/hostname")
    if hostname is not None:
        return hostname.attrib.get("name")

    return None


def _extract_host_status(host: ElementTree.Element) -> str | None:
    status = host.find("status")
    state = status.attrib.get("state") if status is not None else None
    if state == "up":
        return "Up"
    if state == "down":
        return "Down"

    return state


def _extract_open_ports(host: ElementTree.Element) -> list[dict[str, str]]:
    open_ports = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue

        service = port.find("service")
        open_ports.append(
            {
                "port": port.attrib.get("portid", ""),
                "protocol": port.attrib.get("protocol", ""),
                "service": service.attrib.get("name", "unknown") if service is not None else "unknown",
            }
        )

    return open_ports


def _extract_duration(root: ElementTree.Element) -> str | None:
    finished = root.find("runstats/finished")
    elapsed = finished.attrib.get("elapsed") if finished is not None else None
    if not elapsed:
        return None

    return f"{elapsed}s"
