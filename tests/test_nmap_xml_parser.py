import pytest

from app.parsers.nmap_xml_parser import parse_nmap_xml

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.0.24" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" />
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service name="microsoft-ds" />
      </port>
      <port protocol="tcp" portid="999">
        <state state="closed" />
        <service name="unknown" />
      </port>
    </ports>
  </host>
  <runstats>
    <finished elapsed="0.25" />
  </runstats>
</nmaprun>
"""


def test_valid_nmap_xml_parsing() -> None:
    parsed = parse_nmap_xml(NMAP_XML)

    assert parsed == {
        "target": "192.168.0.24",
        "host_status": "Up",
        "open_ports": [
            {"port": "22", "protocol": "tcp", "service": "ssh"},
            {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
        ],
        "services": ["ssh", "microsoft-ds"],
        "duration": "0.25s",
    }


def test_host_extraction() -> None:
    assert parse_nmap_xml(NMAP_XML)["target"] == "192.168.0.24"


def test_port_extraction() -> None:
    assert parse_nmap_xml(NMAP_XML)["open_ports"][0] == {"port": "22", "protocol": "tcp", "service": "ssh"}


def test_invalid_xml_handling() -> None:
    with pytest.raises(ValueError, match="Unable to parse"):
        parse_nmap_xml("<nmaprun>")
