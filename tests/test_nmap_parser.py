from app.tools.nmap_parser import MAX_FORMATTED_OUTPUT_LENGTH, format_nmap_result, parse_nmap_output

NMAP_OUTPUT = """
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for 127.0.0.1
Host is up (0.00012s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
"""


def test_parse_open_ports() -> None:
    parsed = parse_nmap_output(NMAP_OUTPUT)

    assert parsed["open_ports"] == [
        {"port": "22", "protocol": "tcp", "service": "ssh"},
        {"port": "135", "protocol": "tcp", "service": "msrpc"},
        {"port": "445", "protocol": "tcp", "service": "microsoft-ds"},
    ]


def test_parse_target() -> None:
    parsed = parse_nmap_output(NMAP_OUTPUT)

    assert parsed["target"] == "127.0.0.1"


def test_parse_host_status_up() -> None:
    parsed = parse_nmap_output(NMAP_OUTPUT)

    assert parsed["host_status"] == "Up"


def test_parse_duration() -> None:
    parsed = parse_nmap_output(NMAP_OUTPUT)

    assert parsed["duration"] == "0.32s"


def test_format_clean_output() -> None:
    result_text = format_nmap_result(parse_nmap_output(NMAP_OUTPUT))

    assert result_text == (
        "Target: 127.0.0.1\n"
        "\n"
        "Host Status: Up\n"
        "\n"
        "Open Ports:\n"
        "22/tcp ssh\n"
        "135/tcp msrpc\n"
        "445/tcp microsoft-ds\n"
        "\n"
        "Duration: 0.32s"
    )
    assert "Starting Nmap" not in result_text
    assert "https://nmap.org" not in result_text


def test_no_open_ports_case() -> None:
    parsed = parse_nmap_output(
        """
        Nmap scan report for 127.0.0.1
        Host is up.
        All 1000 scanned ports on 127.0.0.1 are in ignored states.
        Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
        """
    )

    assert "No open ports found." in format_nmap_result(parsed)


def test_fallback_output_truncation() -> None:
    fallback_text = f"https://nmap.org {'x' * (MAX_FORMATTED_OUTPUT_LENGTH * 2)}"
    result_text = format_nmap_result({}, fallback_output=fallback_text)

    assert len(result_text) < len(fallback_text)
    assert result_text.startswith("nmap.org ")
    assert "[output truncated]" in result_text
    assert "https://nmap.org" not in result_text
