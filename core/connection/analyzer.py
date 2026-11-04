import socket
import subprocess
import json
from datetime import datetime


def get_interfaces():
    result = subprocess.run(
        ["ip", "-j", "address"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return []

    interfaces = json.loads(result.stdout)

    return [
        {
            "name": interface.get("ifname"),
            "state": interface.get("operstate"),
            "addresses": [
                address.get("local")
                for address in interface.get("addr_info", [])
            ]
        }
        for interface in interfaces
    ]


def test_dns():
    try:
        socket.getaddrinfo("example.com", 443)
        return True
    except OSError:
        return False


def test_internet():
    try:
        connection = socket.create_connection(
            ("1.1.1.1", 443),
            timeout=4
        )
        connection.close()
        return True
    except OSError:
        return False


def main():
    report = {
        "project": "JARO WPF",
        "version": "1.0.0",
        "date": datetime.now().isoformat(),
        "interfaces": get_interfaces(),
        "dns": test_dns(),
        "internet": test_internet()
    }

    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    main()
