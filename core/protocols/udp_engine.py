import socket
import secrets
import struct
import json
import time

DNS_SERVERS = [
    {"name": "Cloudflare", "ip": "1.1.1.1"},
    {"name": "Google", "ip": "8.8.8.8"},
    {"name": "Quad9", "ip": "9.9.9.9"}
]


def create_dns_query(domain):
    transaction_id = secrets.randbelow(65536)

    header = struct.pack(
        "!HHHHHH",
        transaction_id, 0x0100, 1, 0, 0, 0
    )

    question = b""

    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode()

    question += b"\x00"
    question += struct.pack("!HH", 1, 1)

    return transaction_id, header + question


def test_udp_dns(server):
    transaction_id, query = create_dns_query("example.com")
    start = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query, (server["ip"], 53))
            response, address = sock.recvfrom(4096)

        elapsed = (time.perf_counter() - start) * 1000

        valid = (
            len(response) >= 12
            and struct.unpack("!H", response[:2])[0] == transaction_id
            and bool(struct.unpack("!H", response[2:4])[0] & 0x8000)
        )

        return {
            "server": server["name"],
            "ip": server["ip"],
            "udp_response": valid,
            "latency_ms": round(elapsed, 2) if valid else None
        }

    except OSError as error:
        return {
            "server": server["name"],
            "ip": server["ip"],
            "udp_response": False,
            "latency_ms": None,
            "error": str(error)
        }


def main():
    results = [test_udp_dns(server) for server in DNS_SERVERS]

    print(json.dumps({
        "module": "JARO WPF UDP ENGINE",
        "protocol": "UDP DNS",
        "results": results
    }, indent=4))


if __name__ == "__main__":
    main()
