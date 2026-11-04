import socket
import secrets
import struct
import json
import time

SERVERS = [
    {"name": "Cloudflare", "ip": "1.1.1.1"},
    {"name": "Google", "ip": "8.8.8.8"},
    {"name": "Quad9", "ip": "9.9.9.9"}
]


def create_query(domain):
    transaction_id = secrets.randbelow(65536)

    header = struct.pack(
        "!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0
    )

    question = b""
    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode()

    question += b"\x00" + struct.pack("!HH", 1, 1)

    return transaction_id, header + question


def receive_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Respuesta incompleta")
        data += chunk
    return data


def test_server(server):
    transaction_id, query = create_query("example.com")
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (server["ip"], 53), timeout=4
        ) as sock:
            sock.settimeout(4)
            sock.sendall(struct.pack("!H", len(query)) + query)

            length = struct.unpack("!H", receive_exact(sock, 2))[0]
            response = receive_exact(sock, length)

        elapsed = (time.perf_counter() - start) * 1000

        valid = (
            len(response) >= 12
            and struct.unpack("!H", response[:2])[0] == transaction_id
            and bool(struct.unpack("!H", response[2:4])[0] & 0x8000)
        )

        return {
            "server": server["name"],
            "ip": server["ip"],
            "tcp_response": valid,
            "latency_ms": round(elapsed, 2) if valid else None
        }

    except OSError as error:
        return {
            "server": server["name"],
            "ip": server["ip"],
            "tcp_response": False,
            "latency_ms": None,
            "error": str(error)
        }


def main():
    results = [test_server(server) for server in SERVERS]

    print(json.dumps({
        "module": "JARO WPF TCP DNS ENGINE",
        "protocol": "TCP DNS",
        "results": results
    }, indent=4))


if __name__ == "__main__":
    main()
