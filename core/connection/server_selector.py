import socket
import time
import json

SERVERS = [
    {
        "name": "Cloudflare DNS",
        "host": "1.1.1.1",
        "port": 443
    },
    {
        "name": "Google DNS",
        "host": "8.8.8.8",
        "port": 443
    },
    {
        "name": "Quad9 DNS",
        "host": "9.9.9.9",
        "port": 443
    }
]


def test_server(server):
    start = time.perf_counter()

    try:
        connection = socket.create_connection(
            (server["host"], server["port"]),
            timeout=3
        )

        connection.close()

        latency = (time.perf_counter() - start) * 1000

        return {
            "name": server["name"],
            "host": server["host"],
            "available": True,
            "latency_ms": round(latency, 2)
        }

    except OSError:
        return {
            "name": server["name"],
            "host": server["host"],
            "available": False,
            "latency_ms": None
        }


def main():
    results = [test_server(s) for s in SERVERS]

    available = [
        server for server in results
        if server["available"]
    ]

    best = min(
        available,
        key=lambda s: s["latency_ms"],
        default=None
    )

    report = {
        "module": "JARO WPF SERVER SELECTOR",
        "servers": results,
        "best_server": best
    }

    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    main()
