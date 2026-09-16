import socket

from .banner import BANNER
from .probes import send_icmp_probe


def resolve_target(target: str) -> str:
    """Resolve hostname to an IPv4 address."""

    try:
        return socket.gethostbyname(target)

    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve target: {target}"
        ) from exc


def reverse_dns(ip_address: str) -> str:
    """Perform reverse DNS lookup."""

    try:
        return socket.gethostbyaddr(ip_address)[0]

    except (socket.herror, socket.gaierror):
        return "-"


def trace(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0
) -> None:
    """Trace the IPv4 network path to a target."""

    destination = resolve_target(target)

    # Display banner
    print(BANNER)

    print("=" * 70)
    print(f"Target     : {target}")
    print(f"Destination: {destination}")
    print(f"Max hops   : {max_hops}")
    print(f"Timeout    : {timeout}s")
    print("=" * 70)

    print()

    print(
        f"{'HOP':<6}"
        f"{'IP ADDRESS':<20}"
        f"{'RTT':<12}"
        f"HOSTNAME"
    )

    print("-" * 70)

    for ttl in range(1, max_hops + 1):

        try:
            reply, rtt = send_icmp_probe(
                destination,
                ttl,
                timeout
            )

        except PermissionError as exc:
            print(f"\nError: {exc}")
            return

        # No response
        if reply is None:

            print(
                f"{ttl:<6}"
                f"{'*':<20}"
                f"{'timeout':<12}"
                f"-"
            )

            continue

        # Responding device
        hop_ip = reply.src
        hostname = reverse_dns(hop_ip)

        print(
            f"{ttl:<6}"
            f"{hop_ip:<20}"
            f"{rtt:.2f} ms"
            f"{'':<5}"
            f"{hostname}"
        )

        # Destination reached
        if hop_ip == destination:

            print("-" * 70)
            print("Destination reached.")

            return

    print("-" * 70)
    print("Maximum hop limit reached.")