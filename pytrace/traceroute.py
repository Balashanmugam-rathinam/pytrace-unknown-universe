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


def get_icmp_response_type(reply) -> str:
    """Identify the ICMP response type."""

    if not reply.haslayer("ICMP"):
        return "UNKNOWN"

    icmp = reply.getlayer("ICMP")

    if icmp.type == 0:
        return "DESTINATION"

    if icmp.type == 3:
        return "UNREACHABLE"

    if icmp.type == 11:
        return "TIME_EXCEEDED"

    return f"ICMP_TYPE_{icmp.type}"


def trace(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0
) -> None:
    """Trace the IPv4 network path to a target."""

    destination = resolve_target(target)

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
        f"{'HOSTNAME':<30}"
        f"RESPONSE"
    )

    print("-" * 90)

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

        if reply is None:

            print(
                f"{ttl:<6}"
                f"{'*':<20}"
                f"{'timeout':<12}"
                f"{'-':<30}"
                f"NO_RESPONSE"
            )

            continue

        hop_ip = reply.src
        hostname = reverse_dns(hop_ip)
        response_type = get_icmp_response_type(reply)

        print(
            f"{ttl:<6}"
            f"{hop_ip:<20}"
            f"{rtt:.2f} ms"
            f"{'':<5}"
            f"{hostname:<30}"
            f"{response_type}"
        )

        if hop_ip == destination:

            print("-" * 90)
            print("Destination reached.")

            return

    print("-" * 90)
    print("Maximum hop limit reached.")