import socket

from .banner import BANNER
from .probes import send_probe


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


def get_response_type(reply) -> str:
    """Identify the ICMP response type."""

    if not reply.haslayer("ICMP"):
        return "UNKNOWN"

    icmp = reply.getlayer("ICMP")

    if icmp.type == 0:
        return "ECHO_REPLY"

    if icmp.type == 3:
        return "DESTINATION_UNREACHABLE"

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

    print("=" * 90)
    print(f"Target     : {target}")
    print(f"Destination: {destination}")
    print(f"Max hops   : {max_hops}")
    print(f"Timeout    : {timeout}s")
    print("=" * 90)

    print()

    print(
        f"{'HOP':<5}"
        f"{'IP ADDRESS':<20}"
        f"{'HOSTNAME':<40}"
        f"{'RTT':<12}"
        f"RESPONSE"
    )

    print("-" * 105)

    for ttl in range(1, max_hops + 1):

        try:
            reply, rtt, response = send_probe(
                destination,
                ttl,
                timeout
            )

        except PermissionError as exc:
            print(f"\nError: {exc}")
            return

        # No response from either ICMP or UDP.
        if reply is None:

            print(
                f"{ttl:<5}"
                f"{'*':<20}"
                f"{'-':<40}"
                f"{'timeout':<12}"
                f"NO_RESPONSE"
            )

            continue

        hop_ip = reply.src
        hostname = reverse_dns(hop_ip)

        response_type = get_response_type(reply)

        print(
            f"{ttl:<5}"
            f"{hop_ip:<20}"
            f"{hostname:<40}"
            f"{rtt:.3f} ms"
            f"{'':<4}"
            f"{response}"
        )

        # Destination reached through ICMP Echo Reply.
        if (
            hop_ip == destination
            and response_type == "ECHO_REPLY"
        ):

            print("-" * 105)
            print("Destination reached.")

            return

        # Destination can also respond to UDP with
        # ICMP Destination Unreachable / Port Unreachable.
        if (
            hop_ip == destination
            and response_type == "DESTINATION_UNREACHABLE"
        ):

            print("-" * 105)
            print("Destination reached.")

            return

    print("-" * 105)
    print("Maximum hop limit reached.")