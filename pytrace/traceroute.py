import socket

from .banner import BANNER
from .probes import send_probe


PROBES_PER_HOP = 3


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

    print("=" * 115)
    print(f"Target     : {target}")
    print(f"Destination: {destination}")
    print(f"Max hops   : {max_hops}")
    print(f"Timeout    : {timeout}s")
    print(f"Probes/hop : {PROBES_PER_HOP}")
    print("=" * 115)

    print()

    print(
        f"{'HOP':<5}"
        f"{'IP ADDRESS':<20}"
        f"{'HOSTNAME':<42}"
        f"{'RTT':<15}"
        f"RESPONSE"
    )

    print("-" * 115)

    for ttl in range(1, max_hops + 1):

        responses = []

        for _ in range(PROBES_PER_HOP):

            try:
                reply, rtt, response = send_probe(
                    destination,
                    ttl,
                    timeout
                )

            except PermissionError as exc:
                print(f"\nError: {exc}")
                return

            if reply is None:
                responses.append(
                    (None, None, "NO_RESPONSE")
                )
                continue

            hop_ip = reply.src
            hostname = reverse_dns(hop_ip)

            responses.append(
                (
                    hop_ip,
                    hostname,
                    rtt,
                    response
                )
            )

        valid_responses = [
            result
            for result in responses
            if result[0] is not None
        ]

        if not valid_responses:

            print(
                f"{ttl:<5}"
                f"{'*':<20}"
                f"{'-':<42}"
                f"{'timeout':<15}"
                f"NO_RESPONSE"
            )

            continue

        # Group responses by IP.
        hop_ips = {}

        for hop_ip, hostname, rtt, response in valid_responses:

            if hop_ip not in hop_ips:
                hop_ips[hop_ip] = {
                    "hostname": hostname,
                    "rtts": [],
                    "responses": []
                }

            hop_ips[hop_ip]["rtts"].append(rtt)
            hop_ips[hop_ip]["responses"].append(response)

        first_ip = True

        destination_reached = False

        for hop_ip, data in hop_ips.items():

            hostname = data["hostname"]

            rtt_text = "  ".join(
                f"{rtt:.3f} ms"
                for rtt in data["rtts"]
            )

            response_text = ", ".join(
                data["responses"]
            )

            if first_ip:
                hop_text = str(ttl)
                first_ip = False
            else:
                hop_text = ""

            print(
                f"{hop_text:<5}"
                f"{hop_ip:<20}"
                f"{hostname:<42}"
                f"{rtt_text:<15}"
                f"{response_text}"
            )

            if hop_ip == destination:
                destination_reached = True

        print()

        if destination_reached:

            print("-" * 115)
            print("Destination reached.")

            return

    print("-" * 115)
    print("Maximum hop limit reached.")