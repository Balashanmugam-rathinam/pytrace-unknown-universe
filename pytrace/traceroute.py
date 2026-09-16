import socket

from .banner import BANNER
from .probes import send_probe


PROBES_PER_HOP = 3


def resolve_target(target: str) -> str:
    """Resolve the target hostname to an IPv4 address."""

    try:
        return socket.gethostbyname(target)

    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve target: {target}"
        ) from exc


def reverse_dns(ip_address: str) -> str:
    """Resolve an IP address to its hostname."""

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
    """Discover the observable network path to an IPv4 target."""

    destination = resolve_target(target)

    print(BANNER)

    print("=" * 125)
    print(f"Target     : {target}")
    print(f"Destination: {destination}")
    print(f"Max hops   : {max_hops}")
    print(f"Timeout    : {timeout}s")
    print(f"Probes/hop : {PROBES_PER_HOP}")
    print("=" * 125)
    print()

    print(
        f"{'HOP':<5}"
        f"{'IP ADDRESS':<20}"
        f"{'HOSTNAME':<42}"
        f"{'RTT':<32}"
        f"RESPONSE"
    )

    print("-" * 125)

    for ttl in range(1, max_hops + 1):

        responses = []

        # ----------------------------------------
        # Send multiple probes for this TTL
        # ----------------------------------------

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
                    {
                        "ip": None,
                        "hostname": "-",
                        "rtt": None,
                        "response": "NO_RESPONSE"
                    }
                )

                continue

            hop_ip = reply.src
            hostname = reverse_dns(hop_ip)

            response_type = get_response_type(reply)

            responses.append(
                {
                    "ip": hop_ip,
                    "hostname": hostname,
                    "rtt": rtt,
                    "response": response_type
                }
            )

        # ----------------------------------------
        # Remove probes that received no response
        # ----------------------------------------

        valid_responses = [
            item
            for item in responses
            if item["ip"] is not None
        ]

        # ----------------------------------------
        # No router response
        # ----------------------------------------

        if not valid_responses:

            print(
                f"{ttl:<5}"
                f"{'*':<20}"
                f"{'-':<42}"
                f"{'timeout':<32}"
                f"NO_RESPONSE"
            )

            continue

        # ----------------------------------------
        # Group responses by IP address
        # ----------------------------------------

        routers = {}

        for item in valid_responses:

            ip = item["ip"]

            if ip not in routers:

                routers[ip] = {
                    "hostname": item["hostname"],
                    "rtts": [],
                    "responses": []
                }

            routers[ip]["rtts"].append(
                item["rtt"]
            )

            routers[ip]["responses"].append(
                item["response"]
            )

        destination_reached = False

        first_router = True

        # ----------------------------------------
        # Display discovered routers
        # ----------------------------------------

        for ip, data in routers.items():

            hostname = data["hostname"]

            rtt_text = "  ".join(
                f"{rtt:.3f} ms"
                for rtt in data["rtts"]
            )

            response_text = ", ".join(
                data["responses"]
            )

            hop_number = (
                str(ttl)
                if first_router
                else ""
            )

            print(
                f"{hop_number:<5}"
                f"{ip:<20}"
                f"{hostname:<42}"
                f"{rtt_text:<32}"
                f"{response_text}"
            )

            first_router = False

            # ------------------------------------
            # Check destination
            # ------------------------------------

            if ip == destination:
                destination_reached = True

        print()

        if destination_reached:

            print("-" * 125)
            print("Destination reached.")

            return

    print("-" * 125)
    print("Maximum hop limit reached.")