import socket
import statistics

from .banner import BANNER
from .probes import probe_hop


PROBES_PER_HOP = 1


def resolve_target(target: str) -> str:
    """Resolve target hostname to IPv4 address."""

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

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):
        return "-"


def trace(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0
) -> None:
    """Perform multi-protocol network path discovery."""

    destination = resolve_target(target)

    print(BANNER)

    print("=" * 125)
    print(f"Target     : {target}")
    print(f"Destination: {destination}")
    print(f"Max hops   : {max_hops}")
    print(f"Timeout    : {timeout}s")
    print("Protocols  : ICMP + UDP + TCP")
    print("=" * 125)
    print()

    print(
        f"{'HOP':<5}"
        f"{'IP ADDRESS':<20}"
        f"{'HOSTNAME':<42}"
        f"{'PROTOCOL':<12}"
        f"{'RTT':<22}"
        f"RESPONSE"
    )

    print("-" * 125)

    for ttl in range(1, max_hops + 1):

        all_responses = []

        # ----------------------------------------------------
        # Multiple measurements for this TTL
        # ----------------------------------------------------

        for _ in range(PROBES_PER_HOP):

            try:

                responses = probe_hop(
                    destination,
                    ttl,
                    timeout
                )

                all_responses.extend(responses)

            except PermissionError as exc:

                print()
                print(f"ERROR: {exc}")
                return

            except OSError as exc:

                print()
                print(f"ERROR: {exc}")
                return

        # ----------------------------------------------------
        # No response
        # ----------------------------------------------------

        if not all_responses:

            print(
                f"{ttl:<5}"
                f"{'*':<20}"
                f"{'-':<42}"
                f"{'-':<12}"
                f"{'timeout':<22}"
                f"NO_RESPONSE"
            )

            continue

        # ----------------------------------------------------
        # Group responses by IP
        # ----------------------------------------------------

        routers = {}

        for response in all_responses:

            ip = response["ip"]

            if ip not in routers:

                routers[ip] = {
                    "rtts": [],
                    "protocols": [],
                    "responses": []
                }

            routers[ip]["rtts"].append(
                response["rtt"]
            )

            if response["protocol"] not in routers[ip]["protocols"]:

                routers[ip]["protocols"].append(
                    response["protocol"]
                )

            routers[ip]["responses"].append(
                response["type"]
            )

        # ----------------------------------------------------
        # Display discovered devices
        # ----------------------------------------------------

        destination_reached = False
        first = True

        for ip, data in routers.items():

            hostname = reverse_dns(ip)

            rtts = data["rtts"]

            minimum = min(rtts)
            average = statistics.mean(rtts)
            maximum = max(rtts)

            protocol_text = ",".join(
                data["protocols"]
            )

            response_text = ",".join(
                data["responses"]
            )

            rtt_text = (
                f"{minimum:.2f}/"
                f"{average:.2f}/"
                f"{maximum:.2f} ms"
            )

            hop_text = str(ttl) if first else ""

            print(
                f"{hop_text:<5}"
                f"{ip:<20}"
                f"{hostname:<42}"
                f"{protocol_text:<12}"
                f"{rtt_text:<22}"
                f"{response_text}"
            )

            first = False

            if ip == destination:
                destination_reached = True

        print()

        # ----------------------------------------------------
        # Destination reached
        # ----------------------------------------------------

        if destination_reached:

            print("-" * 125)
            print("Destination reached.")
            return

    print("-" * 125)
    print("Maximum hop limit reached.")