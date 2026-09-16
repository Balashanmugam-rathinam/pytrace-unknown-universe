import os
import time

from scapy.layers.inet import IP, ICMP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1


ICMP_ID = os.getpid() & 0xFFFF
UDP_BASE_PORT = 33434


def _send_packet(packet, timeout):
    """Send a packet and return the response with RTT."""

    start = time.perf_counter()

    try:
        reply = sr1(
            packet,
            timeout=timeout,
            verbose=False,
            retry=0
        )

    except PermissionError as exc:
        raise PermissionError(
            "Unable to create the raw socket.\n"
            "Run PyTrace with sufficient privileges."
        ) from exc

    elapsed = (
        time.perf_counter() - start
    ) * 1000

    if reply is None:
        return None, None

    return reply, elapsed


def send_icmp_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """Send an ICMP Echo Request with a specific TTL."""

    packet = (
        IP(
            dst=destination,
            ttl=ttl
        )
        /
        ICMP(
            id=ICMP_ID,
            seq=ttl
        )
        /
        Raw(
            load=b"PyTrace-Unknown-Universe"
        )
    )

    reply, elapsed = _send_packet(
        packet,
        timeout
    )

    if reply is None:
        return None, None, "NO_RESPONSE"

    if not reply.haslayer(ICMP):
        return None, None, "NO_RESPONSE"

    icmp = reply.getlayer(ICMP)

    if icmp is None:
        return None, None, "NO_RESPONSE"

    if icmp.type == 11:
        return reply, elapsed, "ICMP_TIME_EXCEEDED"

    if icmp.type == 0:
        return reply, elapsed, "ICMP_ECHO_REPLY"

    if icmp.type == 3:
        return reply, elapsed, "ICMP_DESTINATION_UNREACHABLE"

    return reply, elapsed, f"ICMP_TYPE_{icmp.type}"


def send_udp_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """
    Send a UDP traceroute probe.

    UDP destination ports start at 33434 and increase
    with each TTL.
    """

    destination_port = UDP_BASE_PORT + ttl

    packet = (
        IP(
            dst=destination,
            ttl=ttl
        )
        /
        UDP(
            dport=destination_port
        )
        /
        Raw(
            load=b"PyTrace-Unknown-Universe"
        )
    )

    reply, elapsed = _send_packet(
        packet,
        timeout
    )

    if reply is None:
        return None, None, "NO_RESPONSE"

    if not reply.haslayer(ICMP):
        return None, None, "NO_RESPONSE"

    icmp = reply.getlayer(ICMP)

    if icmp is None:
        return None, None, "NO_RESPONSE"

    # Router exceeded TTL
    if icmp.type == 11:
        return reply, elapsed, "UDP_TIME_EXCEEDED"

    # Destination received UDP packet on a closed port.
    if icmp.type == 3:
        return reply, elapsed, "UDP_DESTINATION"

    return reply, elapsed, f"ICMP_TYPE_{icmp.type}"


def send_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """
    Try ICMP first.

    If ICMP produces no response, try UDP.

    Returns:
        (reply, rtt_ms, protocol)
    """

    reply, rtt, response = send_icmp_probe(
        destination,
        ttl,
        timeout
    )

    if reply is not None:
        return reply, rtt, response

    reply, rtt, response = send_udp_probe(
        destination,
        ttl,
        timeout
    )

    return reply, rtt, response