import os
import time

from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sr1


ICMP_ID = os.getpid() & 0xFFFF
UDP_BASE_PORT = 33434
TCP_BASE_PORT = 40000


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
    """Send a UDP traceroute probe."""

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

    if icmp.type == 11:
        return reply, elapsed, "UDP_TIME_EXCEEDED"

    if icmp.type == 3:
        return reply, elapsed, "UDP_DESTINATION_UNREACHABLE"

    return reply, elapsed, f"ICMP_TYPE_{icmp.type}"


def send_tcp_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """
    Send a TCP SYN probe with a specific TTL.

    TCP can sometimes reveal hops that do not respond
    to ICMP or UDP probes.
    """

    destination_port = TCP_BASE_PORT + ttl

    packet = (
        IP(
            dst=destination,
            ttl=ttl
        )
        /
        TCP(
            dport=destination_port,
            flags="S"
        )
    )

    reply, elapsed = _send_packet(
        packet,
        timeout
    )

    if reply is None:
        return None, None, "NO_RESPONSE"

    # Intermediate router reporting TTL expiration
    if reply.haslayer(ICMP):

        icmp = reply.getlayer(ICMP)

        if icmp.type == 11:
            return reply, elapsed, "TCP_TIME_EXCEEDED"

        if icmp.type == 3:
            return reply, elapsed, "TCP_DESTINATION_UNREACHABLE"

    # Destination replied with TCP
    if reply.haslayer(TCP):

        tcp = reply.getlayer(TCP)

        if tcp.flags & 0x12:
            return reply, elapsed, "TCP_SYN_ACK"

        if tcp.flags & 0x04:
            return reply, elapsed, "TCP_RST"

        return reply, elapsed, "TCP_RESPONSE"

    return reply, elapsed, "TCP_UNKNOWN"


def send_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """
    Try ICMP first, then UDP, then TCP.

    Returns:
        (reply, rtt_ms, response)
    """

    # ----------------------------------------
    # 1. ICMP
    # ----------------------------------------

    reply, rtt, response = send_icmp_probe(
        destination,
        ttl,
        timeout
    )

    if reply is not None:
        return reply, rtt, response

    # ----------------------------------------
    # 2. UDP
    # ----------------------------------------

    reply, rtt, response = send_udp_probe(
        destination,
        ttl,
        timeout
    )

    if reply is not None:
        return reply, rtt, response

    # ----------------------------------------
    # 3. TCP
    # ----------------------------------------

    reply, rtt, response = send_tcp_probe(
        destination,
        ttl,
        timeout
    )

    if reply is not None:
        return reply, rtt, response

    # ----------------------------------------
    # Nothing responded
    # ----------------------------------------

    return None, None, "NO_RESPONSE"