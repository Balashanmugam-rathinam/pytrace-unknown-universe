import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr


def send_icmp_probe(destination: str, ttl: int, timeout: float):
    """
    Send an ICMP Echo Request with a specific TTL.

    Returns:
        (reply, rtt_ms)
    """

    packet = (
        IP(
            dst=destination,
            ttl=ttl
        )
        / ICMP()
    )

    start = time.perf_counter()

    try:
        answered, unanswered = sr(
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

    elapsed = (time.perf_counter() - start) * 1000

    if not answered:
        return None, None

    for sent_packet, received_packet in answered:

        if not received_packet.haslayer(ICMP):
            continue

        icmp = received_packet.getlayer(ICMP)

        if icmp is None:
            continue

        # ICMP Time Exceeded
        if icmp.type == 11:
            return received_packet, elapsed

        # ICMP Echo Reply
        if icmp.type == 0:
            return received_packet, elapsed

        # ICMP Destination Unreachable
        if icmp.type == 3:
            return received_packet, elapsed

    return None, None