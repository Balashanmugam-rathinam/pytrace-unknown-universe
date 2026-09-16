import os
import time

from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import sr1


# Use a stable identifier for this PyTrace process.
ICMP_ID = os.getpid() & 0xFFFF


def send_icmp_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """
    Send one ICMP Echo Request with a specific TTL.

    Returns:
        (reply, rtt_ms)
    """

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

    if not reply.haslayer(ICMP):
        return None, None

    icmp = reply.getlayer(ICMP)

    if icmp is None:
        return None, None

    # ICMP Time Exceeded
    if icmp.type == 11:
        return reply, elapsed

    # ICMP Echo Reply
    if icmp.type == 0:
        return reply, elapsed

    # ICMP Destination Unreachable
    if icmp.type == 3:
        return reply, elapsed

    return None, None