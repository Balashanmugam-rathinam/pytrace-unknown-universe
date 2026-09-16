import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def send_icmp_probe(destination: str, ttl: int, timeout: float):
    """
    Send an ICMP Echo Request with a specific TTL.

    Returns:
        (reply, rtt_ms)
    """

    packet = (
        IP(dst=destination, ttl=ttl)
        / ICMP()
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
            "Unable to create the raw socket."
        ) from exc

    elapsed = (time.perf_counter() - start) * 1000

    if reply is None:
        return None, None

    # Accept ICMP responses.
    if reply.haslayer(ICMP):
        return reply, elapsed

    return None, None