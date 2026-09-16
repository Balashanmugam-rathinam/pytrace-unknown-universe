import os
import time

from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sr1


ICMP_ID = os.getpid() & 0xFFFF
UDP_BASE_PORT = 33434
TCP_PORT = 443


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
            "Unable to create raw socket.\n"
            "Run PyTrace with sufficient privileges."
        ) from exc

    except OSError as exc:
        raise OSError(
            f"Network error while sending probe: {exc}"
        ) from exc

    elapsed = (
        time.perf_counter() - start
    ) * 1000

    if reply is None:
        return None, None

    return reply, elapsed


# ============================================================
# ICMP
# ============================================================

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

    reply, rtt = _send_packet(
        packet,
        timeout
    )

    if reply is None:
        return None

    if not reply.haslayer(ICMP):
        return None

    icmp = reply.getlayer(ICMP)

    # Pylance/Scapy safety check
    if icmp is None:
        return None

    if icmp.type == 11:
        return {
            "protocol": "ICMP",
            "ip": reply.src,
            "rtt": rtt,
            "type": "TIME_EXCEEDED"
        }

    if icmp.type == 0:
        return {
            "protocol": "ICMP",
            "ip": reply.src,
            "rtt": rtt,
            "type": "ECHO_REPLY"
        }

    if icmp.type == 3:
        return {
            "protocol": "ICMP",
            "ip": reply.src,
            "rtt": rtt,
            "type": "DESTINATION_UNREACHABLE"
        }

    return {
        "protocol": "ICMP",
        "ip": reply.src,
        "rtt": rtt,
        "type": f"ICMP_TYPE_{icmp.type}"
    }


# ============================================================
# UDP
# ============================================================

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

    reply, rtt = _send_packet(
        packet,
        timeout
    )

    if reply is None:
        return None

    if not reply.haslayer(ICMP):
        return None

    icmp = reply.getlayer(ICMP)

    # Pylance/Scapy safety check
    if icmp is None:
        return None

    if icmp.type == 11:
        return {
            "protocol": "UDP",
            "ip": reply.src,
            "rtt": rtt,
            "type": "TIME_EXCEEDED"
        }

    if icmp.type == 3:
        return {
            "protocol": "UDP",
            "ip": reply.src,
            "rtt": rtt,
            "type": "DESTINATION_UNREACHABLE"
        }

    return {
        "protocol": "UDP",
        "ip": reply.src,
        "rtt": rtt,
        "type": f"ICMP_TYPE_{icmp.type}"
    }


# ============================================================
# TCP
# ============================================================

def send_tcp_probe(
    destination: str,
    ttl: int,
    timeout: float
):
    """Send a TCP SYN probe to port 443."""

    packet = (
        IP(
            dst=destination,
            ttl=ttl
        )
        /
        TCP(
            dport=TCP_PORT,
            flags="S"
        )
    )

    reply, rtt = _send_packet(
        packet,
        timeout
    )

    if reply is None:
        return None

    # --------------------------------------------------------
    # ICMP response to TCP probe
    # --------------------------------------------------------

    if reply.haslayer(ICMP):

        icmp = reply.getlayer(ICMP)

        if icmp is not None:

            if icmp.type == 11:
                return {
                    "protocol": "TCP",
                    "ip": reply.src,
                    "rtt": rtt,
                    "type": "TIME_EXCEEDED"
                }

            if icmp.type == 3:
                return {
                    "protocol": "TCP",
                    "ip": reply.src,
                    "rtt": rtt,
                    "type": "DESTINATION_UNREACHABLE"
                }

    # --------------------------------------------------------
    # TCP response
    # --------------------------------------------------------

    if reply.haslayer(TCP):

        tcp = reply.getlayer(TCP)

        if tcp is None:
            return None

        flags = int(tcp.flags)

        # SYN + ACK
        if (flags & 0x12) == 0x12:
            return {
                "protocol": "TCP",
                "ip": reply.src,
                "rtt": rtt,
                "type": "SYN_ACK"
            }

        # RST
        if (flags & 0x04) == 0x04:
            return {
                "protocol": "TCP",
                "ip": reply.src,
                "rtt": rtt,
                "type": "RST"
            }

        return {
            "protocol": "TCP",
            "ip": reply.src,
            "rtt": rtt,
            "type": "TCP_RESPONSE"
        }

    return None


# ============================================================
# MULTI-PROTOCOL DISCOVERY
# ============================================================

def probe_hop(
    destination: str,
    ttl: int,
    timeout: float
):
    """
    Probe one TTL using ICMP, UDP and TCP independently.

    Returns every observable response.
    """

    responses = []

    probes = (
        send_icmp_probe,
        send_udp_probe,
        send_tcp_probe
    )

    for probe in probes:

        try:

            result = probe(
                destination,
                ttl,
                timeout
            )

        except PermissionError:
            raise

        except OSError:
            result = None

        except Exception:
            result = None

        if result is not None:
            responses.append(result)

    return responses