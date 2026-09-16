from pytrace.traceroute import (
    resolve_target,
    reverse_dns
)


def test_resolve_localhost():
    ip = resolve_target("localhost")

    assert ip == "127.0.0.1"


def test_reverse_dns():
    hostname = reverse_dns("127.0.0.1")

    assert isinstance(hostname, str)