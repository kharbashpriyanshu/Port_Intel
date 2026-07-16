import argparse

import pytest

from portintel.cli.validators import (
    valid_network,
    valid_port,
    valid_target,
    valid_threads,
    valid_timeout,
)


def test_valid_target_ip():
    assert valid_target("192.168.1.1") == "192.168.1.1"

def test_valid_target_hostname():
    assert valid_target("example.com") == "example.com"
    assert valid_target("localhost") == "localhost"

def test_invalid_target():
    with pytest.raises(argparse.ArgumentTypeError):
        valid_target("192.168.1.999")
    with pytest.raises(argparse.ArgumentTypeError):
        valid_target("invalid_hostname!!!")

def test_valid_network():
    assert valid_network("192.168.1.0/24") == "192.168.1.0/24"
    assert valid_network("10.0.0.0/8") == "10.0.0.0/8"

def test_invalid_network():
    with pytest.raises(argparse.ArgumentTypeError):
        valid_network("192.168.1.0/40")
    with pytest.raises(argparse.ArgumentTypeError):
        valid_network("not-a-network")

def test_valid_port():
    assert valid_port("80") == 80
    assert valid_port("65535") == 65535

def test_invalid_port():
    with pytest.raises(argparse.ArgumentTypeError):
        valid_port("0")
    with pytest.raises(argparse.ArgumentTypeError):
        valid_port("65536")
    with pytest.raises(argparse.ArgumentTypeError):
        valid_port("abc")

def test_valid_threads():
    assert valid_threads("100") == 100

def test_invalid_threads():
    with pytest.raises(argparse.ArgumentTypeError):
        valid_threads("0")
    with pytest.raises(argparse.ArgumentTypeError):
        valid_threads("5001")

def test_valid_timeout():
    assert valid_timeout("1.5") == 1.5

def test_invalid_timeout():
    with pytest.raises(argparse.ArgumentTypeError):
        valid_timeout("0.05")
    with pytest.raises(argparse.ArgumentTypeError):
        valid_timeout("61")
