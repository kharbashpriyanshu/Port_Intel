import socket
from unittest.mock import MagicMock, patch

from portintel.scanner.tcp_udp import scan_range_threaded


@patch("portintel.scanner.tcp_udp.socket.socket")
def test_scan_tcp_open_port(mock_socket):
    # Mocking socket connection to simulate an open port
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.connect_ex.return_value = 0  # 0 means success/open

    results = scan_range_threaded("127.0.0.1", 80, 80, threads=1, timeout=1.0, is_udp=False)

    assert len(results) == 1
    assert results[0].port == 80
    assert results[0].status == "OPEN"
    mock_sock_instance.connect_ex.assert_called_with(("127.0.0.1", 80))

@patch("portintel.scanner.tcp_udp.socket.socket")
def test_scan_tcp_closed_port(mock_socket):
    # Mocking socket connection to simulate a closed port
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.connect_ex.return_value = 111  # non-zero means closed

    results = scan_range_threaded("127.0.0.1", 81, 81, threads=1, timeout=1.0, is_udp=False)

    assert len(results) == 0

@patch("portintel.scanner.tcp_udp.socket.socket")
def test_scan_udp_port(mock_socket):
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.recvfrom.return_value = (b"response", ("127.0.0.1", 53))

    results = scan_range_threaded("127.0.0.1", 53, 53, threads=1, timeout=1.0, is_udp=True)

    assert len(results) == 1
    assert results[0].port == 53
    assert results[0].status == "OPEN"

@patch("portintel.scanner.tcp_udp.socket.socket")
def test_scan_timeout_exception(mock_socket):
    # If a socket throws an exception, it should be caught and treated as closed
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.connect_ex.side_effect = socket.timeout("Timed out")

    results = scan_range_threaded("127.0.0.1", 443, 443, threads=1, timeout=0.1, is_udp=False)
    assert len(results) == 0
