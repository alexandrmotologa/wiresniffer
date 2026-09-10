"""Unit tests for transaction replay engine and diff calculator."""

import io
import urllib.error
from unittest.mock import MagicMock, patch

from wiresniffer.decoders.base import HttpTransaction, ProtocolType
from wiresniffer.replay.diff import calculate_transaction_diff, format_diff_markup
from wiresniffer.replay.engine import replay_transaction


def test_calculate_transaction_diff_identical():
    tx1 = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"status": "ok"}',
    )
    tx2 = HttpTransaction(
        timestamp=105.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=200,
        response_headers={"content-type": "application/json"},
        response_body=b'{"status": "ok"}',
    )

    diff = calculate_transaction_diff(tx1, tx2)
    assert diff.is_identical is True
    assert diff.status_changed is False
    markup = format_diff_markup(diff)
    assert "identical" in markup.lower()


def test_calculate_transaction_diff_changes():
    tx1 = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=200,
        response_headers={"content-type": "application/json", "x-old": "1"},
        response_body=b'{"count": 1}',
    )
    tx2 = HttpTransaction(
        timestamp=105.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        response_status=500,
        response_headers={"content-type": "application/json", "x-new": "2"},
        response_body=b'{"count": 2}',
    )

    diff = calculate_transaction_diff(tx1, tx2)
    assert diff.is_identical is False
    assert diff.status_changed is True
    assert "x-new" in diff.headers_added
    assert "x-old" in diff.headers_removed
    assert len(diff.body_diff_lines) > 0

    markup = format_diff_markup(diff)
    assert "Status Code Changed" in markup
    assert "x-new" in markup


@patch("urllib.request.urlopen")
def test_replay_transaction_success(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.reason = "OK"
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.read.return_value = b'{"replayed": true}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="GET",
        path="/api/test",
        request_headers={"host": "example.com", "accept": "application/json"},
    )

    replayed = replay_transaction(tx, url_override="http://127.0.0.1:8080/api/test")
    assert replayed.response_status == 200
    assert replayed.response_body == b'{"replayed": true}'
    assert replayed.latency_ms is not None
    assert mock_urlopen.called


@patch("urllib.request.urlopen")
def test_replay_transaction_http_error(mock_urlopen):
    err = urllib.error.HTTPError(
        url="http://example.com/api/test",
        code=404,
        msg="Not Found",
        hdrs={"Content-Type": "text/plain"},
        fp=io.BytesIO(b"Resource missing"),
    )
    mock_urlopen.side_effect = err

    tx = HttpTransaction(
        timestamp=100.0,
        protocol=ProtocolType.HTTP1,
        client_endpoint=("127.0.0.1", 1000),
        server_endpoint=("127.0.0.1", 80),
        method="GET",
        path="/api/test",
        request_headers={"host": "example.com"},
    )

    replayed = replay_transaction(tx)
    assert replayed.response_status == 404
    assert replayed.response_body == b"Resource missing"
