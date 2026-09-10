"""Reproducible cURL command line generator."""

from wiresniffer.decoders.base import HttpTransaction


def generate_curl_command(tx: HttpTransaction) -> str:
    """Generate an executable cURL command replicating the captured request."""
    return tx.to_curl()
