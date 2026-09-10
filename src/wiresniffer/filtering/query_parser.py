"""Structured query parser and evaluator for transaction filtering."""

from typing import Any

from wiresniffer.decoders.base import HttpTransaction


def get_nested_key(data: Any, path: str) -> Any:
    """Retrieve value from nested dictionary using dot notation (e.g. data.user.id)."""
    parts = path.split(".")
    curr = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


class FilterPredicate:
    """Evaluates an HttpTransaction against structured filter conditions."""

    def __init__(self, raw_query: str) -> None:
        self.raw_query = raw_query.strip()
        self.terms = [t for t in self.raw_query.split() if t]

    def matches(self, tx: HttpTransaction) -> bool:
        """Return True if transaction satisfies all terms in the query."""
        if not self.terms:
            return True

        for term in self.terms:
            if not self._evaluate_term(term, tx):
                return False
        return True

    def _evaluate_term(self, term: str, tx: HttpTransaction) -> bool:
        term_lower = term.lower()

        # 1. Status Filter (e.g. status:200, status:4xx, status:>=400, status:<300)
        if term_lower.startswith("status:"):
            cond = term_lower[7:].strip()
            status = tx.response_status or 0
            if cond == "2xx":
                return 200 <= status < 300
            elif cond == "3xx":
                return 300 <= status < 400
            elif cond == "4xx":
                return 400 <= status < 500
            elif cond == "5xx":
                return 500 <= status < 600
            elif cond.startswith(">="):
                try:
                    return status >= int(cond[2:])
                except ValueError:
                    return False
            elif cond.startswith("<="):
                try:
                    return status <= int(cond[2:])
                except ValueError:
                    return False
            elif cond.startswith(">"):
                try:
                    return status > int(cond[1:])
                except ValueError:
                    return False
            elif cond.startswith("<"):
                try:
                    return status < int(cond[1:])
                except ValueError:
                    return False
            else:
                try:
                    return status == int(cond)
                except ValueError:
                    return False

        # 2. Latency Filter (e.g. latency:>200, latency:>500ms, latency:<50)
        if term_lower.startswith("latency:"):
            cond = term_lower[8:].replace("ms", "").strip()
            latency = tx.latency_ms or 0.0
            if cond.startswith(">="):
                try:
                    return latency >= float(cond[2:])
                except ValueError:
                    return False
            elif cond.startswith(">"):
                try:
                    return latency > float(cond[1:])
                except ValueError:
                    return False
            elif cond.startswith("<="):
                try:
                    return latency <= float(cond[2:])
                except ValueError:
                    return False
            elif cond.startswith("<"):
                try:
                    return latency < float(cond[1:])
                except ValueError:
                    return False
            return False

        # 3. Method Filter (e.g. method:POST, method:GET)
        if term_lower.startswith("method:"):
            val = term_lower[7:].upper()
            return tx.method.upper() == val

        # 4. Protocol Filter (e.g. proto:http2, proto:ws, proto:grpc)
        if term_lower.startswith("proto:"):
            val = term_lower[6:]
            return val in tx.protocol.value.lower()

        # 5. Header Filter (e.g. header:auth or header:content-type=application/json)
        if term_lower.startswith("header:"):
            sub = term_lower[7:]
            if "=" in sub:
                hk, hv = sub.split("=", 1)
                for k, v in tx.request_headers.items():
                    if k.lower() == hk and hv in v.lower():
                        return True
                for k, v in tx.response_headers.items():
                    if k.lower() == hk and hv in v.lower():
                        return True
                return False
            else:
                # Header name exists
                return any(sub in k.lower() for k in tx.request_headers) or any(
                    sub in k.lower() for k in tx.response_headers
                )

        # 6. Alert Filter (e.g. alert:any, alert:critical, alert:high)
        if term_lower.startswith("alert:"):
            sub = term_lower[6:].strip()
            if not tx.security_alerts:
                return False
            if sub == "any":
                return True
            return any(a.get("severity", "").lower() == sub for a in tx.security_alerts)

        # 7. JSON Field Filter (e.g. json:user.id=42 or json:status=ok)
        if term_lower.startswith("json:"):
            sub = term_lower[5:]
            if "=" in sub:
                path, expected = sub.split("=", 1)
                for json_obj in (tx.request_json(), tx.response_json()):
                    if json_obj is not None:
                        val = get_nested_key(json_obj, path)
                        if str(val).lower() == expected:
                            return True
                return False
            else:
                for json_obj in (tx.request_json(), tx.response_json()):
                    if json_obj is not None and get_nested_key(json_obj, sub) is not None:
                        return True
                return False

        # 8. General Substring Match across URL, method, path, host, and body
        term_clean = term.lower()
        if (
            term_clean in tx.method.lower()
            or term_clean in tx.path.lower()
            or term_clean in tx.host.lower()
            or (tx.response_status and term_clean in str(tx.response_status))
            or term_clean in tx.protocol.value.lower()
            or term_clean in tx.request_body_text.lower()
            or term_clean in tx.response_body_text.lower()
        ):
            return True

        return False
