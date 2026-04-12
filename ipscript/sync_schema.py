import ipaddress
import json


RESPONSE_KEYS = {
    "ok": bool,
    "applied_ips": list,
    "missing": list,
    "extra": list,
    "errors": list,
}


def normalize_ip_list(values):
    normalized = []
    for value in values:
        normalized.append(str(ipaddress.ip_address(value)))
    return sorted(set(normalized))


def parse_remote_request(stdin_text):
    try:
        payload = json.loads(stdin_text)
    except Exception as exc:
        return None, [f"invalid JSON payload: {exc}"]

    if not isinstance(payload, dict):
        return None, ["payload must be a JSON object"]

    errors = []

    chain = payload.get("chain")
    if not isinstance(chain, str) or not chain.strip():
        errors.append("chain must be a non-empty string")

    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        errors.append("request_id must be a non-empty string")

    target_id = payload.get("target_id")
    if not isinstance(target_id, str) or not target_id.strip():
        errors.append("target_id must be a non-empty string")

    ips = payload.get("ips")
    if not isinstance(ips, list):
        errors.append("ips must be a JSON array")
        ips = []

    normalized_ips = []
    for raw_ip in ips:
        if not isinstance(raw_ip, str):
            errors.append(f"ip must be a string: {raw_ip}")
            continue
        try:
            normalized_ips.append(str(ipaddress.ip_address(raw_ip)))
        except Exception:
            errors.append(f"invalid ip: {raw_ip}")

    return {
        "chain": chain.strip() if isinstance(chain, str) else "",
        "request_id": request_id.strip() if isinstance(request_id, str) else "",
        "target_id": target_id.strip() if isinstance(target_id, str) else "",
        "ips": sorted(set(normalized_ips)),
    }, errors


def parse_remote_response(stdout):
    if not isinstance(stdout, str) or not stdout.strip():
        return None, "remote stdout was empty"

    try:
        parsed = json.loads(stdout)
    except Exception as exc:
        return None, f"remote stdout was not valid JSON: {exc}"

    if not isinstance(parsed, dict):
        return None, "remote JSON response must be an object"

    for key, expected_type in RESPONSE_KEYS.items():
        if key not in parsed:
            return None, f"remote JSON response missing key '{key}'"
        if not isinstance(parsed[key], expected_type):
            return None, f"remote JSON response key '{key}' must be {expected_type.__name__}"

    try:
        parsed["applied_ips"] = normalize_ip_list(parsed.get("applied_ips", []))
        parsed["missing"] = normalize_ip_list(parsed.get("missing", []))
        parsed["extra"] = normalize_ip_list(parsed.get("extra", []))
    except Exception as exc:
        return None, f"remote JSON response has invalid IP lists: {exc}"

    return parsed, None


def build_remote_response(ok, applied_ips, missing, extra, errors):
    return {
        "ok": bool(ok),
        "applied_ips": list(applied_ips),
        "missing": list(missing),
        "extra": list(extra),
        "errors": list(errors),
    }
