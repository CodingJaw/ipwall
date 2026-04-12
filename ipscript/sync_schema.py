import ipaddress
import json


"""Shared sync contract used by the host orchestrator and remote applier.

Request contract (host -> remote):
  - chain: str
  - target_id: str
  - request_id: str
  - ips: list[str] full desired set

Response contract (remote -> host):
  - ok: bool
  - applied_ips: list[str]
  - missing: list[str]
  - extra: list[str]
  - errors: list[str]
"""

REQUEST_REQUIRED_KEYS = ("chain", "target_id", "request_id", "ips")
RESPONSE_REQUIRED_KEYS = ("ok", "applied_ips", "missing", "extra", "errors")

REQUEST_SCHEMA = {
    "type": "object",
    "required": list(REQUEST_REQUIRED_KEYS),
    "additionalProperties": False,
    "properties": {
        "chain": {"type": "string", "minLength": 1},
        "target_id": {"type": "string", "minLength": 1},
        "request_id": {"type": "string", "minLength": 1},
        "ips": {"type": "array", "items": {"type": "string"}},
    },
}

RESPONSE_SCHEMA = {
    "type": "object",
    "required": list(RESPONSE_REQUIRED_KEYS),
    "additionalProperties": False,
    "properties": {
        "ok": {"type": "boolean"},
        "applied_ips": {"type": "array", "items": {"type": "string"}},
        "missing": {"type": "array", "items": {"type": "string"}},
        "extra": {"type": "array", "items": {"type": "string"}},
        "errors": {"type": "array", "items": {"type": "string"}},
    },
}


def normalize_ip_list(values):
    normalized = []
    for value in values:
        normalized.append(str(ipaddress.ip_address(value)))
    return sorted(set(normalized))


def _validate_exact_keys(payload, required_keys, object_name):
    if not isinstance(payload, dict):
        return [f"{object_name} must be a JSON object"]

    errors = []
    payload_keys = set(payload)
    required = set(required_keys)

    missing = sorted(required - payload_keys)
    if missing:
        errors.append(f"{object_name} missing required keys: {missing}")

    extra = sorted(payload_keys - required)
    if extra:
        errors.append(f"{object_name} has unexpected keys: {extra}")

    return errors


def parse_remote_request(stdin_text):
    try:
        payload = json.loads(stdin_text)
    except Exception as exc:
        return None, [f"invalid JSON payload: {exc}"]

    errors = _validate_exact_keys(payload, REQUEST_REQUIRED_KEYS, "request payload")
    if errors:
        return None, errors

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

    validation_errors = _validate_exact_keys(parsed, RESPONSE_REQUIRED_KEYS, "response payload")
    if validation_errors:
        return None, "; ".join(validation_errors)

    if not isinstance(parsed["ok"], bool):
        return None, "response payload key 'ok' must be bool"

    for list_key in ("applied_ips", "missing", "extra", "errors"):
        if not isinstance(parsed[list_key], list):
            return None, f"response payload key '{list_key}' must be list"

    if not all(isinstance(error, str) for error in parsed["errors"]):
        return None, "response payload key 'errors' must contain only strings"

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
        "errors": [str(err) for err in errors],
    }


def build_remote_request(chain, target_id, request_id, ips):
    return {
        "chain": str(chain),
        "target_id": str(target_id),
        "request_id": str(request_id),
        "ips": list(ips),
    }
