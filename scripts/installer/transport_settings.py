"""Canonical managed transport; no secrets or inference from request headers."""
import re


def hostname(value):
    # Canonical ASCII FQDN only: safe in DNS, TLS/SNI, Origin and managed JSON.
    # Provider-independent; public resolution/IP ownership is checked separately.
    if type(value) is not str or not 3 <= len(value) <= 253:
        raise ValueError("INVALID_HTTPS_HOSTNAME")
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("INVALID_HTTPS_HOSTNAME")
    if not re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}", labels[-1]):
        raise ValueError("INVALID_HTTPS_HOSTNAME")
    if labels[-1] in {"local", "localhost", "internal", "invalid", "test", "example", "onion"} or value == "home.arpa" or value.endswith(".home.arpa"):
        raise ValueError("INVALID_HTTPS_HOSTNAME")
    try:
        for label in labels:
            if label.startswith("xn--") and label.encode("ascii").decode("idna").encode("idna").decode("ascii") != label:
                raise ValueError("INVALID_HTTPS_HOSTNAME")
    except UnicodeError:
        raise ValueError("INVALID_HTTPS_HOSTNAME") from None
    return value


def https_settings(state):
    value = (state or {}).get("https")
    if value is None: return None
    if not isinstance(value, dict) or set(value) != {"format", "hostname"} or type(value["format"]) is not int or value["format"] != 1:
        raise ValueError("INVALID_HTTPS_STATE")
    return {"format": 1, "hostname": hostname(value["hostname"])}


def https_origin(settings):
    return "https://" + https_settings({"https": settings})["hostname"]
