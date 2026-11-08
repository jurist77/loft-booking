"""Canonical managed transport; no secrets or inference from request headers."""
import re


def hostname(value):
    if type(value) is not str or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.duckdns\.org", value):
        raise ValueError("INVALID_HTTPS_HOSTNAME")
    return value


def https_settings(state):
    value = (state or {}).get("https")
    if value is None: return None
    if not isinstance(value, dict) or set(value) != {"format", "hostname"} or type(value["format"]) is not int or value["format"] != 1:
        raise ValueError("INVALID_HTTPS_STATE")
    return {"format": 1, "hostname": hostname(value["hostname"])}


def https_origin(settings):
    return "https://" + https_settings({"https": settings})["hostname"]
