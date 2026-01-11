import time
import requests


_CACHE = {}
_CACHE_TTL = 24 * 3600


def _cache_get(key):
    v = _CACHE.get(key)
    if not v:
        return None
    if time.time() - v["ts"] > _CACHE_TTL:
        return None
    return v["data"]


def _cache_set(key, data):
    _CACHE[key] = {"ts": time.time(), "data": data}


def geo_ip(ip: str):
    if not ip:
        return None
    cached = _cache_get(ip)
    if cached:
        return cached

    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,query"
    try:
        r = requests.get(url, timeout=4)
        data = r.json()
        if data.get("status") != "success":
            return None
        _cache_set(ip, data)
        return data
    except Exception:
        return None


def enrich_suspicious_ips(alerts):
    ips = set()
    for a in alerts:
        if a.get("src_ip"):
            ips.add(a["src_ip"])
        if a.get("dst_ip"):
            ips.add(a["dst_ip"])

    out = {}
    for ip in sorted(ips):
        out[ip] = {"geo": geo_ip(ip)}
    return out
