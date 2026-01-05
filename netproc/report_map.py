import os
import folium


def build_map_optional(out_dir, alerts, enrichment):
    pts = []
    for a in alerts:
        ip = a.get("dst_ip") or a.get("src_ip")
        if not ip:
            continue
        geo = (enrichment or {}).get(ip, {}).get("geo")
        if not geo:
            continue
        lat = geo.get("lat")
        lon = geo.get("lon")
        if lat is None or lon is None:
            continue
        pts.append((lat, lon, ip, a.get("rule_id")))

    if not pts:
        return None

    m = folium.Map(location=[pts[0][0], pts[0][1]], zoom_start=3)
    for lat, lon, ip, rid in pts[:500]:
        folium.Marker([lat, lon], popup=f"{ip} {rid}").add_to(m)

    out_html = os.path.join(out_dir, "map.html")
    m.save(out_html)
    return out_html
