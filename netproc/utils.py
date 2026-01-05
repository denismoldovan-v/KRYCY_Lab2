from datetime import datetime, timezone


def ms_to_dt(ms: int):
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%H:%M:%S")
    except Exception:
        return "?"
