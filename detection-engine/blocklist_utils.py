import ipaddress
import re
from datetime import datetime, timedelta, timezone
METADATA_SERVICE_CIDR = "169.254.169.254/32"

DESCRIPTION_PREFIX = "auto-blocked"
DESCRIPTION_RE = re.compile(
    r"^auto-blocked;blocked_at=(?P<blocked_at>[^;]+);expiry=(?P<expiry>[^;]+);reason=(?P<reason>.+)$"
)


def build_description(blocked_at, expiry, reason):
    return (
        f"{DESCRIPTION_PREFIX};blocked_at={blocked_at.isoformat()};"
        f"expiry={expiry.isoformat()};reason={reason}"
    )


def parse_description(description):
    if not description:
        return None
    match = DESCRIPTION_RE.match(description)
    if not match:
        return None
    try:
        blocked_at = datetime.fromisoformat(match.group("blocked_at"))
        expiry = datetime.fromisoformat(match.group("expiry"))
    except ValueError:
        return None
    return {
        "blocked_at": blocked_at,
        "expiry": expiry,
        "reason": match.group("reason"),
    }


def compute_expiry(duration_minutes, now=None):
    now = now or datetime.now(timezone.utc)
    return now, now + timedelta(minutes=duration_minutes)


def is_whitelisted(ip, whitelist_cidrs):
    try:
        candidate = ipaddress.ip_address(ip)
    except ValueError:
        return True

    all_cidrs = list(whitelist_cidrs) + [METADATA_SERVICE_CIDR]
    for cidr in all_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if candidate in network:
            return True
    return False
