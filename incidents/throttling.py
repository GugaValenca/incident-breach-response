"""Who is "one visitor" for rate limiting.

Behind Vercel's proxy, REMOTE_ADDR identifies the platform, not the
visitor — every request could share one budget. Vercel instead puts the
client's public IP in X-Real-IP (identical to X-Forwarded-For), overwriting
any value the client sent, "to prevent IP spoofing"
(https://vercel.com/docs/headers/request-headers, checked 2026-09-26).

That guarantee only holds on Vercel. Anywhere else a client can set the
header to anything, so it's ignored and REMOTE_ADDR is used instead.
"""

from django.conf import settings
from django.http import HttpRequest


def client_ip(group: str, request: HttpRequest) -> str:
    """Rate-limit key function (django-ratelimit's `key=` callable)."""
    if settings.RUNNING_ON_VERCEL:
        forwarded = request.META.get("HTTP_X_REAL_IP", "").strip()
        if forwarded:
            return forwarded
    return request.META.get("REMOTE_ADDR", "")
