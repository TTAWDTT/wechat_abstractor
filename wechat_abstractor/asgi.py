"""ASGI config for wechat_abstractor project."""
from __future__ import annotations

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "wechat_abstractor.settings")

application = get_asgi_application()
