"""WSGI config for wechat_abstractor project."""
from __future__ import annotations

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "wechat_abstractor.settings")

application = get_wsgi_application()
