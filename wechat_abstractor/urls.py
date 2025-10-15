"""wechat_abstractor URL Configuration."""
from __future__ import annotations

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("chat_extractor.urls")),
]
