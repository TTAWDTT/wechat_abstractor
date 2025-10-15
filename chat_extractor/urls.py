from __future__ import annotations

from django.urls import path

from . import views

app_name = "chat_extractor"

urlpatterns = [
    path("", views.index, name="index"),
    path("preview/", views.preview, name="preview"),
    path("export/", views.export_text, name="export"),
]
