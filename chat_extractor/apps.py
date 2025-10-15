from __future__ import annotations

from django.apps import AppConfig


class ChatExtractorConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "chat_extractor"
    verbose_name = "微信聊天提取"
