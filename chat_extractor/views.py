from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime
from io import StringIO
from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .forms import ExtractionForm
from .services import wechat_crypto, wechat_process
from .services.extractor import ExtractionError, ExtractionService

SERVICE = ExtractionService()


@require_http_methods(["GET", "POST"])
def index(request: HttpRequest) -> HttpResponse:
    form = ExtractionForm(request.POST or None)
    context: dict[str, Any] = {
        "form": form,
        "results": [],
        "stats": None,
        "threads": [],
        "error": None,
        "detected_keys": [],
        "sqlcipher_ready": wechat_crypto.HAS_PYCRYPTODOME,
        "is_windows": os.name == "nt",
        "has_psutil": wechat_process.HAS_PSUTIL,
    }

    if request.method == "POST":
        if form.is_valid():
            filters = form.to_filters()
            try:
                extraction = SERVICE.extract(filters)
            except ExtractionError as exc:
                context["error"] = str(exc)
            else:
                context["results"] = [message.to_dict() for message in extraction.messages]
                context["stats"] = asdict(extraction.stats)
                context["threads"] = [group.to_dict() for group in extraction.grouped_threads]
        else:
            context["error"] = "表单校验失败，请检查输入项。"
    else:
        context["results"] = []

    context["detected_keys"] = SERVICE.available_wechat_keys()

    return render(request, "chat_extractor/index.html", context)


@require_http_methods(["POST"])
def preview(request: HttpRequest) -> JsonResponse:
    form = ExtractionForm(request.POST)
    if not form.is_valid():
        return JsonResponse({"errors": form.errors}, status=400, json_dumps_params={"ensure_ascii": False})

    filters = form.to_filters()
    filters.limit = min(filters.limit, 50)  # 限制预览请求的返回条数
    try:
        extraction = SERVICE.extract(filters)
    except ExtractionError as exc:
        return JsonResponse({"error": str(exc)}, status=400, json_dumps_params={"ensure_ascii": False})

    payload = {
        "messages": [message.to_dict() for message in extraction.messages],
        "stats": asdict(extraction.stats),
        "threads": [group.to_dict() for group in extraction.grouped_threads],
    }
    return JsonResponse(payload, json_dumps_params={"ensure_ascii": False})


@require_http_methods(["POST"])
def export_text(request: HttpRequest) -> HttpResponse:
    form = ExtractionForm(request.POST)
    if not form.is_valid():
        return JsonResponse({"errors": form.errors}, status=400, json_dumps_params={"ensure_ascii": False})

    filters = form.to_filters()
    filters.limit = min(filters.limit, 10000)
    try:
        extraction = SERVICE.extract(filters)
    except ExtractionError as exc:
        return JsonResponse({"error": str(exc)}, status=400, json_dumps_params={"ensure_ascii": False})

    buffer = StringIO()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    buffer.write("微信聊天记录导出\n")
    buffer.write(f"导出时间: {now_str}\n")
    buffer.write(f"来源目录: {filters.base_dir}\n")
    buffer.write(f"消息条数: {len(extraction.messages)}\n")

    for group in extraction.grouped_threads:
        buffer.write("\n")
        buffer.write(f"=== 会话: {group.name} ({group.count} 条消息) ===\n")
        for message in group.messages:
            timestamp = _format_timestamp(message.timestamp)
            content = (message.display_content or "").replace("\r", "").replace("\n", " ")
            direction = {
                "outgoing": "(发出)",
                "incoming": "(接收)",
            }.get(message.direction, "")
            label = message.display_type or message.message_type
            buffer.write(f"[{timestamp}] {message.sender}{direction} [{label}]: {content}\n")

    filename = datetime.now().strftime("wechat_export_%Y%m%d_%H%M%S.txt")
    response = HttpResponse(buffer.getvalue(), content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f"attachment; filename={filename}"
    return response


def _format_timestamp(value: datetime | None) -> str:
    if not value:
        return "未知时间"
    normalized = value.astimezone() if value.tzinfo else value
    return normalized.strftime("%Y-%m-%d %H:%M:%S")
