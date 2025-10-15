from __future__ import annotations

from dataclasses import asdict
from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .forms import ExtractionForm
from .services.extractor import ExtractionError, ExtractionService

SERVICE = ExtractionService()


@require_http_methods(["GET", "POST"])
def index(request: HttpRequest) -> HttpResponse:
    form = ExtractionForm(request.POST or None)
    context: dict[str, Any] = {"form": form, "results": [], "stats": None, "error": None}

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
        else:
            context["error"] = "表单校验失败，请检查输入项。"
    else:
        context["results"] = []

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
    }
    return JsonResponse(payload, json_dumps_params={"ensure_ascii": False})
