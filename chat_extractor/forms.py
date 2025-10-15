from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from django import forms

DATE_INPUT_FORMATS = [
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",
    "%Y.%m.%d %H:%M",
    "%Y.%m.%d",
]

MESSAGE_TYPE_CHOICES: tuple[tuple[str, str], ...] = (
    ("text", "文本"),
    ("image", "图片"),
    ("video", "视频"),
    ("voice", "语音"),
    ("file", "文件"),
    ("system", "系统"),
)


@dataclass
class ParsedFilters:
    base_dir: Path
    contacts: list[str]
    limit: int
    start_time: datetime | None
    end_time: datetime | None
    message_types: list[str]
    include_subdirectories: bool
    wechat_db_key: str | None = None


class ExtractionForm(forms.Form):
    base_dir = forms.CharField(
        label="消息文件目录",
        max_length=500,
        help_text="输入包含微信 .msg/.db 文件的文件夹路径。",
        widget=forms.TextInput(
            attrs={
                "placeholder": r"例如: C:\\Users\\你\\Documents\\WeChat\\Msg",
                "class": "form-control",
            }
        ),
    )
    contacts = forms.CharField(
        label="聊天对象 (可选)",
        required=False,
        help_text="支持多个姓名或微信号，使用逗号分隔。",
        widget=forms.TextInput(
            attrs={
                "placeholder": "张三, 李四",
                "class": "form-control",
            }
        ),
    )
    message_types = forms.MultipleChoiceField(
        label="消息类型 (可选)",
        required=False,
        choices=MESSAGE_TYPE_CHOICES,
        help_text="未勾选则返回所有类型。",
        widget=forms.CheckboxSelectMultiple,
    )
    custom_message_types = forms.CharField(
        label="自定义类型 (可选)",
        required=False,
        help_text="额外的消息类型关键字，使用逗号分隔。",
        widget=forms.TextInput(
            attrs={"placeholder": "Location, Sticker", "class": "form-control"}
        ),
    )
    limit = forms.IntegerField(
        label="最大条数",
        min_value=1,
        max_value=5000,
        initial=200,
        help_text="限制返回的消息数量，避免一次性加载过多数据。",
        widget=forms.NumberInput(attrs={"class": "form-control"}),
    )
    start_time = forms.DateTimeField(
        label="开始时间",
        required=False,
        input_formats=DATE_INPUT_FORMATS,
        widget=forms.TextInput(
            attrs={"placeholder": "2024-01-01 00:00", "class": "form-control"}
        ),
    )
    end_time = forms.DateTimeField(
        label="结束时间",
        required=False,
        input_formats=DATE_INPUT_FORMATS,
        widget=forms.TextInput(
            attrs={"placeholder": "2024-12-31 23:59", "class": "form-control"}
        ),
    )
    include_subdirectories = forms.BooleanField(
        label="包含子目录",
        required=False,
        initial=True,
    )
    wechat_db_key = forms.CharField(
        label="数据库密钥 (可选)",
        required=False,
        help_text="当数据库为 SQLCipher 加密时，可直接输入 64 位十六进制密钥。留空将尝试自动获取。",
        widget=forms.TextInput(
            attrs={"placeholder": "82b1a2…", "class": "form-control"}
        ),
    )

    def clean_base_dir(self) -> str:
        raw_path = self.cleaned_data["base_dir"].strip()
        base_path = Path(raw_path).expanduser().resolve()
        if not base_path.exists():
            raise forms.ValidationError("目录不存在，请确认路径是否正确。")
        if not base_path.is_dir():
            raise forms.ValidationError("提供的路径不是文件夹，请输入目录路径。")
        self.cleaned_data["base_dir"] = str(base_path)
        return self.cleaned_data["base_dir"]

    def clean(self) -> dict[str, object]:
        cleaned = super().clean()
        start_time = cleaned.get("start_time")
        end_time = cleaned.get("end_time")
        if start_time and end_time and start_time > end_time:
            raise forms.ValidationError("开始时间不能晚于结束时间。")
        return cleaned

    def get_message_types(self) -> list[str]:
        selected: list[str] = list(self.cleaned_data.get("message_types") or [])
        extras: Iterable[str] = []
        custom = self.cleaned_data.get("custom_message_types")
        if custom:
            extras = [item.strip() for item in custom.split(",") if item.strip()]
        return list(dict.fromkeys([*selected, *extras]))

    def get_contacts(self) -> list[str]:
        raw_contacts = self.cleaned_data.get("contacts")
        if not raw_contacts:
            return []
        return [item.strip() for item in raw_contacts.split(",") if item.strip()]

    def to_filters(self) -> ParsedFilters:
        if not self.is_valid():  # Guard for misuse
            raise ValueError("Form must be valid before converting filters.")
        return ParsedFilters(
            base_dir=Path(self.cleaned_data["base_dir"]),
            contacts=self.get_contacts(),
            limit=self.cleaned_data["limit"],
            start_time=self.cleaned_data.get("start_time"),
            end_time=self.cleaned_data.get("end_time"),
            message_types=self.get_message_types(),
            include_subdirectories=self.cleaned_data.get("include_subdirectories", True),
            wechat_db_key=self.cleaned_data.get("wechat_db_key") or None,
        )
