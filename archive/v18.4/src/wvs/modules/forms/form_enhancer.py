"""WVS v18 - POST 表单增强模块

增强表单处理能力：
1. 完整提取 hidden 字段（含 value）
2. 支持 textarea/select 默认值
3. 多参数 POST：测试时保留其他表单参数原值
4. 智能填充：为文本字段生成合理默认值
5. 表单分类：识别登录/搜索/评论等表单类型
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Tag


@dataclass
class FormField:
    """表单字段"""
    name: str
    type: str = "text"           # text, hidden, password, textarea, select, checkbox, radio, submit
    value: str = ""
    default_value: str = ""       # 原始默认值（提取时保留）
    options: List[str] = field(default_factory=list)  # select 的选项列表
    is_testable: bool = True      # 是否适合注入测试
    is_required: bool = False


@dataclass
class EnhancedForm:
    """增强型表单"""
    url: str                      # action URL（完整）
    method: str = "POST"
    enctype: str = ""             # multipart/form-data 等
    fields: Dict[str, FormField] = field(default_factory=dict)
    form_type: str = "unknown"    # login, search, comment, contact, custom
    parent_url: str = ""          # 来源页面

    def get_post_data(self, test_field: str = None, test_value: Any = None) -> Dict[str, str]:
        """
        生成 POST 数据

        Args:
            test_field: 正在测试的字段名（会用 test_value 替换）
            test_value: 测试用的 payload 值
        Returns:
            完整的 POST 数据字典，包含所有字段
        """
        data = {}
        for name, f in self.fields.items():
            if name == test_field and test_value is not None:
                data[name] = str(test_value)
            elif f.type == "submit":
                continue  # 提交按钮不发送
            elif f.type == "checkbox" and not f.value:
                continue  # 未选中的 checkbox 不发送
            elif f.default_value:
                data[name] = f.default_value
            elif f.type == "hidden":
                data[name] = f.value
            elif f.type == "select" and f.options:
                data[name] = f.options[0]  # 第一个选项
            else:
                data[name] = f.value or ""
        return data

    def get_testable_fields(self) -> List[str]:
        """获取可测试注入的字段列表"""
        return [name for name, f in self.fields.items() if f.is_testable]


class FormEnhancer:
    """表单增强处理器"""

    # 登录表单特征字段
    LOGIN_FIELD_PATTERNS = [
        r"user(name|_name)?", r"(login|log[_-]?in)", r"email", r"account",
        r"pass(word|_word|phrase)?", r"pwd", r"passwd"
    ]

    # 搜索表单特征
    SEARCH_FIELD_PATTERNS = [
        r"search", r"query", r"q$", r"keyword(s)?", r"find", r"filter"
    ]

    # 评论/内容表单特征
    CONTENT_FIELD_PATTERNS = [
        r"comment", r"message", r"content", r"body", r"description", r"text", r"review",
        r"feedback", r"note", r"remark"
    ]

    def __init__(self):
        self._form_count = 0

    def extract_forms(self, html: str, page_url: str) -> List[EnhancedForm]:
        """
        从 HTML 中完整提取所有表单

        Args:
            html: 页面 HTML
            page_url: 页面 URL（用于解析相对 action）
        Returns:
            增强型表单列表
        """
        forms = []
        soup = BeautifulSoup(html, "html.parser")

        for form_tag in soup.find_all("form"):
            self._form_count += 1
            form = self._parse_form(form_tag, page_url)
            if form and form.fields:
                forms.append(form)

        return forms

    def _parse_form(self, form_tag: Tag, page_url: str) -> Optional[EnhancedForm]:
        """解析单个 form 标签"""
        # 提取 action
        action = form_tag.get("action", "")
        if not action:
            action = page_url  # 空 action = 当前页面
        else:
            action = urljoin(page_url, action)

        method = form_tag.get("method", "POST").upper()
        enctype = form_tag.get("enctype", "")

        # 提取所有字段
        fields = self._extract_fields(form_tag)

        if not fields:
            return None

        # 分类表单类型
        form_type = self._classify_form(fields)

        return EnhancedForm(
            url=action,
            method=method,
            enctype=enctype,
            fields=fields,
            form_type=form_type,
            parent_url=page_url
        )

    def _extract_fields(self, form_tag: Tag) -> Dict[str, FormField]:
        """从 form 标签提取所有字段（完整版）"""
        fields = {}

        # 1. input 标签（含 hidden）
        for input_tag in form_tag.find_all("input"):
            name = input_tag.get("name")
            if not name:
                continue

            input_type = input_tag.get("type", "text").lower()
            value = input_tag.get("value", "")

            # 判断是否可测试（注入测试）
            is_testable = input_type in (
                "text", "search", "url", "tel", "email", "hidden",
                "password", "number", "date", "datetime", "datetime-local",
                "month", "week", "time", "color", "range"
            )

            is_required = input_tag.has_attr("required")

            # checkbox 特殊处理
            if input_type == "checkbox":
                is_testable = True
                checked = input_tag.has_attr("checked")
                value = input_tag.get("value", "on")
                if not checked:
                    value = ""  # 未选中

            # radio 特殊处理
            if input_type == "radio":
                is_testable = True
                checked = input_tag.has_attr("checked")
                # radio 同名只保留选中的
                if checked:
                    fields[name] = FormField(
                        name=name,
                        type=input_type,
                        value=value,
                        default_value=value,
                        is_testable=True
                    )
                continue

            fields[name] = FormField(
                name=name,
                type=input_type,
                value=value,
                default_value=value,
                is_testable=is_testable,
                is_required=is_required
            )

        # 2. textarea 标签
        for textarea in form_tag.find_all("textarea"):
            name = textarea.get("name")
            if not name:
                continue

            value = textarea.string or ""
            required = textarea.has_attr("required")

            fields[name] = FormField(
                name=name,
                type="textarea",
                value=value.strip(),
                default_value=value.strip(),
                is_testable=True,
                is_required=required
            )

        # 3. select 标签
        for select in form_tag.find_all("select"):
            name = select.get("name")
            if not name:
                continue

            options = []
            default_value = ""
            for opt in select.find_all("option"):
                opt_value = opt.get("value", opt.string or "")
                if opt_value is None:
                    opt_value = ""
                options.append(opt_value)
                if opt.has_attr("selected"):
                    default_value = opt_value

            if not default_value and options:
                default_value = options[0]

            required = select.has_attr("required")

            fields[name] = FormField(
                name=name,
                type="select",
                value=default_value,
                default_value=default_value,
                options=options,
                is_testable=True,
                is_required=required
            )

        # 4. button 标签（type=submit 作为 submit 字段）
        for button in form_tag.find_all("button"):
            name = button.get("name")
            if not name:
                continue
            btn_type = button.get("type", "submit").lower()
            if btn_type == "submit":
                value = button.string or button.get("value", "Submit")
                fields[name] = FormField(
                    name=name,
                    type="submit",
                    value=value.strip(),
                    default_value=value.strip(),
                    is_testable=False
                )

        return fields

    def _classify_form(self, fields: Dict[str, FormField]) -> str:
        """分类表单类型"""
        field_names_lower = [name.lower() for name in fields.keys()]

        # 登录表单：同时有 user + password
        has_user = any(
            any(re.search(pat, name, re.IGNORECASE) for pat in self.LOGIN_FIELD_PATTERNS)
            for name in field_names_lower
        )
        has_pass = any(re.search(r"pass(word|_word|phrase)?|pwd", name, re.IGNORECASE)
                       for name in field_names_lower)

        if has_user and has_pass:
            return "login"

        # 搜索表单
        is_search = any(
            any(re.search(pat, name, re.IGNORECASE) for pat in self.SEARCH_FIELD_PATTERNS)
            for name in field_names_lower
        )
        if is_search:
            return "search"

        # 评论/内容表单
        is_content = any(
            any(re.search(pat, name, re.IGNORECASE) for pat in self.CONTENT_FIELD_PATTERNS)
            for name in field_names_lower
        )
        if is_content:
            return "comment"

        # 文件上传
        has_file = any(f.type == "file" for f in fields.values())
        if has_file:
            return "upload"

        return "custom"

    def classify_from_raw_forms(self, raw_forms: List[Dict]) -> List[EnhancedForm]:
        """
        将旧版爬虫提取的表单（Dict 格式）转换为 EnhancedForm

        Args:
            raw_forms: 旧版格式 [{"url": str, "method": str, "inputs": {name: {type, value}}, "parent": str}]
        Returns:
            EnhancedForm 列表
        """
        enhanced = []
        for raw in raw_forms:
            fields = {}
            for name, info in raw.get("inputs", {}).items():
                input_type = info.get("type", "text")
                value = info.get("value", "")
                fields[name] = FormField(
                    name=name,
                    type=input_type,
                    value=value,
                    default_value=value,
                    is_testable=input_type not in ("submit", "button", "image", "reset", "file")
                )

            form_type = self._classify_form(fields)
            enhanced.append(EnhancedForm(
                url=raw.get("url", ""),
                method=raw.get("method", "POST"),
                fields=fields,
                form_type=form_type,
                parent_url=raw.get("parent", "")
            ))

        return enhanced
