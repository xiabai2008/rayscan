"""
RayScan Web UI (Flask + SSE 实时日志) — v2.3 T3.5

HTTP 层:路由 / 鉴权 / CSRF / 序列化。
业务逻辑:web_ui.payloads(请求 → 配置)、web_ui.sessions(扫描/被动会话)。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets  # noqa: E402
import threading  # noqa: E402
from datetime import datetime  # noqa: E402
from pathlib import Path  # noqa: E402

from flask import (  # noqa: E402
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    session,
    stream_with_context,
)

from web_ui import payloads, sessions  # noqa: E402
from wvs import __version__  # noqa: E402
from wvs.config import ConfigManager  # noqa: E402
from wvs.plugins.auth import AuthManager, configure_from_options  # noqa: E402
from wvs.profiles import ProfileManager  # noqa: E402

app = Flask(__name__)

# ── 鉴权 + CSRF 配置 ──
# SECRET_KEY：必需（生产环境请用环境变量覆盖）。仅在缺失时给一个进程内随机值，
# 这意味着每次重启会让已有 session 失效 — 配合 CSRF 重新签发即可。
_app_secret = os.environ.get("RAYSCAN_WEB_SECRET")
if _app_secret:
    app.secret_key = _app_secret
else:
    app.secret_key = secrets.token_hex(32)
    print(
        "[WARN] 未设置 RAYSCAN_WEB_SECRET；Web UI 使用进程内随机 secret key。"
        "重启后所有 session/CSRF token 失效。生产请设置该环境变量。"
    )

# 简单的 API token（与登录 session 二选一）。默认生成一个并打印到终端，
# 用户可以 RAYSCAN_WEB_TOKEN=xxx 覆盖。
_DEFAULT_TOKEN = secrets.token_urlsafe(24)
API_TOKEN = os.environ.get("RAYSCAN_WEB_TOKEN") or _DEFAULT_TOKEN
print(f"[INFO] RayScan Web UI API token (header 'X-Api-Token'): {API_TOKEN}")
print("[INFO] 访问 /login 页面用此 token 登录；或 curl 调用时带 X-Api-Token。")

# 仓库根与 scan_reports 目录（queue_out 白名单）
REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = (REPO_ROOT / "scan_reports").resolve()

# 全局会话 + Profile 管理器（测试可 monkeypatch）
scan_session = sessions.ScanSession()
passive_session = sessions.PassiveProxySession()
_profile_manager = ProfileManager()

# 扫描历史存储
SCAN_HISTORY: list = []
_HISTORY_LOCK = threading.Lock()


def _is_authorized() -> bool:
    """校验当前请求是否已通过鉴权（session 或 API token 任一即可）"""
    if session.get("authenticated"):
        return True
    token = request.headers.get("X-Api-Token", "")
    if token and secrets.compare_digest(token, API_TOKEN):
        return True
    return False


def _get_or_create_csrf_token() -> str:
    """返回当前 session 的 CSRF token（缺失时生成）"""
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _require_csrf():
    """校验 POST/PUT/DELETE 是否带有效 CSRF token（API token 用户不受限）"""
    if request.headers.get("X-Api-Token") and secrets.compare_digest(request.headers.get("X-Api-Token", ""), API_TOKEN):
        return  # API token 用户已通过 _is_authorized，跳过 CSRF
    sent = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if not expected or not sent or not secrets.compare_digest(sent, expected):
        abort(403, description="CSRF token missing or invalid")


def _resolve_queue_out(raw) -> Path:
    """校验 queue_out 位于 scan_reports/ 下（防任意文件写）。"""
    value = (str(raw).strip() if raw else "") or "scan_reports/proxy_queue.json"
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = (REPORTS_DIR / candidate) if candidate.parent == Path(".") else (REPO_ROOT / candidate)
    resolved = candidate.resolve()
    if resolved != REPORTS_DIR and REPORTS_DIR not in resolved.parents:
        raise ValueError("queue_out 必须是 scan_reports/ 下的路径")
    return resolved


# ── 路由 ──


@app.route("/")
def index():
    if not _is_authorized():
        return _redirect_to_login()
    return render_template("index.html", csrf_token=_get_or_create_csrf_token(), version=__version__)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        submitted = (request.form.get("token") or "").strip()
        if submitted and secrets.compare_digest(submitted, API_TOKEN):
            session["authenticated"] = True
            return _redirect_to_index()
        return render_template("login.html", error="Token 无效"), 401
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return _redirect_to_login()


def _redirect_to_login():
    from flask import redirect, url_for

    return redirect(url_for("login"))


def _redirect_to_index():
    from flask import redirect, url_for

    return redirect(url_for("index"))


@app.route("/api/modules")
def api_modules():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return jsonify({"modules": payloads.module_catalog()})


@app.route("/api/profiles", methods=["GET"])
def api_profiles():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return jsonify({"profiles": _profile_manager.list_profiles()})


@app.route("/api/profiles/<name>", methods=["GET"])
def api_profile_detail(name):
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    profile = _profile_manager.load_profile(name)
    if profile is None:
        return jsonify({"error": "profile 不存在"}), 404
    builtin = any(p["name"] == name and p.get("builtin") for p in _profile_manager.list_profiles())
    return jsonify(
        {
            "name": name,
            "description": profile.get("description", ""),
            "builtin": builtin,
            "modules": profile.get("modules", {}),
            "params": profile.get("params", {}),
        }
    )


@app.route("/api/profiles", methods=["POST"])
def api_profile_save():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "请输入 Profile 名称"}), 400
    builtin_names = {p["name"] for p in _profile_manager.list_profiles() if p.get("builtin")}
    if name in builtin_names:
        return jsonify({"error": f"'{name}' 是内置 Profile，请换一个名称"}), 409
    profile = {
        "name": name,
        "description": data.get("description", ""),
        "modules": data.get("modules") or {"enabled": [], "disabled": []},
        "params": data.get("params") or {},
    }
    try:
        path = _profile_manager.save_profile(name, profile)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"status": "saved", "path": str(path)})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    if scan_session.scanning:
        return jsonify({"error": "已有扫描正在运行"}), 400

    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "请输入 URL"}), 400

    try:
        config = ConfigManager()
        profile_name = payloads.apply_scan_config(config, data, _profile_manager)
        modules = payloads.resolve_scan_modules(data, profile_name, _profile_manager)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    auth_payload = data.get("auth") or {}
    if auth_payload:
        ok, err = configure_from_options(AuthManager(config), auth_payload)
        if not ok:
            return jsonify({"error": err}), 400

    from_proxy_path = None
    if data.get("from_proxy"):
        from_proxy_path = passive_session.queue_path
        if not from_proxy_path or not Path(from_proxy_path).exists():
            return jsonify({"error": "没有可用的被动捕获队列，请先在「被动捕获」启动代理"}), 400

    def _on_finish(result, elapsed, _payload):
        _record_scan(url, result.vulnerabilities if result else [], elapsed)

    scan_session.start(
        data,
        config,
        modules,
        from_proxy_queue_path=from_proxy_path,
        on_finish=_on_finish,
    )
    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    scan_session.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/stream")
def api_stream():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return Response(
        stream_with_context(scan_session.events()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/passive/start", methods=["POST"])
def api_passive_start():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    if passive_session.running:
        return jsonify({"error": "被动代理已在运行"}), 409

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "请输入目标域（未指定会捕获全量流量）"}), 400
    port = int(data.get("port") or 8081)
    if not (1 <= port <= 65535):
        return jsonify({"error": "端口非法"}), 400
    try:
        queue_path = _resolve_queue_out(data.get("queue_out"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        passive_session.start(
            {
                "target": target,
                "listen": data.get("listen") or "127.0.0.1",
                "port": port,
                "tls_intercept": bool(data.get("tls_intercept")),
                "ca_dir": data.get("ca_dir") or None,
                "queue_path": str(queue_path),
            }
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "started", "queue_path": str(queue_path)})


@app.route("/api/passive/stop", methods=["POST"])
def api_passive_stop():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    try:
        passive_session.stop()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "stopped", "stats": passive_session.status()})


@app.route("/api/passive/status")
def api_passive_status():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return jsonify(passive_session.status())


@app.route("/api/export/<fmt>")
def api_export(fmt):
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    result = scan_session._result
    if result is None:
        return jsonify({"error": "没有结果"}), 400

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        return jsonify(
            {
                "scan_time": ts,
                "total": len(result.vulnerabilities),
                "vulnerabilities": [sessions.serialize_vuln(v) for v in result.vulnerabilities],
            }
        )
    return jsonify({"error": "不支持格式"}), 400


@app.route("/api/history")
def api_scan_history():
    """获取扫描历史"""
    if not _is_authorized():
        abort(401)
    limit = request.args.get("limit", 50, type=int)
    with _HISTORY_LOCK:
        snapshot = list(SCAN_HISTORY)
    history = sorted(snapshot, key=lambda x: x.get("time", ""), reverse=True)[:limit]
    return jsonify(history)


@app.route("/api/stats")
def api_stats():
    """获取统计概览"""
    if not _is_authorized():
        abort(401)
    with _HISTORY_LOCK:
        snapshot = list(SCAN_HISTORY)
    total_scans = len(snapshot)
    total_vulns = sum(h.get("total_vulns", 0) for h in snapshot)
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for h in snapshot:
        for sev, count in h.get("severity_counts", {}).items():
            if sev in severity_totals:
                severity_totals[sev] += count
    return jsonify(
        {
            "total_scans": total_scans,
            "total_vulns": total_vulns,
            "severity_totals": severity_totals,
            "engines_available": {"nuclei": True, "sqlmap": True},
        }
    )


def _record_scan(target: str, vulns: list, duration: float) -> dict:
    """记录一次扫描到历史（worker 线程调用，需加锁）。"""
    severity_counts = {}
    for v in vulns:
        sev = v.severity.value if hasattr(v.severity, "value") else "info"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    record = {
        "id": len(SCAN_HISTORY) + 1,
        "target": target,
        "time": datetime.now().isoformat(),
        "duration": round(duration, 1),
        "total_vulns": len(vulns),
        "severity_counts": severity_counts,
    }
    with _HISTORY_LOCK:
        SCAN_HISTORY.append(record)
        if len(SCAN_HISTORY) > 200:
            SCAN_HISTORY[:] = SCAN_HISTORY[-200:]
    return record


if __name__ == "__main__":
    # ── 默认仅本机绑定，避免无认证状态下对外暴露 ──
    # 需要对外服务时：RAYSCAN_WEB_HOST=0.0.0.0 python app.py
    bind_host = os.environ.get("RAYSCAN_WEB_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("RAYSCAN_WEB_PORT", "5000"))
    print("=" * 50)
    print(f"  RayScan {__version__} — Web UI")
    print(f"  http://{bind_host}:{bind_port}")
    if bind_host in ("0.0.0.0", "::"):
        print("  [WARN] 监听所有网卡 — 请确保已启用鉴权 (RAYSCAN_WEB_TOKEN)")
    print("=" * 50)
    app.run(debug=False, host=bind_host, port=bind_port, threaded=True)
