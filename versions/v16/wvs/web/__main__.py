"""WVS v16.0 - Web UI 启动脚本

用法:
    python -m wvs.web
    
    # 指定端口
    python -m wvs.web --port 8080
"""
import argparse
from . import start_web_ui


def main():
    parser = argparse.ArgumentParser(description="WVS v16.0 Web UI")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=8080, help="监听端口 (默认: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    WVS v16.0 Web UI                          ║
║                                                              ║
║  访问地址: http://localhost:{args.port:<5}                      ║
║  API 文档: http://localhost:{args.port}/docs                  ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if not args.no_browser:
        import webbrowser
        webbrowser.open(f"http://localhost:{args.port}")
    
    start_web_ui(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
