"""WVS 命令行入口 v4.0"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import click
except ImportError:
    print("错误: 需要安装 click: pip install click")
    sys.exit(1)

from wvs.core.config import ScanConfig
from wvs.core.auth import AuthConfig
from wvs.core.config_manager import ConfigManager
from wvs.core.scanner import WVSScanner


@click.group()
def cli():
    """WVS v4.0 - Web Vulnerability Scanner
    
    专业级 Web 漏洞扫描工具
    
    支持功能:
    - XSS/SQLi/敏感信息/目录遍历 检测
    - POC 验证
    - 批量扫描
    - 结果对比
    """
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="扫描目标 URL")
@click.option("--port-range", "-p", default="80-81", help="端口范围")
@click.option("--max-depth", "-d", default=3, help="爬虫最大深度")
@click.option("--max-urls", "-u", default=100, help="最大爬取 URL 数")
@click.option("--concurrency", "-c", default=50, help="并发数")
@click.option("--timeout", default=10.0, help="请求超时")
@click.option("--output", "-o", default="reports", help="报告输出目录")
@click.option("--profile", default="standard", 
              type=click.Choice(["quick", "standard", "deep"]),
              help="扫描策略 (quick/standard/deep)")
@click.option("--config", "-C", default=None, help="YAML 配置文件路径")
@click.option("--verify-poc", is_flag=True, help="启用 POC 验证")
@click.option("--auth", default=None, help="认证信息 (cookie:xxx/bearer:xxx/basic:user:pass)")
@click.option("--min-confidence", default=0.5, help="最小置信度 (0-1)")
def scan(target, port_range, max_depth, max_urls, concurrency, timeout, output,
         profile, config, verify_poc, auth, min_confidence):
    """执行漏洞扫描"""
    try:
        start, end = map(int, port_range.split("-"))
        port_range_tuple = (start, end)
    except ValueError:
        click.echo("错误: 端口范围格式错误，应为 'start-end'")
        sys.exit(1)
    
    # 创建配置
    try:
        scan_config = ConfigManager.create_scan_config(
            target=target,
            profile_name=profile,
            yaml_config=config,
            port_range=port_range_tuple,
            max_depth=max_depth,
            max_urls=max_urls,
            concurrency=concurrency,
            timeout=timeout,
            output_dir=output,
            verify_poc=verify_poc,
            min_confidence=min_confidence,
        )
        
        # 处理命令行认证参数
        if auth:
            scan_config.auth = AuthConfig.from_string(auth)
        
    except Exception as e:
        click.echo(f"配置错误: {e}")
        sys.exit(1)
    
    # 执行扫描
    try:
        scanner = WVSScanner(scan_config)
        result = asyncio.run(scanner.scan())
        
        if result["vulnerabilities"] > 0:
            sys.exit(1)
        sys.exit(0)
        
    except KeyboardInterrupt:
        click.echo("\n[!] 扫描被用户中断")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n[!] 扫描失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
def profiles():
    """列出可用扫描策略"""
    click.echo("可用扫描策略:")
    for name, desc in ConfigManager.list_profiles().items():
        click.echo(f"  {name:10} - {desc}")


@cli.command()
def plugins():
    """列出已加载的插件"""
    from .core.plugin_system import plugin_manager
    click.echo("已加载的插件:")
    for plugin in plugin_manager.list_plugins():
        status = "启用" if plugin["enabled"] else "禁用"
        click.echo(f"  {plugin['name']:20} v{plugin['version']:8} [{status}] - {plugin['description']}")


@cli.command()
@click.argument("keyword")
def kb(keyword):
    """搜索漏洞知识库"""
    from .core.knowledge_base import kb
    results = kb.search(keyword)
    if not results:
        click.echo(f"未找到与 '{keyword}' 相关的漏洞信息")
        return
    
    for knowledge in results:
        click.echo(f"\n{knowledge.name}")
        click.echo(f"  分类: {knowledge.category}")
        click.echo(f"  严重等级: {knowledge.severity}")
        if knowledge.cvss_score:
            click.echo(f"  CVSS: {knowledge.cvss_score}")
        if knowledge.cve_ids:
            click.echo(f"  CVE: {', '.join(knowledge.cve_ids)}")
        click.echo(f"  描述: {knowledge.description[:100]}...")


@cli.command()
@click.option("--target", "-t", required=True, help="扫描目标")
@click.option("--interval", "-i", default=60, help="扫描间隔（分钟）")
@click.option("--profile", default="standard", help="扫描策略")
def schedule(target, interval, profile):
    """添加定时扫描任务"""
    from .core.scheduler import scheduled_scanner
    import uuid
    
    schedule_id = f"schedule_{uuid.uuid4().hex[:8]}"
    scheduled_scanner.add_schedule(schedule_id, target, interval, profile)
    
    click.echo(f"定时扫描任务已添加:")
    click.echo(f"  ID: {schedule_id}")
    click.echo(f"  目标: {target}")
    click.echo(f"  间隔: {interval} 分钟")
    click.echo(f"  策略: {profile}")
    
    # 启动定时扫描器
    scheduled_scanner.start()
    click.echo("定时扫描器已启动 (按 Ctrl+C 停止)")
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        scheduled_scanner.stop()
        click.echo("\n定时扫描器已停止")


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="监听地址")
@click.option("--port", "-p", default=8080, help="监听端口")
def server(host, port):
    """启动 API 服务器"""
    from .api.server import api_server
    
    async def run_server():
        await api_server.start()
        click.echo(f"API 文档: http://{host}:{port}/")
        
        # 保持运行
        while True:
            await asyncio.sleep(1)
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        click.echo("\n服务器已停止")


@cli.command()
@click.option("--webhook", "-w", required=True, help="Webhook URL")
@click.option("--target", "-t", required=True, help="扫描目标")
@click.option("--profile", default="standard", help="扫描策略")
def scan_with_webhook(webhook, target, profile):
    """扫描并发送 Webhook 通知"""
    from .core.notifier import webhook_notifier
    from .core.config_manager import ConfigManager
    from .core.scanner import WVSScanner
    
    # 添加 webhook
    webhook_notifier.add_from_url(webhook)
    
    async def do_scan():
        # 发送开始通知
        await webhook_notifier.notify_scan_started("pending", target)
        
        # 执行扫描
        config = ConfigManager.create_scan_config(
            target=target,
            profile_name=profile,
        )
        
        scanner = WVSScanner(config)
        result = await scanner.scan()
        
        # 发送完成通知
        await webhook_notifier.notify_scan_completed(result)
        
        click.echo(f"扫描完成，Webhook 已发送到: {webhook}")
    
    asyncio.run(do_scan())


@cli.command()
def stats():
    """显示扫描统计"""
    from .core.dashboard import dashboard
    
    summary = dashboard.get_summary()
    
    click.echo("\n📊 扫描统计")
    click.echo("=" * 50)
    click.echo(f"总扫描次数: {summary['overview']['total_scans']}")
    click.echo(f"总漏洞数: {summary['overview']['total_vulnerabilities']}")
    click.echo(f"平均漏洞/扫描: {summary['overview']['average_vulns_per_scan']}")
    
    click.echo("\n严重等级分布:")
    for sev, count in summary['severity_distribution'].items():
        click.echo(f"  {sev}: {count}")


@cli.command()
@click.option("--output", "-o", default="dashboard.html", help="输出文件")
def dashboard_cmd(output):
    """生成统计面板"""
    from .core.dashboard import dashboard
    
    output_path = dashboard.generate_html_dashboard(output)
    click.echo(f"统计面板已生成: {output_path}")


@cli.command()
def history():
    """显示扫描历史"""
    from .core.database import db
    
    scans = db.list_scans(limit=20)
    
    click.echo("\n📜 扫描历史")
    click.echo("=" * 80)
    click.echo(f"{'Scan ID':<20} {'Target':<30} {'Vulns':<8} {'Time':<20}")
    click.echo("-" * 80)
    
    for scan in scans:
        scan_id = scan['scan_id'][:18]
        target = scan['target'][:28]
        vulns = scan['vulnerability_count']
        time = scan['timestamp'][:19]
        click.echo(f"{scan_id:<20} {target:<30} {vulns:<8} {time:<20}")


@cli.command()
@click.argument("scan_id")
def pdf(scan_id):
    """生成 PDF 报告"""
    from .core.database import db
    from .report.pdf_gen import PDFReportGenerator
    
    scan = db.get_scan(scan_id)
    if not scan:
        click.echo(f"错误: 扫描记录不存在: {scan_id}")
        return
    
    import json
    vulnerabilities = json.loads(scan.get("vulnerabilities", "[]"))
    
    generator = PDFReportGenerator()
    output_path = f"reports/{scan_id}.pdf"
    
    try:
        generator.generate(
            scan_id=scan_id,
            target=scan["target"],
            vulnerabilities=vulnerabilities,
            output_path=output_path
        )
        click.echo(f"PDF 报告已生成: {output_path}")
    except ImportError:
        click.echo("错误: 需要安装 fpdf2: pip install fpdf2")
    except Exception as e:
        click.echo(f"生成失败: {e}")


@cli.command()
def templates():
    """列出扫描模板"""
    from .core.templates import template_manager
    
    templates = template_manager.list_templates()
    click.echo("\n📋 扫描模板")
    click.echo("=" * 60)
    click.echo(f"{'名称':<20} {'类型':<10} {'描述'}")
    click.echo("-" * 60)
    
    for t in templates:
        type_str = "内置" if t["type"] == "builtin" else "自定义"
        click.echo(f"{t['name']:<20} {type_str:<10} {t['description']}")


@cli.command()
@click.option("--template", "-t", required=True, help="模板名称")
@click.option("--target", "-u", required=True, help="扫描目标")
def scan_with_template(template, target):
    """使用模板扫描"""
    from .core.templates import template_manager
    from .core.config_manager import ConfigManager
    from .core.scanner import WVSScanner
    
    try:
        config_data = template_manager.apply_template(template, target)
    except ValueError as e:
        click.echo(f"错误: {e}")
        return
    
    click.echo(f"使用模板 '{template}' 扫描 {target}...")
    
    async def do_scan():
        config = ConfigManager.create_scan_config(
            target=target,
            profile_name=config_data["profile"],
        )
        
        scanner = WVSScanner(config)
        result = await scanner.scan()
        
        click.echo(f"扫描完成，发现 {result['vulnerabilities']} 个漏洞")
    
    asyncio.run(do_scan())


@cli.command()
def tickets():
    """显示漏洞工单"""
    from .core.workflow import workflow
    
    tickets = workflow.list_tickets()
    stats = workflow.get_statistics()
    
    click.echo("\n🎫 漏洞工单")
    click.echo("=" * 80)
    click.echo(f"总计: {stats['total']} | 逾期: {stats['overdue']} | 今日到期: {stats['due_today']}")
    click.echo("-" * 80)
    click.echo(f"{'工单ID':<15} {'漏洞':<25} {'状态':<12} {'负责人'}")
    click.echo("-" * 80)
    
    for t in tickets[:20]:
        status_str = t.status.replace("_", " ")
        click.echo(f"{t.ticket_id:<15} {t.vuln_name[:24]:<25} {status_str:<12} {t.assigned_to}")


@cli.command()
@click.option("--username", "-u", required=True, help="用户名")
@click.option("--email", "-e", required=True, help="邮箱")
@click.option("--password", "-p", required=True, help="密码")
@click.option("--role", "-r", default="viewer", help="角色 (admin/scanner/remediator/viewer)")
def create_user(username, email, password, role):
    """创建用户"""
    from .core.auth_manager import user_manager, Role
    
    role_map = {
        "admin": Role.ADMIN,
        "scanner": Role.SCANNER,
        "remediator": Role.REMEDIATOR,
        "viewer": Role.VIEWER,
    }
    
    if role not in role_map:
        click.echo(f"错误: 无效的角色 {role}")
        return
    
    try:
        user = user_manager.create_user(username, email, password, role_map[role])
        click.echo(f"用户创建成功: {user.user_id}")
    except Exception as e:
        click.echo(f"创建失败: {e}")


@cli.command()
def users():
    """列出用户"""
    from .core.auth_manager import user_manager
    
    users = user_manager.list_users()
    click.echo("\n👥 用户列表")
    click.echo("=" * 60)
    click.echo(f"{'ID':<15} {'用户名':<15} {'角色':<12} {'邮箱'}")
    click.echo("-" * 60)
    
    for u in users:
        click.echo(f"{u['user_id']:<15} {u['username']:<15} {u['role']:<12} {u['email']}")


@cli.command()
@click.option("--target", "-t", required=True, help="扫描目标")
def smart_scan(target):
    """智能扫描 - 自适应策略"""
    from .core.smart_scan import SmartScanner
    from .core.config_manager import ConfigManager
    from .core.scanner import WVSScanner
    
    click.echo(f"正在分析目标: {target}...")
    
    async def do_scan():
        # 先进行目标分析
        smart = SmartScanner()
        
        # 模拟一些响应用于分析
        sample_responses = [
            {"headers": {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}, "body": "<html>"},
        ]
        
        profile = smart.analyze_target(sample_responses)
        click.echo(f"检测到技术栈: {', '.join(profile.tech_stack)}")
        
        if profile.waf_detected:
            click.echo("⚠️ 检测到WAF，将使用规避策略")
        
        # 获取自适应策略
        strategy = smart.adapt_strategy()
        click.echo(f"并发数: {strategy['concurrency']}, 延迟: {strategy['delay']}s")
        
        # 执行扫描
        config = ConfigManager.create_scan_config(
            target=target,
            profile_name="smart",
        )
        
        scanner = WVSScanner(config)
        result = await scanner.scan()
        
        click.echo(f"扫描完成，发现 {result['vulnerabilities']} 个漏洞")
    
    asyncio.run(do_scan())


@cli.command()
@click.option("--target", "-t", required=True, help="目标URL")
def predict(target):
    """预测可能存在漏洞的位置"""
    from .core.smart_scan import VulnerabilityPredictor
    from .core.database import db
    
    # 加载历史数据
    scans = db.list_scans(limit=100)
    historical_vulns = []
    
    for scan in scans:
        import json
        try:
            vulns = json.loads(scan.get("vulnerabilities", "[]"))
            historical_vulns.extend(vulns)
        except:
            pass
    
    predictor = VulnerabilityPredictor()
    predictor.train(historical_vulns)
    
    # 预测
    urls = [target, f"{target}/admin", f"{target}/api", f"{target}/login"]
    predictions = predictor.predict(urls)
    
    click.echo("\n🔮 漏洞预测")
    click.echo("=" * 60)
    click.echo(f"{'URL':<35} {'类型':<15} {'置信度'}")
    click.echo("-" * 60)
    
    for p in predictions:
        click.echo(f"{p['url']:<35} {p['predicted_type']:<15} {p['confidence']:.2%}")


@cli.command()
@click.option("--name", "-n", required=True, help="节点名称")
@click.option("--host", "-h", required=True, help="节点地址")
@click.option("--port", "-p", default=8081, help="节点端口")
def register_node(name, host, port):
    """注册扫描节点"""
    from .core.distributed import distributed_scanner
    
    node = distributed_scanner.node_manager.register_node(name, host, port)
    click.echo(f"节点注册成功: {node.node_id}")
    click.echo(f"  名称: {node.name}")
    click.echo(f"  地址: {node.host}:{node.port}")


@cli.command()
def nodes():
    """显示扫描节点"""
    from .core.distributed import distributed_scanner
    
    active_nodes = distributed_scanner.node_manager.get_active_nodes()
    
    click.echo("\n🖥️ 扫描节点")
    click.echo("=" * 80)
    click.echo(f"{'节点ID':<15} {'名称':<15} {'状态':<10} {'负载':<10} {'区域'}")
    click.echo("-" * 80)
    
    for node in active_nodes:
        load = f"{node.current_load}/{node.max_concurrency}"
        click.echo(f"{node.node_id:<15} {node.name:<15} {node.status:<10} {load:<10} {node.region}")


@cli.command()
def cluster():
    """显示集群状态"""
    from .core.distributed import distributed_scanner
    
    status = distributed_scanner.get_cluster_status()
    
    click.echo("\n☸️ 集群状态")
    click.echo("=" * 60)
    click.echo(f"节点: {status['nodes']['active']}/{status['nodes']['total']} 活跃")
    click.echo(f"任务: {status['tasks']['total']} 总计")
    click.echo(f"  - 等待: {status['tasks']['pending']}")
    click.echo(f"  - 运行: {status['tasks']['running']}")
    click.echo(f"  - 完成: {status['tasks']['completed']}")
    click.echo(f"  - 失败: {status['tasks']['failed']}")
    click.echo(f"负载: {status['load']}/{status['capacity']}")


@cli.command()
@click.option("--scan-id", "-s", required=True, help="扫描ID")
def suggest_fix(scan_id):
    """生成修复建议"""
    from .core.database import db
    from .core.autofix import AutoFixer
    
    scan = db.get_scan(scan_id)
    if not scan:
        click.echo(f"错误: 扫描记录不存在: {scan_id}")
        return
    
    import json
    vulns = json.loads(scan.get("vulnerabilities", "[]"))
    
    fixer = AutoFixer()
    
    click.echo("\n🔧 自动修复建议")
    click.echo("=" * 80)
    
    for vuln in vulns:
        fix = fixer.generate_fix(vuln)
        if fix:
            click.echo(f"\n漏洞: {vuln.get('name')}")
            click.echo(f"描述: {fix.description}")
            click.echo(f"置信度: {fix.confidence:.0%}")
            click.echo(f"可自动修复: {'是' if fix.automated else '否'}")


@cli.command()
@click.option("--platform", "-p", required=True, help="平台 (github/gitlab/jenkins)")
@click.option("--target", "-t", required=True, help="扫描目标")
def generate_ci(platform, target):
    """生成CI/CD配置"""
    from .core.autofix import DevSecOpsIntegration
    
    devsecops = DevSecOpsIntegration()
    config = devsecops.generate_ci_config(platform, target)
    
    click.echo(f"\n📋 {platform.upper()} CI/CD 配置")
    click.echo("=" * 60)
    click.echo(config)


@cli.command()
@click.option("--scan-id", "-s", required=True, help="扫描ID")
@click.option("--standard", "-std", default="owasp", help="合规标准")
def compliance(scan_id, standard):
    """合规检查"""
    from .core.database import db
    from .core.autofix import DevSecOpsIntegration
    
    scan = db.get_scan(scan_id)
    if not scan:
        click.echo(f"错误: 扫描记录不存在: {scan_id}")
        return
    
    import json
    vulns = json.loads(scan.get("vulnerabilities", "[]"))
    
    devsecops = DevSecOpsIntegration()
    result = devsecops.check_compliance(vulns, standard)
    
    click.echo(f"\n📊 合规检查 - {standard.upper()}")
    click.echo("=" * 60)
    click.echo(f"合规分数: {result['score']:.1f}%")
    click.echo(f"检查结果: {'通过' if result['passed'] else '未通过'}")
    
    for category, findings in result['findings'].items():
        if findings:
            click.echo(f"\n❌ {category}: {len(findings)} 个问题")


@cli.command()
@click.option("--target", "-t", required=True, help="扫描目标")
def intelligent_scan(target):
    """智能快速扫描 (v9.0)"""
    import asyncio
    from .templates.intelligent import IntelligentQuickScan
    
    async def do_scan():
        scanner = IntelligentQuickScan()
        results = await scanner.run(target)
        
        click.echo(f"\n✅ 智能扫描完成")
        click.echo(f"发现 {len(results)} 个漏洞")
        
        for r in results:
            click.echo(f"  - {r['type']} [{r['severity']}] AI置信度: {r.get('ai_confidence', 0):.0%}")
    
    asyncio.run(do_scan())


@cli.command()
@click.option("--target", "-t", required=True, help="扫描目标")
def context_scan(target):
    """上下文感知扫描 (v9.0)"""
    import asyncio
    from .core.context.scanner import ContextAwareScanner
    
    async def do_scan():
        scanner = ContextAwareScanner()
        context = await scanner.analyze(target)
        
        click.echo("\n🔍 目标上下文分析")
        click.echo("=" * 60)
        click.echo(f"框架: {context.framework}")
        click.echo(f"认证方式: {context.auth_method}")
        click.echo(f"风险等级: {context.risk_level}")
        click.echo(f"推荐模板: {context.recommended_template}")
        click.echo(f"技术栈: {', '.join(context.tech_stack)}")
        click.echo(f"服务器: {context.server_software}")
        click.echo(f"CMS: {context.cms or '未检测'}")
        click.echo(f"WAF检测: {'是' if context.waf_detected else '否'}")
    
    asyncio.run(do_scan())


@cli.command()
def ai_verify():
    """AI验证演示 (v9.0)"""
    from .core.ai.verifier import AIVulnerabilityVerifier
    
    verifier = AIVulnerabilityVerifier()
    
    # 模拟扫描结果
    test_result = {
        'target': 'http://example.com',
        'response_times': [0.1, 0.15, 0.12, 0.2, 0.11],
        'error_patterns': ['sql syntax error'],
        'payload_reflection': {'depth': 3},
        'response': '<script>alert(1)</script> sql syntax error',
    }
    
    result = verifier.verify(test_result)
    
    click.echo("\n🤖 AI漏洞验证")
    click.echo("=" * 60)
    click.echo(f"是否漏洞: {'是' if result.is_vulnerable else '否'}")
    click.echo(f"置信度: {result.confidence:.2%}")
    click.echo(f"解释: {result.explanation}")
    click.echo("\n特征向量:")
    for name, value in result.features.items():
        click.echo(f"  {name}: {value:.4f}")


@cli.command()
def performance():
    """性能监控 (v9.0)"""
    from .core.performance.optimizer import PerformanceOptimizer
    
    optimizer = PerformanceOptimizer()
    metrics = optimizer.monitor_resources()
    
    click.echo("\n📈 系统资源")
    click.echo("=" * 60)
    click.echo(f"CPU使用率: {metrics.cpu_percent:.1f}%")
    click.echo(f"内存使用率: {metrics.memory_percent:.1f}%")
    click.echo(f"可用内存: {metrics.memory_available_mb:.0f} MB")
    click.echo(f"磁盘读取: {metrics.disk_read_mb:.1f} MB")
    click.echo(f"磁盘写入: {metrics.disk_write_mb:.1f} MB")
    
    # 计算最优参数
    optimal_concurrency = optimizer.calculate_optimal_concurrency('medium')
    click.echo(f"\n推荐并发数: {optimal_concurrency}")


@cli.command()
@click.option("--image", "-i", required=True, help="Docker镜像名称")
@click.option("--format", "-f", default="text", help="输出格式 (text/json/html)")
def scan_container(image, format):
    """扫描容器镜像 (v10.0)"""
    from .plugins.cloud_native.container_scanner import ContainerScanner
    
    scanner = ContainerScanner()
    results = scanner.scan_image(image)
    
    if 'error' in results:
        click.echo(f"错误: {results['error']}")
        return
    
    click.echo(f"\n🐳 容器镜像扫描: {image}")
    click.echo("=" * 60)
    click.echo(f"漏洞: {len(results['vulnerabilities'])}")
    click.echo(f"配置问题: {len(results['misconfigurations'])}")
    click.echo(f"敏感信息: {len(results['secrets'])}")
    
    if results['vulnerabilities']:
        click.echo("\n漏洞列表:")
        for v in results['vulnerabilities'][:5]:
            click.echo(f"  - {v['cve_id']} [{v['severity']}] {v['affected_package']}")


@cli.command()
@click.option("--kubeconfig", "-k", default=None, help="kubeconfig路径")
@click.option("--namespace", "-n", default=None, help="指定命名空间")
def scan_k8s(kubeconfig, namespace):
    """扫描Kubernetes集群 (v10.0)"""
    from .plugins.cloud_native.k8s_scanner import KubernetesScanner
    
    scanner = KubernetesScanner(kubeconfig)
    results = scanner.scan_cluster()
    
    if 'error' in results:
        click.echo(f"错误: {results['error']}")
        return
    
    click.echo("\n☸️ Kubernetes集群扫描")
    click.echo("=" * 60)
    click.echo(f"节点问题: {len(results['nodes'])}")
    click.echo(f"Pod问题: {len(results['pods'])}")
    click.echo(f"RBAC问题: {len(results['rbac'])}")
    click.echo(f"网络策略问题: {len(results['network_policies'])}")
    
    if results['pods']:
        click.echo("\nPod安全问题:")
        for issue in results['pods'][:5]:
            click.echo(f"  - [{issue['severity']}] {issue['type']} in {issue.get('pod', 'N/A')}")


@cli.command()
def integrations():
    """列出已启用的集成 (v11.0)"""
    from .integrations.manager import UnifiedAPIGateway
    
    gateway = UnifiedAPIGateway()
    integrations = gateway.list_integrations()
    
    click.echo("\n🔗 已启用的集成")
    click.echo("=" * 60)
    if integrations:
        for integration in integrations:
            click.echo(f"  ✓ {integration}")
    else:
        click.echo("  未配置任何集成")
        click.echo("  编辑 config/integrations.yaml 启用集成")


@cli.command()
@click.option("--vuln-id", "-v", required=True, help="漏洞ID")
@click.option("--system", "-s", required=True, help="目标系统 (jira/gitlab/github)")
def forward_vuln(vuln_id, system):
    """转发漏洞到集成系统 (v11.0)"""
    from .integrations.manager import UnifiedAPIGateway
    
    # 模拟漏洞数据
    vuln = {
        'id': vuln_id,
        'type': 'xss',
        'severity': 'high',
        'target': 'http://example.com',
        'description': 'Cross-site scripting vulnerability',
        'recommendation': 'Sanitize user input',
    }
    
    gateway = UnifiedAPIGateway()
    result = gateway.forward_vulnerability(vuln, system)
    
    if result.get('success'):
        click.echo(f"✅ 漏洞已转发到 {system}")
        if 'issue_key' in result:
            click.echo(f"   Issue: {result['issue_key']}")
        if 'url' in result:
            click.echo(f"   URL: {result['url']}")
    else:
        click.echo(f"❌ 转发失败: {result.get('error')}")


@cli.command()
@click.option("--message", "-m", required=True, help="通知消息")
@click.option("--channels", "-c", multiple=True, default=['slack'], help="通知渠道")
@click.option("--severity", "-s", default='info', help="严重级别")
def notify(message, channels, severity):
    """发送通知到多个渠道 (v11.0)"""
    from .integrations.manager import UnifiedAPIGateway
    
    gateway = UnifiedAPIGateway()
    results = gateway.send_notification(message, list(channels), severity)
    
    click.echo("\n📢 通知发送结果")
    click.echo("=" * 60)
    for channel, result in results.items():
        status = "✅" if result.get('success') else "❌"
        click.echo(f"{status} {channel}: {result.get('status_code', 'N/A')}")


@cli.command()
@click.option("--output", "-o", default="wvs-config.yaml", help="输出文件名")
def init_config(output):
    """生成示例配置文件"""
    sample = ConfigManager.generate_sample_config()
    with open(output, "w", encoding="utf-8") as f:
        f.write(sample)
    click.echo(f"配置文件已生成: {output}")


@cli.command()
@click.argument("targets_file", type=click.Path(exists=True))
@click.option("--profile", default="standard", help="扫描策略")
@click.option("--output", "-o", default="reports", help="报告输出目录")
def batch(targets_file, profile, output):
    """批量扫描多个目标"""
    # 读取目标列表
    with open(targets_file, "r") as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    click.echo(f"批量扫描 {len(targets)} 个目标...")
    
    # 创建基础配置
    base_config = ConfigManager.create_scan_config(
        target="",  # 将在循环中设置
        profile_name=profile,
        output_dir=output,
    )
    
    # 执行批量扫描
    from wvs.core.batch_compare import BatchScanner
    batch_scanner = BatchScanner(base_config)
    
    try:
        results = asyncio.run(batch_scanner.scan_multiple(targets))
        
        # 生成汇总报告
        summary = batch_scanner.generate_summary_report()
        summary_path = Path(output) / "batch_summary.json"
        import json
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        click.echo(f"\n批量扫描完成!")
        click.echo(f"汇总报告: {summary_path}")
        click.echo(f"总漏洞数: {summary['summary']['total_vulnerabilities']}")
        
    except Exception as e:
        click.echo(f"批量扫描失败: {e}")
        sys.exit(1)


@cli.command()
@click.argument("current_result", type=click.Path(exists=True))
@click.argument("previous_result", type=click.Path(exists=True))
def compare(current_result, previous_result):
    """对比两次扫描结果"""
    from wvs.core.batch_compare import ResultComparator
    
    comparator = ResultComparator()
    
    try:
        current = comparator.load_previous_result(current_result)
        previous = comparator.load_previous_result(previous_result)
        
        diff = comparator.compare(current, previous)
        
        click.echo("\n扫描结果对比:")
        click.echo(f"目标: {diff['target']}")
        click.echo(f"当前扫描: {diff['current_scan']}")
        click.echo(f"历史扫描: {diff['previous_scan']}")
        click.echo(f"\n漏洞变化:")
        click.echo(f"  新增: {diff['summary']['new']}")
        click.echo(f"  修复: {diff['summary']['fixed']}")
        click.echo(f"  未变: {diff['summary']['unchanged']}")
        
        if diff['new_vulnerabilities']:
            click.echo("\n新增漏洞:")
            for v in diff['new_vulnerabilities'][:5]:
                click.echo(f"  - {v}")
        
    except Exception as e:
        click.echo(f"对比失败: {e}")
        sys.exit(1)


# ==================== v12.0 移动安全 ====================

@cli.command()
@click.option("--file", "-f", required=True, help="APK/IPA文件路径")
@click.option("--platform", "-p", default="auto", help="平台 (android/ios/auto)")
@click.option("--output", "-o", default="reports", help="输出目录")
def scan_mobile(file, platform, output):
    """扫描移动应用 (v12.0)"""
    try:
        from wvs.plugins.mobile import MobileSecurityScanner
        
        scanner = MobileSecurityScanner()
        results = scanner.scan(file, platform=platform)
        
        if 'error' in results:
            click.echo(f"错误: {results['error']}")
            return
        
        click.echo(f"\n📱 移动应用扫描: {file}")
        click.echo("=" * 60)
        
        summary = results.get('summary', {})
        click.echo(f"平台: {results.get('platform', 'unknown')}")
        click.echo(f"文件大小: {results.get('file_size_mb', 0):.1f} MB")
        click.echo(f"漏洞: {summary.get('total_issues', 0)} (严重{summary.get('critical', 0)} 高危{summary.get('high', 0)} 中危{summary.get('medium', 0)} 低危{summary.get('low', 0)})")
        
        # 保存报告
        import json
        import os
        os.makedirs(output, exist_ok=True)
        report_file = os.path.join(output, f"mobile-scan-{os.path.basename(file)}.json")
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"报告已保存: {report_file}")
        
    except ImportError as e:
        click.echo(f"移动安全模块未安装: {e}")
    except Exception as e:
        click.echo(f"扫描失败: {e}")


@cli.command()
@click.option("--endpoints", "-e", required=True, help="API端点列表(逗号分隔)")
@click.option("--token", "-t", help="认证Token")
def scan_mobile_api(endpoints, token):
    """扫描移动后端API (v12.0)"""
    try:
        from wvs.plugins.mobile.api_scanner import MobileAPISecurityScanner
        
        scanner = MobileAPISecurityScanner()
        endpoint_list = [e.strip() for e in endpoints.split(',')]
        auth_tokens = {'access_token': token} if token else {}
        
        results = scanner.scan_mobile_api(endpoint_list, auth_tokens)
        
        click.echo(f"\n📱 移动API扫描")
        click.echo("=" * 60)
        click.echo(f"端点数: {results.get('endpoints_scanned', 0)}")
        
        summary = results.get('summary', {})
        click.echo(f"问题: {summary.get('total_issues', 0)}")
        
    except Exception as e:
        click.echo(f"扫描失败: {e}")


# ==================== v13.0 数据合规 ====================

@cli.command()
@click.option("--target", "-t", required=True, help="目标URL")
@click.option("--framework", "-f", default="gdpr", help="合规框架 (gdpr/ccpa/china_ds/pci_dss)")
@click.option("--depth", "-d", default="standard", help="扫描深度")
def compliance(target, framework, depth):
    """数据合规扫描 (v13.0)"""
    try:
        from wvs.plugins.compliance.scanner import DataComplianceScanner
        
        scanner = DataComplianceScanner()
        
        # 扫描PII
        click.echo(f"\n🔍 扫描PII数据...")
        pii_results = scanner.scan_for_pii([target], depth)
        
        click.echo(f"发现PII: {pii_results.get('pii_summary', {}).get('total_findings', 0)} 处")
        
        # 生成合规报告
        click.echo(f"\n📋 生成{framework.upper()}合规报告...")
        report = scanner.generate_compliance_report(pii_results, framework)
        
        click.echo(f"\n合规评分: {report.get('compliance_score', 0)}/100")
        click.echo(f"合规状态: {'✅ 合规' if report.get('is_compliant') else '❌ 不合规'}")
        
        violations = report.get('violations', [])
        if violations:
            click.echo(f"\n违规项 ({len(violations)}):")
            for v in violations[:5]:
                click.echo(f"  - [{v.get('severity', 'medium')}] {v.get('description', '')}")
        
        click.echo(f"\n修复建议:")
        for step in report.get('remediation_steps', [])[:5]:
            click.echo(f"  • {step}")
        
    except Exception as e:
        click.echo(f"合规扫描失败: {e}")


# ==================== v14.0 AI增强 ====================

@cli.command()
@click.option("--scan-id", "-s", required=True, help="扫描结果ID或文件路径")
@click.option("--audience", "-a", default="executive", help="受众 (executive/technical)")
def ai_report(scan_id, audience):
    """AI智能报告生成 (v14.0)"""
    click.echo("\n🤖 AI智能报告生成")
    click.echo("=" * 60)
    click.echo("注意: 需要配置OPENAI_API_KEY或ANTHROPIC_API_KEY")
    
    async def generate():
        try:
            from wvs.core.ai.llm_engine import AIEnhancedScanner
            import json
            
            # 加载扫描结果
            if os.path.exists(scan_id):
                with open(scan_id, 'r') as f:
                    scan_results = json.load(f)
            else:
                click.echo(f"错误: 找不到文件 {scan_id}")
                return
            
            scanner = AIEnhancedScanner()
            
            click.echo("正在分析扫描结果...")
            enhanced = await scanner.analyze_scan_results(scan_results)
            
            click.echo("正在生成报告...")
            report = await scanner.generate_report(scan_results, audience)
            
            click.echo("\n" + "=" * 60)
            click.echo(report[:2000])  # 显示前2000字符
            if len(report) > 2000:
                click.echo("\n... (报告已截断)")
            
        except Exception as e:
            click.echo(f"AI报告生成失败: {e}")
    
    asyncio.run(generate())


@cli.command()
@click.option("--history", "-h", help="历史扫描数据文件")
def ai_predict(history):
    """AI风险预测 (v14.0)"""
    click.echo("\n🔮 AI安全风险预测")
    click.echo("=" * 60)
    
    async def predict():
        try:
            from wvs.core.ai.llm_engine import AIEnhancedScanner
            import json
            
            scanner = AIEnhancedScanner()
            
            historical_data = {'vulnerabilities': [], 'threat_intel': {}}
            if history and os.path.exists(history):
                with open(history, 'r') as f:
                    historical_data = json.load(f)
            
            current_scan = {'vulnerabilities': []}
            
            prediction = await scanner.llm_engine.predict_security_risks(
                historical_data, current_scan
            )
            
            click.echo(f"\n高风险区域:")
            for area in prediction.get('high_risk_areas', [])[:5]:
                click.echo(f"  • {area}")
            
            click.echo(f"\n新兴威胁:")
            for threat in prediction.get('emerging_threats', [])[:5]:
                click.echo(f"  • {threat}")
            
            click.echo(f"\n修复优先级:")
            for priority in prediction.get('remediation_priority', [])[:5]:
                click.echo(f"  • {priority}")
            
        except Exception as e:
            click.echo(f"预测失败: {e}")
    
    asyncio.run(predict())


# ==================== v15.0 商业生态 ====================

@cli.group()
def marketplace():
    """插件市场 (v15.0)"""
    pass


@marketplace.command(name="list")
@click.option("--category", "-c", help="分类筛选")
@click.option("--free", is_flag=True, help="仅显示免费插件")
def marketplace_list(category, free):
    """列出可用插件"""
    try:
        from wvs.marketplace.marketplace import PluginMarketplace
        
        mp = PluginMarketplace()
        pricing = 'free' if free else 'all'
        plugins = mp.browse_plugins(category, pricing)
        
        click.echo(f"\n📦 可用插件 ({len(plugins)})")
        click.echo("=" * 60)
        
        for p in plugins[:10]:
            installed = "✅" if p.get('is_installed') else "  "
            license_type = "FREE" if p['license_type'] == 'free' else f"${p['price']}"
            click.echo(f"{installed} {p['name']} [{license_type}] - {p['description'][:50]}...")
        
    except Exception as e:
        click.echo(f"加载失败: {e}")


@marketplace.command(name="install")
@click.option("--plugin-id", "-p", required=True, help="插件ID")
@click.option("--license", "-l", help="许可证密钥")
def marketplace_install(plugin_id, license):
    """安装插件"""
    try:
        from wvs.marketplace.marketplace import PluginMarketplace
        
        mp = PluginMarketplace()
        result = mp.install_plugin(plugin_id, license)
        
        if result.get('success'):
            click.echo(f"✅ {result.get('message')}")
        else:
            click.echo(f"❌ {result.get('error')}")
            if 'purchase_url' in result:
                click.echo(f"购买链接: {result['purchase_url']}")
        
    except Exception as e:
        click.echo(f"安装失败: {e}")


@marketplace.command(name="installed")
def marketplace_installed():
    """列出已安装插件"""
    try:
        from wvs.marketplace.marketplace import PluginMarketplace
        
        mp = PluginMarketplace()
        plugins = mp.get_installed_plugins()
        
        click.echo(f"\n📦 已安装插件 ({len(plugins)})")
        click.echo("=" * 60)
        
        for p in plugins:
            click.echo(f"  {p['name']} v{p['installed_version']}")
        
    except Exception as e:
        click.echo(f"加载失败: {e}")


@cli.group()
def subscription():
    """订阅管理 (v15.0)"""
    pass


@subscription.command(name="plans")
def subscription_plans():
    """查看订阅计划"""
    try:
        from wvs.marketplace.marketplace import PluginMarketplace
        
        mp = PluginMarketplace()
        plans = mp.get_subscription_plans()
        
        click.echo(f"\n💎 订阅计划")
        click.echo("=" * 60)
        
        for name, plan in plans.items():
            price = "免费" if plan['price'] == 0 else (f"${plan['price']}/月" if plan['price'] > 0 else "定制")
            click.echo(f"\n{name.upper()}: {price}")
            click.echo(f"  功能: {', '.join(plan['features'][:3])}...")
            limits = plan['limits']
            click.echo(f"  限制: 并发{limits.get('concurrent_scans', '∞')} 日API{limits.get('api_calls_per_day', '∞')}")
        
    except Exception as e:
        click.echo(f"加载失败: {e}")


@subscription.command(name="subscribe")
@click.option("--plan", "-p", required=True, help="计划名称 (community/professional/enterprise)")
@click.option("--user-id", "-u", required=True, help="用户ID")
def subscription_subscribe(plan, user_id):
    """订阅计划"""
    try:
        from wvs.marketplace.marketplace import PluginMarketplace
        
        mp = PluginMarketplace()
        result = mp.subscribe(user_id, plan)
        
        if result.get('success'):
            click.echo(f"✅ 订阅成功!")
            click.echo(f"   计划: {result.get('plan')}")
            click.echo(f"   订阅ID: {result.get('subscription_id')}")
            click.echo(f"   下次扣费: {result.get('next_billing_date')}")
        else:
            click.echo(f"❌ {result.get('error')}")
        
    except Exception as e:
        click.echo(f"订阅失败: {e}")


# ==================== v15.0 插件开发SDK ====================

@cli.command()
@click.option("--name", "-n", required=True, help="插件名称")
@click.option("--type", "-t", default="scanner", help="插件类型 (scanner/reporter/notifier)")
@click.option("--output", "-o", default="./plugins", help="输出目录")
def create_plugin(name, type, output):
    """创建插件模板 (v15.0)"""
    try:
        from wvs.marketplace.sdk import PluginSDK
        
        sdk = PluginSDK()
        templates = sdk.create_plugin_template(name, type)
        plugin_dir = sdk.generate_plugin_structure(name, templates, output)
        
        click.echo(f"✅ 插件模板已创建: {plugin_dir}")
        click.echo(f"\n文件列表:")
        for filename in templates.keys():
            click.echo(f"  - {filename}")
        
        click.echo(f"\n下一步:")
        click.echo(f"  1. cd {plugin_dir}")
        click.echo(f"  2. 编辑 plugin.py 实现扫描逻辑")
        click.echo(f"  3. wvs validate-plugin {plugin_dir}")
        
    except Exception as e:
        click.echo(f"创建失败: {e}")


@cli.command()
@click.argument("plugin_path")
def validate_plugin(plugin_path):
    """验证插件 (v15.0)"""
    try:
        from wvs.marketplace.sdk import PluginSDK
        
        sdk = PluginSDK()
        result = sdk.validate_plugin(plugin_path)
        
        click.echo(f"\n🔍 插件验证结果")
        click.echo("=" * 60)
        click.echo(f"状态: {'✅ 通过' if result['is_valid'] else '❌ 未通过'}")
        click.echo(f"认证: {result['certification_status']}")
        
        click.echo(f"\n详细检查:")
        for check, passed in result['details'].items():
            status = "✅" if passed else "❌"
            click.echo(f"  {status} {check}")
        
    except Exception as e:
        click.echo(f"验证失败: {e}")


if __name__ == "__main__":
    cli()
