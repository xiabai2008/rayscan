"""Log Poisoning RCE Scanner - LFI 到 RCE 检测链

攻击链:
1. LFI 检测 → 确认文件包含漏洞
2. 日志投毒 → 向 Apache/Nginx 日志写入 PHP payload
3. LFI 触发 → 通过 LFI 包含被污染的日志文件
4. RCE 验证 → 检查命令执行结果

适用场景:
- Apache: /var/log/apache2/access.log, /var/log/apache2/error.log
- Nginx: /var/log/nginx/access.log, /var/log/nginx/error.log
- SSH: /var/log/auth.log (写入 python reverse shell)

检测策略:
- 时间盲注 (响应时间)
- DNS 外带 (需要配置域名)
- 回显检测 (需支持写入日志)
"""
from .log_poison_scanner import LogPoisonScanner

__all__ = ["LogPoisonScanner"]
