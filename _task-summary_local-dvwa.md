# 本地 DVWA 靶场搭建 & 扫描 — 2026-05-06

## 背景
远端 ECS (47.95.192.41) 挂死，WSL2 无法启动 (Hyper-V 未安装 + VMware 占用 VT-x)，需要本地靶场。

## 方案实现
利用已运行的 Kali 2024.1 VM (172.17.43.129) 直接部署靶场：

1. **PHP 内置服务器** — `php8.2 -S 0.0.0.0:8888 -t /home/kali/www`（不走 Apache，不需要 root）
2. **MariaDB 已预装** — `sudo -S` 配合 kali 密码启动
3. **DVWA 部署** — git clone master → 解压到 `/home/kali/www/dvwa`
4. **Session 修复** — PHP 内置服务器默认 session.save_path 无写权限，指定 `/home/kali/php_sessions`

## 关键修复
| 问题 | 解决 |
|------|------|
| sudo 无密码 | 用 `echo kali \| sudo -S` 管道传入 |
| vmrun 不返回 stdout | 命令输出重定向到文件 → `copyFileFromGuestToHost` |
| PHP session 丢失 | 设置 session.save_path 到用户可写目录 |
| 登录重定向到 setup.php | DB 表未创建，POST setup.php 先初始化 |

## 扫描结果 (scan_dvwa.py)

**配置**：9 模块 × 13 手动端点 = 117 任务，并发 5，单任务超时 60s

| 指标 | 值 |
|------|-----|
| 耗时 | 511s (8.5min) |
| 漏洞总数 | 20 |
| SSRF | 12 (含误报) |
| LFI | 6 (含误报) |
| SQLi | 1 (布尔盲注, brute/username) |
| 信息泄露 | 1 |

**已知问题**：
- 大量 TIMEOUT (60s 单任务超时太紧)
- XSS 检出未被计入报告 (异步竞争/print 先于 return)
- CMDi 模块未检出 (可能静默超时)
- SSRF/LFI 误报较多 (DVWA 无对应漏洞的端点也被标记)

## 后续改进方向
1. 单任务超时提高到 120s
2. 调查 XSS 未计入报告的异步竞争根因
3. 验证 CMDi 模块在本地 DVWA 的 exec 端点是否正常工作
