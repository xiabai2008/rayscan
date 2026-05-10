#!/usr/bin/env python3
"""
WVS Web管理界面集成演示
"""
import asyncio
import requests
import time
import json
from datetime import datetime

class WVSWebDemo:
    """WVS Web界面演示"""
    
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api/v1"
        print(f"WVS Web管理界面演示")
        print(f"API地址: {self.api_url}")
        print("=" * 60)
    
    async def test_scanner_status(self):
        """测试扫描器状态API"""
        print("1. 测试扫描器状态API...")
        
        try:
            response = requests.get(f"{self.api_url}/scanner/status")
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 状态: {data['status']}")
                print(f"   ✅ 版本: {data['version']}")
                print(f"   ✅ 能力: {', '.join(data['capabilities'].keys())}")
                print(f"   ✅ 性能: {data['performance']}")
                return data
            else:
                print(f"   ❌ 失败: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"   ❌ 错误: {e}")
            return None
    
    async def test_start_scan(self):
        """测试启动扫描API"""
        print("\n2. 测试启动扫描API...")
        
        scan_config = {
            "scan_type": "comprehensive",
            "targets": [
                "http://192.168.18.131/dvwa/",
                "http://192.168.18.131/mutillidae/"
            ],
            "scan_depth": "medium",
            "enable_concurrent": True,
            "enable_cache": True,
            "enable_rate_limit": True,
            "modules": {
                "zero_day": True,
                "logic": True,
                "api_security": True,
                "auth_bypass": True
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/scanner/start",
                json=scan_config
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 任务ID: {data['task_id']}")
                print(f"   ✅ 状态: {data['status']}")
                print(f"   ✅ 预估时间: {data['estimated_time']}")
                return data['task_id']
            else:
                print(f"   ❌ 失败: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"   ❌ 错误: {e}")
            return None
    
    async def test_scan_status(self, task_id):
        """测试扫描状态API"""
        if not task_id:
            return
        
        print(f"\n3. 测试扫描状态API (任务: {task_id})...")
        
        try:
            response = requests.get(f"{self.api_url}/scanner/status/{task_id}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 状态: {data['status']}")
                print(f"   ✅ 进度: {data['progress']}%")
                print(f"   ✅ 开始时间: {data['start_time']}")
                print(f"   ✅ 结果就绪: {data['results_available']}")
                return data
            elif response.status_code == 404:
                print(f"   ⚠️  任务不存在")
                return None
            else:
                print(f"   ❌ 失败: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"   ❌ 错误: {e}")
            return None
    
    async def test_get_results(self, task_id):
        """测试获取结果API"""
        if not task_id:
            return
        
        print(f"\n4. 测试获取扫描结果API (任务: {task_id})...")
        
        try:
            response = requests.get(f"{self.api_url}/scanner/results/{task_id}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 扫描ID: {data['scan_id']}")
                print(f"   ✅ 目标数量: {data['summary']['total_targets']}")
                print(f"   ✅ 漏洞总数: {data['summary']['total_vulnerabilities']}")
                print(f"   ✅ 严重程度分布: {data['summary']['severity_distribution']}")
                
                # 显示前3个漏洞
                if data['vulnerabilities']:
                    print(f"   ✅ 漏洞示例:")
                    for i, vuln in enumerate(data['vulnerabilities'][:3], 1):
                        print(f"      {i}. [{vuln['severity'].upper()}] {vuln['type']}: {vuln['description']}")
                
                return data
            elif response.status_code == 202:
                print(f"   ⏳ 扫描尚未完成")
                return None
            elif response.status_code == 404:
                print(f"   ⚠️  任务不存在")
                return None
            else:
                print(f"   ❌ 失败: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"   ❌ 错误: {e}")
            return None
    
    async def test_list_tasks(self):
        """测试列出任务API"""
        print("\n5. 测试列出所有任务API...")
        
        try:
            response = requests.get(f"{self.api_url}/scanner/tasks")
            
            if response.status_code == 200:
                tasks = response.json()
                print(f"   ✅ 任务总数: {len(tasks)}")
                
                if tasks:
                    print(f"   ✅ 任务列表:")
                    for i, task in enumerate(tasks[:5], 1):  # 显示前5个
                        print(f"      {i}. {task['task_id']}: {task['status']} ({task['progress']}%)")
                else:
                    print(f"   ℹ️  无任务")
                
                return tasks
            else:
                print(f"   ❌ 失败: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"   ❌ 错误: {e}")
            return None
    
    async def test_demo_scans(self):
        """测试演示扫描API"""
        print("\n6. 测试演示扫描API...")
        
        # 测试快速演示扫描
        try:
            response = requests.post(f"{self.api_url}/scanner/demo/quick")
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 快速演示扫描启动: {data['task_id']}")
            else:
                print(f"   ❌ 快速演示失败: {response.status_code}")
        except Exception as e:
            print(f"   ❌ 快速演示错误: {e}")
        
        # 测试全面演示扫描
        try:
            response = requests.post(f"{self.api_url}/scanner/demo/comprehensive")
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 全面演示扫描启动: {data['task_id']}")
            else:
                print(f"   ❌ 全面演示失败: {response.status_code}")
        except Exception as e:
            print(f"   ❌ 全面演示错误: {e}")
    
    async def run_full_demo(self):
        """运行完整演示"""
        print("=" * 60)
        print("WVS Web管理界面 - 完整集成演示")
        print("=" * 60)
        
        # 1. 测试扫描器状态
        status = await self.test_scanner_status()
        if not status:
            print("❌ 扫描器状态测试失败，停止演示")
            return
        
        # 2. 启动扫描
        task_id = await self.test_start_scan()
        
        if task_id:
            # 3. 检查扫描状态（多次）
            print(f"\n等待扫描进度...")
            for i in range(3):
                await asyncio.sleep(3)
                await self.test_scan_status(task_id)
            
            # 4. 获取结果
            await self.test_get_results(task_id)
        
        # 5. 列出所有任务
        await self.test_list_tasks()
        
        # 6. 测试演示扫描
        await self.test_demo_scans()
        
        print("\n" + "=" * 60)
        print("演示完成!")
        print("=" * 60)
        
        # 生成演示报告
        report = {
            "demo_time": datetime.now().isoformat(),
            "api_base_url": self.api_url,
            "tests_performed": [
                "scanner_status",
                "start_scan",
                "scan_status",
                "get_results",
                "list_tasks",
                "demo_scans"
            ],
            "notes": "这是一个模拟演示，实际WVS扫描器集成需要连接真实的扫描引擎"
        }
        
        # 保存报告
        with open("wvs_web_demo_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"演示报告已保存: wvs_web_demo_report.json")

async def main():
    """主函数"""
    demo = WVSWebDemo()
    
    try:
        await demo.run_full_demo()
    except KeyboardInterrupt:
        print("\n演示被用户中断")
    except Exception as e:
        print(f"\n演示出错: {e}")

def check_backend_status():
    """检查后端服务状态"""
    print("检查后端服务状态...")
    
    try:
        # 尝试连接健康检查端点
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ 后端服务运行正常")
            return True
        else:
            print(f"❌ 后端服务异常: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ 无法连接到后端服务")
        print("请确保后端服务已启动:")
        print("  cd wvs_web/backend")
        print("  uvicorn main:app --reload")
        return False
    except Exception as e:
        print(f"❌ 检查失败: {e}")
        return False

if __name__ == "__main__":
    print("WVS Web管理界面集成演示启动")
    print("=" * 60)
    
    # 检查后端服务
    if not check_backend_status():
        print("\n⚠️  后端服务未运行，启动模拟演示...")
        
        # 创建模拟服务检查文件
        with open("backend_not_running_note.txt", "w") as f:
            f.write("后端服务未运行，这是一个模拟演示。\n")
            f.write("要运行完整演示，请启动后端服务：\n")
            f.write("1. cd wvs_web/backend\n")
            f.write("2. pip install -r requirements.txt\n")
            f.write("3. uvicorn main:app --reload\n")
    
    # 运行演示
    asyncio.run(main())