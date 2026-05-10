#!/usr/bin/env python3
"""
立即下载Nuclei模板 - 国内网络优化版
"""
import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def download_nuclei_templates():
    """下载Nuclei模板"""
    print("[*] 开始下载Nuclei官方模板...")
    
    try:
        from nuclei_manager import NucleiManager
        
        # 创建管理器
        manager = NucleiManager()
        
        print("[*] 使用国内优化下载源:")
        for source in manager.sources:
            print(f"  - {source.name}: {source.base_url}")
        
        # 只下载核心分类，加快速度
        core_categories = ["web", "cves", "technologies"]
        
        print(f"\n[*] 下载核心分类: {core_categories}")
        print("[*] 使用jsdelivr CDN加速...")
        
        # 开始下载
        success = await manager.download_templates(
            categories=core_categories,
            mirror="jsdelivr",
            show_progress=True
        )
        
        if success:
            print("\n[SUCCESS] Nuclei模板下载完成!")
            
            # 统计下载的文件
            template_dir = manager.template_dir
            if template_dir.exists():
                template_count = sum(1 for _ in template_dir.rglob("*.yaml") if _.is_file())
                print(f"[*] 下载模板数: {template_count}")
                
                # 列出主要分类
                print("\n[*] 已下载分类:")
                for category_dir in template_dir.iterdir():
                    if category_dir.is_dir():
                        yaml_count = sum(1 for _ in category_dir.rglob("*.yaml") if _.is_file())
                        print(f"  - {category_dir.name}: {yaml_count}个模板")
            
            return True
        else:
            print("\n[ERROR] 模板下载失败")
            return False
            
    except Exception as e:
        print(f"[ERROR] 下载过程出错: {e}")
        import traceback
        traceback.print_exc()
        return False


async def check_nuclei_integration():
    """检查Nuclei集成"""
    print("\n[*] 检查Nuclei集成...")
    
    try:
        # 检查Nuclei二进制
        nuclei_path = r"C:\Tools\nuclei\nuclei.exe"
        
        if os.path.exists(nuclei_path):
            print(f"[SUCCESS] Nuclei已安装: {nuclei_path}")
            
            # 测试运行
            import subprocess
            try:
                result = subprocess.run([nuclei_path, "-version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version = result.stdout.strip().split('\n')[0]
                    print(f"[*] Nuclei版本: {version}")
                else:
                    print(f"[WARNING] 获取版本失败: {result.stderr[:100]}")
            except Exception as e:
                print(f"[WARNING] 检查版本出错: {e}")
        else:
            print(f"[WARNING] Nuclei未找到: {nuclei_path}")
            print("[INFO] 请确保Nuclei已安装到C:\\Tools\\nuclei\\")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 集成检查失败: {e}")
        return False


async def main():
    """主函数"""
    print("=" * 60)
    print("Nuclei模板下载器 - 国内网络优化版")
    print("=" * 60)
    
    # 检查集成
    integration_ok = await check_nuclei_integration()
    
    if not integration_ok:
        print("\n[WARNING] Nuclei集成检查失败，继续尝试下载...")
    
    # 下载模板
    download_ok = await download_nuclei_templates()
    
    print("\n" + "=" * 60)
    if download_ok:
        print("[SUCCESS] Nuclei模板下载任务完成!")
        print("[NEXT] 模板已就绪，可以用于漏洞扫描")
    else:
        print("[WARNING] 模板下载可能不完整")
        print("[INFO] 可以手动下载: https://github.com/projectdiscovery/nuclei-templates")
    
    return download_ok


if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    success = asyncio.run(main())
    sys.exit(0 if success else 1)