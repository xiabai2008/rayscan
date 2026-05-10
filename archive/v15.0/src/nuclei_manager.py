"""Nuclei 模板管理器 - 智能下载器

国内网络优化：
1. 多源下载：jsDelivr CDN、GitHub Proxy、原始GitHub
2. 断点续传：大文件分块下载
3. 模板管理：分类下载、增量更新、版本控制
4. CLI接口：update/list/clean命令

与Nuclei二进制兼容
"""
import asyncio
import aiohttp
import os
import json
import hashlib
import shutil
import zipfile
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urljoin


@dataclass
class TemplateInfo:
    """模板信息"""
    name: str
    path: str
    category: str
    severity: str
    size: int
    checksum: str = ""
    last_updated: str = ""


@dataclass
class DownloadSource:
    """下载源"""
    name: str
    base_url: str
    priority: int


@dataclass
class DownloadProgress:
    """下载进度"""
    total_size: int = 0
    downloaded: int = 0
    current_speed: float = 0.0
    status: str = "idle"  # idle, downloading, paused, completed, failed
    error: str = ""


class NucleiManager:
    """Nuclei模板管理器"""

    # 下载源配置
    DEFAULT_SOURCES = [
        DownloadSource("jsdelivr", "https://cdn.jsdelivr.net/gh/projectdiscovery/nuclei-templates@main", 1),
        DownloadSource("ghproxy", "https://ghproxy.com/https://github.com/projectdiscovery/nuclei-templates", 2),
        DownloadSource("github", "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main", 3),
        DownloadSource("mirror1", "https://mirror.ghproxy.com/https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main", 4),
    ]

    # 模板分类
    CATEGORIES = {
        "web": ["cves", "vulnerabilities", "exposed-panels", "default-logins",
                "technologies", "token-spray", "miscellaneous", "files"],
        "network": ["network", "dns", "ssl"],
        "cms": ["cms", "wordpress", "drupal", "joomla", "magento"],
        "misc": ["iot", "android", "hardcoded-secrets"],
    }

    # 配置
    CHUNK_SIZE = 1024 * 1024  # 1MB per chunk
    MAX_RETRIES = 3
    TIMEOUT = aiohttp.ClientTimeout(total=300, connect=30, sock_read=30)
    MAX_CONCURRENT = 3

    def __init__(self, template_dir: str = "./nuclei-templates", cache_dir: str = "./.nuclei-cache"):
        self.template_dir = Path(template_dir)
        self.cache_dir = Path(cache_dir)
        self.sources = self.DEFAULT_SOURCES.copy()
        self.progress = DownloadProgress()
        self._version_file = self.cache_dir / "version.json"
        self._index_file = self.cache_dir / "templates_index.json"

    # ==================== 核心下载功能 ====================

    async def download_templates(
        self,
        categories: Optional[List[str]] = None,
        mirror: str = "jsdelivr",
        show_progress: bool = True
    ) -> bool:
        """下载模板主函数

        Args:
            categories: 要下载的分类，None表示全部
            mirror: 使用的镜像源
            show_progress: 是否显示进度

        Returns:
            bool: 下载是否成功
        """
        source = self._get_source(mirror)
        if not source:
            print(f"[!] Unknown mirror: {mirror}")
            return False

        print(f"[*] Using source: {source.name} ({source.base_url})")

        # 创建目录
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # 获取模板列表
        if categories:
            target_paths = []
            for cat in categories:
                if cat in self.CATEGORIES:
                    target_paths.extend(self.CATEGORIES[cat])
                else:
                    target_paths.append(cat)
        else:
            # 下载全部 - 获取仓库信息
            target_paths = None

        try:
            # 下载主压缩包（更快）
            success = await self._download_full_archive(source, show_progress)
            if success:
                await self._extract_and_index()
                await self._save_version()
                print(f"\n[+] Templates installed to: {self.template_dir}")
                return True

            # 如果压缩包下载失败，尝试分类下载
            print("[*] Trying category-by-category download...")
            return await self._download_by_category(source, categories or list(self.CATEGORIES.keys()), show_progress)

        except Exception as e:
            print(f"[!] Download failed: {e}")
            # 内置fallback
            await self._download_fallback_templates()
            return False

    async def download_with_resume(
        self,
        url: str,
        save_path: Path,
        chunk_size: int = None,
        show_progress: bool = True
    ) -> bool:
        """断点续传下载

        Args:
            url: 下载URL
            save_path: 保存路径
            chunk_size: 分块大小，默认1MB
            show_progress: 是否显示进度

        Returns:
            bool: 下载是否成功
        """
        chunk_size = chunk_size or self.CHUNK_SIZE

        # 检查已有文件
        resume_pos = 0
        if save_path.exists():
            resume_pos = save_path.stat().st_size
            print(f"[*] Resuming from byte {resume_pos}")

        headers = {"Range": f"bytes={resume_pos}-"} if resume_pos > 0 else {}

        for attempt in range(self.MAX_RETRIES):
            try:
                async with aiohttp.ClientSession(timeout=self.TIMEOUT) as session:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 416:  # Range not satisfiable
                            # 文件已完整
                            return True

                        if resp.status == 206:
                            # 断点续传
                            pass
                        elif resp.status != 200 and resp.status != 206:
                            print(f"[!] HTTP {resp.status}, retrying...")
                            await asyncio.sleep(2 ** attempt)
                            continue

                        total_size = int(resp.headers.get('Content-Length', 0)) + resume_pos
                        self.progress.total_size = total_size
                        self.progress.status = "downloading"

                        with open(save_path, "ab" if resume_pos > 0 else "wb") as f:
                            downloaded = resume_pos
                            start_time = asyncio.get_event_loop().time()
                            last_update = start_time

                            async for chunk in resp.content.iter_chunked(chunk_size):
                                f.write(chunk)
                                downloaded += len(chunk)
                                self.progress.downloaded = downloaded

                                # 显示进度
                                if show_progress:
                                    current_time = asyncio.get_event_loop().time()
                                    if current_time - last_update >= 1:  # 每秒更新
                                        speed = len(chunk) / (current_time - last_update)
                                        self.progress.current_speed = speed
                                        pct = (downloaded / total_size * 100) if total_size > 0 else 0
                                        print(f"\r[*] Progress: {pct:.1f}% ({downloaded/1024/1024:.1f}MB/{total_size/1024/1024:.1f}MB) {speed/1024:.0f}KB/s", end="")
                                        last_update = current_time

                        self.progress.status = "completed"
                        return True

            except asyncio.TimeoutError:
                print(f"[!] Timeout on attempt {attempt + 1}/{self.MAX_RETRIES}")
            except aiohttp.ClientError as e:
                print(f"[!] Connection error: {e}, retrying...")
            except Exception as e:
                print(f"[!] Error: {e}")

            await asyncio.sleep(2 ** attempt)  # 指数退避

        self.progress.status = "failed"
        self.progress.error = "Max retries exceeded"
        return False

    async def update_templates(self, incremental: bool = True) -> bool:
        """更新模板

        Args:
            incremental: 是否增量更新

        Returns:
            bool: 更新是否成功
        """
        if not incremental:
            return await self.download_templates()

        # 检查版本
        current_version = await self._get_current_version()
        latest_version = await self._check_latest_version()

        if current_version == latest_version:
            print("[*] Templates are up to date")
            return True

        print(f"[*] Updating from v{current_version} to v{latest_version}")

        # 增量更新逻辑
        return await self._incremental_update(latest_version)

    # ==================== 辅助方法 ====================

    def _get_source(self, mirror: str) -> Optional[DownloadSource]:
        """获取镜像源"""
        for source in self.sources:
            if source.name == mirror:
                return source
        return self.sources[0]  # 默认使用第一个

    async def _download_full_archive(self, source: DownloadSource, show_progress: bool) -> bool:
        """下载完整压缩包"""
        # Nuclei templates 仓库的ZIP包
        archive_url = f"https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main"

        print(f"[*] Downloading full template archive...")
        temp_zip = self.cache_dir / "templates.zip"

        success = await self.download_with_resume(
            archive_url,
            temp_zip,
            show_progress=show_progress
        )

        if success and temp_zip.exists():
            print(f"\n[*] Extracting archive...")
            try:
                with zipfile.ZipFile(temp_zip, 'r') as zf:
                    # 解压到模板目录
                    for member in zf.namelist():
                        # 跳过根目录
                        if member.startswith('nuclei-templates-main/'):
                            member_path = member.replace('nuclei-templates-main/', '')
                            if member_path:
                                target = self.template_dir / member_path
                                if member.endswith('/'):
                                    target.mkdir(parents=True, exist_ok=True)
                                else:
                                    target.parent.mkdir(parents=True, exist_ok=True)
                                    with zf.open(member) as src:
                                        with open(target, 'wb') as dst:
                                            dst.write(src.read())
                return True
            except Exception as e:
                print(f"[!] Extraction failed: {e}")
                return False

        return False

    async def _download_by_category(
        self,
        source: DownloadSource,
        categories: List[str],
        show_progress: bool
    ) -> bool:
        """按分类下载"""
        success_count = 0

        for category in categories:
            print(f"\n[*] Downloading category: {category}")

            # 获取该分类的文件列表
            api_url = f"{source.base_url}/.index.json"
            try:
                async with aiohttp.ClientSession(timeout=self.TIMEOUT) as session:
                    async with session.get(api_url) as resp:
                        if resp.status != 200:
                            continue

                        index_data = await resp.json()

                        # 过滤该分类的文件
                        category_files = [
                            f for f in index_data.get("directory", [])
                            if category in f.get("path", "")
                        ]

                        # 下载文件
                        for file_info in category_files[:50]:  # 限制数量
                            file_path = file_info.get("path", "")
                            if not file_path.endswith(('.yaml', '.yml')):
                                continue

                            url = f"{source.base_url}/{file_path}"
                            save_path = self.template_dir / file_path

                            if await self.download_with_resume(url, save_path, show_progress=False):
                                success_count += 1

            except Exception as e:
                print(f"[!] Error downloading {category}: {e}")
                continue

        return success_count > 0

    async def _download_fallback_templates(self):
        """下载内置fallback模板（最小集）"""
        print("[*] Using bundled minimal templates...")

        minimal_templates = """
id: basic-sql-injection
info:
  name: Basic SQL Injection
  severity: critical
  author: wvs
requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable?id=1'"
    matchers:
      - type: regex
        regex:
          - "SQL syntax.*MySQL"
          - "Warning.*mysql_"
"""

        minimal_dir = self.template_dir / "cves" / "low"
        minimal_dir.mkdir(parents=True, exist_ok=True)

        template_file = minimal_dir / "basic-sqli.yaml"
        with open(template_file, 'w') as f:
            f.write(minimal_templates)

        print(f"[+] Minimal templates saved to: {template_file}")

    async def _extract_and_index(self):
        """提取并建立索引"""
        index: Dict[str, TemplateInfo] = {}

        for yaml_file in self.template_dir.rglob("*.yaml"):
            if yaml_file.name.startswith("."):
                continue

            rel_path = yaml_file.relative_to(self.template_dir)

            # 简单分类推断
            category = rel_path.parts[0] if rel_path.parts else "unknown"

            index[str(rel_path)] = TemplateInfo(
                name=yaml_file.stem,
                path=str(rel_path),
                category=category,
                severity="medium",  # 默认
                size=yaml_file.stat().st_size,
                last_updated=datetime.now().isoformat()
            )

        # 保存索引
        with open(self._index_file, 'w') as f:
            json.dump({k: vars(v) for k, v in index.items()}, f, indent=2)

        print(f"[*] Indexed {len(index)} templates")

    async def _save_version(self):
        """保存版本信息"""
        version_data = {
            "version": datetime.now().strftime("%Y%m%d"),
            "updated": datetime.now().isoformat(),
            "source": "github"
        }

        with open(self._version_file, 'w') as f:
            json.dump(version_data, f, indent=2)

    async def _get_current_version(self) -> str:
        """获取当前版本"""
        if self._version_file.exists():
            with open(self._version_file, 'r') as f:
                data = json.load(f)
                return data.get("version", "unknown")
        return "unknown"

    async def _check_latest_version(self) -> str:
        """检查最新版本"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                api_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates"
                async with session.get(api_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # 使用最后更新时间
                        return data.get("updated_at", "")[:10].replace("-", "")
        except:
            pass

        return datetime.now().strftime("%Y%m%d")

    async def _incremental_update(self, target_version: str) -> bool:
        """增量更新"""
        print("[*] Incremental update not fully implemented, doing full download...")
        return await self.download_templates()

    # ==================== CLI 命令 ====================

    async def list_templates(self) -> List[TemplateInfo]:
        """列出已安装模板"""
        if not self._index_file.exists():
            await self._extract_and_index()

        templates = []
        with open(self._index_file, 'r') as f:
            data = json.load(f)
            for v in data.values():
                templates.append(TemplateInfo(**v))

        return templates

    async def clean_cache(self):
        """清理缓存"""
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            print(f"[*] Cleaned cache: {self.cache_dir}")

        # 清理临时文件
        temp_files = list(self.template_dir.glob("*.tmp"))
        for tf in temp_files:
            tf.unlink()

        print("[*] Cache cleaned")

    def get_template_dir(self) -> Path:
        """获取模板目录"""
        return self.template_dir


# ==================== CLI 入口 ====================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Nuclei Template Manager")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # update 命令
    update_parser = subparsers.add_parser("update", help="Update templates")
    update_parser.add_argument("--category", "-c", nargs="+", help="Specific categories")
    update_parser.add_argument("--mirror", "-m", default="jsdelivr",
                               choices=["jsdelivr", "ghproxy", "github", "mirror1"],
                               help="Download mirror")

    # list 命令
    subparsers.add_parser("list", help="List installed templates")

    # clean 命令
    subparsers.add_parser("clean", help="Clean cache")

    # status 命令
    subparsers.add_parser("status", help="Show status")

    args = parser.parse_args()

    # 创建管理器
    manager = NucleiManager()

    if args.command == "update":
        success = await manager.download_templates(
            categories=args.category,
            mirror=args.mirror
        )
        return 0 if success else 1

    elif args.command == "list":
        templates = await manager.list_templates()

        # 按分类统计
        by_category: Dict[str, int] = {}
        for t in templates:
            by_category[t.category] = by_category.get(t.category, 0) + 1

        print(f"\n[*] Total templates: {len(templates)}")
        print("\nBy category:")
        for cat, count in sorted(by_category.items()):
            print(f"  {cat}: {count}")

        return 0

    elif args.command == "clean":
        await manager.clean_cache()
        return 0

    elif args.command == "status":
        template_dir = manager.get_template_dir()
        version = await manager._get_current_version()

        print(f"\n[*] Template Directory: {template_dir}")
        print(f"[*] Cache Directory: {manager.cache_dir}")
        print(f"[*] Current Version: {version}")
        print(f"[*] Sources: {[s.name for s in manager.sources]}")

        # 统计
        templates = await manager.list_templates()
        print(f"[*] Installed Templates: {len(templates)}")

        return 0

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))