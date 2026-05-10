#!/usr/bin/env python3
"""
WVS 版本备份工具
"""
import os
import shutil
import json
import time
import sys
from datetime import datetime
from pathlib import Path

class VersionBackup:
    """版本备份管理器"""
    
    def __init__(self, source_dir=None, versions_dir=None):
        # 源目录：当前WVS项目
        self.source_dir = source_dir or r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18"
        
        # 版本目录：版本档案存储
        self.versions_dir = versions_dir or r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-versions"
        
        # 确保目录存在
        os.makedirs(self.versions_dir, exist_ok=True)
        
        print(f"版本备份工具初始化")
        print(f"源目录: {self.source_dir}")
        print(f"版本目录: {self.versions_dir}")
    
    def backup_version(self, version, description=None):
        """备份当前版本"""
        print(f"\n开始备份版本: {version}")
        
        # 解析版本号
        major, minor, patch = self._parse_version(version)
        
        # 创建版本目录结构
        version_path = self._create_version_structure(major, minor, patch)
        
        # 复制文件
        self._copy_source_files(version_path)
        
        # 创建版本元数据
        metadata = self._create_metadata(version, description)
        self._save_metadata(version_path, metadata)
        
        # 创建版本标识文件
        self._create_version_file(version_path, version)
        
        print(f"版本备份完成: {version_path}")
        return version_path
    
    def _parse_version(self, version_str):
        """解析版本号"""
        # 移除v前缀
        if version_str.startswith('v'):
            version_str = version_str[1:]
        
        # 分割版本号
        parts = version_str.split('.')
        
        # 确保有3个部分
        while len(parts) < 3:
            parts.append('0')
        
        return parts[0], parts[1], parts[2]
    
    def _create_version_structure(self, major, minor, patch):
        """创建版本目录结构"""
        # 主版本目录
        major_minor_dir = os.path.join(self.versions_dir, f"v{major}.{minor}")
        os.makedirs(major_minor_dir, exist_ok=True)
        
        # 子版本目录
        version_dir = os.path.join(major_minor_dir, f"v{major}.{minor}.{patch}")
        
        # 如果目录已存在，添加时间戳后缀
        if os.path.exists(version_dir):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            version_dir = f"{version_dir}_{timestamp}"
        
        # 创建标准目录结构
        dirs = [
            version_dir,
            os.path.join(version_dir, "src"),
            os.path.join(version_dir, "docs"),
            os.path.join(version_dir, "tests"),
            os.path.join(version_dir, "config"),
            os.path.join(version_dir, "tools"),
            os.path.join(version_dir, "examples"),
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
        
        return version_dir
    
    def _copy_source_files(self, target_dir):
        """复制源文件到版本目录"""
        print(f"复制文件到: {target_dir}")
        
        # 要复制的文件类型
        file_extensions = ['.py', '.md', '.json', '.txt', '.yml', '.yaml', '.ini', '.cfg']
        
        # 要排除的目录
        exclude_dirs = ['__pycache__', '.git', '.idea', '.vscode', 'node_modules']
        
        # 要排除的文件
        exclude_files = ['*.log', '*.tmp', 'temp_*']
        
        # 统计信息
        stats = {'files': 0, 'size': 0}
        
        # 遍历源目录
        for root, dirs, files in os.walk(self.source_dir):
            # 排除目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            # 计算相对路径
            rel_path = os.path.relpath(root, self.source_dir)
            target_path = os.path.join(target_dir, "src", rel_path)
            
            # 创建目标目录
            if rel_path != '.':
                os.makedirs(target_path, exist_ok=True)
            
            # 复制文件
            for file in files:
                # 检查文件扩展名
                if any(file.endswith(ext) for ext in file_extensions):
                    src_file = os.path.join(root, file)
                    dst_file = os.path.join(target_path, file)
                    
                    try:
                        shutil.copy2(src_file, dst_file)
                        stats['files'] += 1
                        stats['size'] += os.path.getsize(src_file)
                    except Exception as e:
                        print(f"  警告: 复制文件失败 {file}: {e}")
        
        print(f"  复制完成: {stats['files']} 个文件, {stats['size']:,} 字节")
        return stats
    
    def _create_metadata(self, version, description=None):
        """创建版本元数据"""
        return {
            "version": version,
            "description": description or f"WVS {version} 版本备份",
            "backup_time": datetime.now().isoformat(),
            "source_directory": self.source_dir,
            "system_info": {
                "platform": sys.platform,
                "python_version": sys.version,
                "hostname": os.environ.get('COMPUTERNAME', 'unknown')
            },
            "file_stats": self._analyze_source_files()
        }
    
    def _analyze_source_files(self):
        """分析源文件统计信息"""
        stats = {
            "total_files": 0,
            "total_size": 0,
            "by_extension": {},
            "largest_files": []
        }
        
        # 遍历源目录
        for root, dirs, files in os.walk(self.source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    size = os.path.getsize(file_path)
                    ext = os.path.splitext(file)[1] or "无扩展名"
                    
                    stats["total_files"] += 1
                    stats["total_size"] += size
                    
                    # 按扩展名统计
                    stats["by_extension"][ext] = stats["by_extension"].get(ext, 0) + 1
                    
                    # 记录大文件
                    if size > 1024 * 1024:  # 大于1MB
                        stats["largest_files"].append({
                            "file": file,
                            "path": os.path.relpath(file_path, self.source_dir),
                            "size": size
                        })
                        
                except Exception:
                    continue
        
        # 按大小排序大文件
        stats["largest_files"].sort(key=lambda x: x["size"], reverse=True)
        stats["largest_files"] = stats["largest_files"][:10]  # 只保留前10个
        
        return stats
    
    def _save_metadata(self, version_dir, metadata):
        """保存元数据到文件"""
        metadata_file = os.path.join(version_dir, "VERSION_METADATA.json")
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print(f"  元数据保存: {metadata_file}")
    
    def _create_version_file(self, version_dir, version):
        """创建版本标识文件"""
        version_file = os.path.join(version_dir, "VERSION.txt")
        with open(version_file, 'w', encoding='utf-8') as f:
            f.write(f"WVS {version}\n")
            f.write(f"Backup Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source: {self.source_dir}\n")
        
        print(f"  版本标识文件: {version_file}")
    
    def list_versions(self):
        """列出所有已备份的版本"""
        print("\n已备份的版本:")
        
        versions = []
        
        # 遍历版本目录
        for major_minor in os.listdir(self.versions_dir):
            major_minor_path = os.path.join(self.versions_dir, major_minor)
            
            if os.path.isdir(major_minor_path) and major_minor.startswith('v'):
                for version in os.listdir(major_minor_path):
                    version_path = os.path.join(major_minor_path, version)
                    
                    if os.path.isdir(version_path) and version.startswith('v'):
                        # 读取版本文件
                        version_file = os.path.join(version_path, "VERSION.txt")
                        if os.path.exists(version_file):
                            with open(version_file, 'r') as f:
                                first_line = f.readline().strip()
                        else:
                            first_line = version
                        
                        # 获取目录大小
                        size = self._get_directory_size(version_path)
                        
                        versions.append({
                            "name": version,
                            "path": version_path,
                            "display": first_line,
                            "size": size,
                            "mtime": os.path.getmtime(version_path)
                        })
        
        # 按修改时间排序
        versions.sort(key=lambda x: x["mtime"], reverse=True)
        
        # 显示版本列表
        for i, ver in enumerate(versions, 1):
            size_mb = ver["size"] / (1024 * 1024)
            mtime_str = datetime.fromtimestamp(ver["mtime"]).strftime("%Y-%m-%d %H:%M")
            print(f"{i:2d}. {ver['display']:20s} {size_mb:6.1f} MB  {mtime_str}")
        
        return versions
    
    def _get_directory_size(self, directory):
        """计算目录大小"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
        return total_size


def main():
    """主函数"""
    print("=" * 60)
    print("WVS 版本备份工具")
    print("=" * 60)
    
    # 创建备份管理器
    backup = VersionBackup()
    
    # 检查参数
    if len(sys.argv) > 1:
        version = sys.argv[1]
        description = sys.argv[2] if len(sys.argv) > 2 else None
        
        # 执行备份
        backup.backup_version(version, description)
    else:
        # 显示菜单
        print("\n使用方法:")
        print("  1. 备份版本: python version_backup.py <版本号> [描述]")
        print("  2. 列出版本: python version_backup.py --list")
        print("  3. 交互模式: 直接运行")
        
        # 交互模式
        print("\n交互模式:")
        
        # 列出现有版本
        backup.list_versions()
        
        # 询问是否备份
        print("\n是否备份当前版本？")
        version = input("输入版本号 (例如: v18.4.2): ").strip()
        
        if version:
            description = input("版本描述 (可选): ").strip() or None
            backup.backup_version(version, description)
        else:
            print("未输入版本号，退出")


if __name__ == "__main__":
    main()