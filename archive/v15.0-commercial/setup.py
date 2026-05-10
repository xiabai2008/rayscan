from setuptools import setup, find_packages

setup(
    name="wvs",
    version="1.0.0",
    description="Web Vulnerability Scanner - Web 漏洞扫描工具",
    author="Security Team",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "click>=8.1.0",
    ],
    entry_points={
        "console_scripts": [
            "wvs=wvs.cli:main",
        ],
    },
    python_requires=">=3.10",
)
