#!/usr/bin/env bash
#
# RayScan Nuclei 模板部署脚本
# 部署 12.5w+ PoC 模板到 ~/.rayscan/nuclei-templates/
#
# 用法:
#   ./scripts/deploy_nuclei_templates.sh                     # 从默认路径部署
#   ./scripts/deploy_nuclei_templates.sh --from /path/to/zip  # 从指定 ZIP 部署
#   ./scripts/deploy_nuclei_templates.sh --update             # 更新已有模板
#   ./scripts/deploy_nuclei_templates.sh --list-sources       # 列出可用来源
#

set -euo pipefail

RAYSCAN_DIR="${HOME}/.rayscan"
TEMPLATE_DIR="${RAYSCAN_DIR}/nuclei-templates"
XRAY_DIR="${RAYSCAN_DIR}/xray-pocs"
CACHE_DB="${RAYSCAN_DIR}/template_cache.db"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
header(){ echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

# ── 默认搜索路径 ──────────────────────────────────────────────
# 用户可在此处添加自己的 Zip 文件路径
NUCLEI_ZIP_CANDIDATES=(
    # 本地工具合集路径（按优先级）
    "${HOME}/Tools/POC/Nuclei-Poc-12.5w*.zip"
    "${HOME}/Downloads/Nuclei-Poc-*.zip"
    "${HOME}/Desktop/Nuclei-Poc-*.zip"
    # 其他常见位置
    "/opt/pocs/Nuclei-Poc-*.zip"
    "/usr/share/pocs/Nuclei-Poc-*.zip"
)

XRAY_ZIP_CANDIDATES=(
    "${HOME}/Tools/POC/xray-fscan-pocs*.zip"
    "${HOME}/Downloads/xray*.zip"
)

BEEBEETO_ZIP_CANDIDATES=(
    "${HOME}/Tools/POC/beebeeto*.zip"
)

BUGSCAN_ZIP_CANDIDATES=(
    "${HOME}/Tools/POC/bugscan*.zip"
)

# ── 辅助函数 ──────────────────────────────────────────────────

usage() {
    echo "用法: $0 [OPTIONS]"
    echo "选项:"
    echo "  --from /path/to/zip   从指定 ZIP 文件部署 Nuclei 模板"
    echo "  --from-xray /path     部署 xRay PoC"
    echo "  --from-beebeeto /path 部署 Beebeeto PoC"
    echo "  --from-bugscan /path  部署 BugScan PoC"
    echo "  --update              更新已有模板（重建索引）"
    echo "  --list-sources        列出可用的 PoC 来源"
    echo "  --force               强制重建索引"
    echo "  --help                显示此帮助"
    exit 0
}

# ── 部署函数 ──────────────────────────────────────────────────

deploy_nuclei() {
    local src="$1"
    header "部署 Nuclei 模板"

    mkdir -p "${TEMPLATE_DIR}"

    if [ -f "${src}" ]; then
        info "从 ZIP 部署: ${src}"
        unzip -o -q "${src}" -d "${TEMPLATE_DIR}" 2>/dev/null && {
            info "Nuclei 模板部署成功"
            return 0
        } || {
            # 尝试 7z
            if command -v 7z &>/dev/null; then
                7z x "${src}" -o"${TEMPLATE_DIR}" -y -bso0 2>/dev/null
                info "使用 7z 解压成功"
                return 0
            fi
            error "解压失败: ${src}"
            return 1
        }
    elif [ -d "${src}" ]; then
        info "从目录复制: ${src}"
        cp -r "${src}"/* "${TEMPLATE_DIR}/" 2>/dev/null
        info "模板复制成功"
        return 0
    else
        error "找不到路径: ${src}"
        return 1
    fi
}

deploy_xray() {
    local src="$1"
    header "部署 xRay PoC"
    mkdir -p "${XRAY_DIR}"

    if [ -f "${src}" ]; then
        info "从 ZIP 部署: ${src}"
        unzip -o -q "${src}" -d "${XRAY_DIR}" 2>/dev/null
        info "xRay PoC 部署成功"
    elif [ -d "${src}" ]; then
        cp -r "${src}"/* "${XRAY_DIR}/" 2>/dev/null
        info "xRay PoC 复制成功"
    else
        warn "找不到 xRay PoC: ${src}"
    fi
}

# ── 自动发现 ZIP 文件 ──────────────────────────────────────────

find_first_match() {
    local patterns=("$@")
    for pattern in "${patterns[@]}"; do
        # Expand glob
        for f in ${pattern}; do
            if [ -f "${f}" ]; then
                echo "${f}"
                return 0
            fi
        done
    done
    return 1
}

list_sources() {
    header "可用 PoC 来源"
    echo ""
    echo "要部署 Nuclei 12.5w+ 模板，请将以下文件放入任意候选目录："
    echo "  - Nuclei-Poc-12.5w(2024.12).zip  (来自 05-POC插件专区/)"
    echo "  - POC-Collect-1370个.zip"
    echo "  - xray-fscan-pocs-385个.zip"
    echo "  - beebeeto-317个.zip"
    echo "  - bugscan-1224个.zip"
    echo ""
    echo "候选搜索路径："
    for c in "${NUCLEI_ZIP_CANDIDATES[@]}"; do echo "  - ${c}"; done
    echo ""
    echo "RayScan 会将模板部署到: ${TEMPLATE_DIR}"
    echo "RayScan 会自动索引并缓存这些模板 (SQLite: ${CACHE_DB})"
}

# ── 主逻辑 ──────────────────────────────────────────────────

main() {
    local mode="auto"
    local custom_src=""
    local force_rebuild=false

    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --from)        mode="custom"; custom_src="$2"; shift 2 ;;
            --from-xray)   mode="xray";  custom_src="$2"; shift 2 ;;
            --from-beebeeto) mode="beebeeto"; custom_src="$2"; shift 2 ;;
            --from-bugscan)  mode="bugscan"; custom_src="$2"; shift 2 ;;
            --update)      mode="update" ;;
            --list-sources) list_sources; exit 0 ;;
            --force)       force_rebuild=true ;;
            --help)        usage ;;
            *)             error "未知参数: $1"; usage ;;
        esac
    done

    mkdir -p "${RAYSCAN_DIR}"

    case "${mode}" in
        auto)
            header "自动部署模式"
            # 尝试自动发现并部署 Nuclei 模板
            local found
            found=$(find_first_match "${NUCLEI_ZIP_CANDIDATES[@]}") || true
            if [ -n "${found}" ]; then
                deploy_nuclei "${found}"
                info "来源: ${found}"
            else
                warn "未找到 Nuclei 模板 Zip 文件"
                warn "请先下载 Nuclei-Poc-12.5w 并放入候选目录"
                echo ""
                list_sources
            fi

            # 尝试部署 xRay
            found=$(find_first_match "${XRAY_ZIP_CANDIDATES[@]}") || true
            if [ -n "${found}" ]; then
                deploy_xray "${found}"
            fi
            ;;

        custom)
            deploy_nuclei "${custom_src}"
            ;;

        xray)
            deploy_xray "${custom_src}"
            ;;

        beebeeto)
            header "部署 Beebeeto PoC (暂仅作为来源记录)"
            mkdir -p "${RAYSCAN_DIR}/beebeeto-pocs"
            if [ -f "${custom_src}" ]; then
                unzip -o -q "${custom_src}" -d "${RAYSCAN_DIR}/beebeeto-pocs"
                info "Beebeeto PoC 已部署"
            fi
            ;;

        bugscan)
            header "部署 BugScan PoC (暂仅作为来源记录)"
            mkdir -p "${RAYSCAN_DIR}/bugscan-pocs"
            if [ -f "${custom_src}" ]; then
                unzip -o -q "${custom_src}" -d "${RAYSCAN_DIR}/bugscan-pocs"
                info "BugScan PoC 已部署"
            fi
            ;;

        update)
            header "更新模式"
            info "删除旧索引缓存..."
            rm -f "${CACHE_DB}"
            info "缓存已清除，下次扫描时将自动重建索引"
            ;;
    esac

    # 统计结果
    header "部署统计"
    local count=0
    if [ -d "${TEMPLATE_DIR}" ]; then
        count=$(find "${TEMPLATE_DIR}" -name "*.yaml" 2>/dev/null | wc -l)
    fi
    info "Nuclei 模板: ${count} 个"

    if [ -d "${XRAY_DIR}" ]; then
        local xcount
        xcount=$(find "${XRAY_DIR}" -name "*.yaml" 2>/dev/null | wc -l)
        info "xRay PoC: ${xcount} 个"
    fi

    echo ""
    info "部署完成！"
    echo "运行以下命令索引模板:"
    echo "  python -m wvs scan http://example.com  # 首次扫描自动索引"
}

main "$@"
