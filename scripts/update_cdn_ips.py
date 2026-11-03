#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
每日解析目标域名的所有 A 记录 IP，并将它们以独立 Clash proxy 节点的形式
写入 baidu-cdn.yaml 的「自动生成区」标记之间。

标记说明（必须存在于 YAML 中）：
  proxies 区:   # >>>BAIDU-CDN-PROXIES-START>>> ... # <<<BAIDU-CDN-PROXIES-END<<<
  组成员区:     # >>>BAIDU-CDN-GROUP-START>>>    ... # <<<BAIDU-CDN-GROUP-END<<<

设计要点：
  - 每个 IP 生成一个独立节点，server 直接填 IP，Host/SNI 仍保留原域名，
    因此行为等价于「解析后的 cloudnproxy.baidu.com」。
  - 每个节点上方用注释标注该 IP 的物理地址（国家/省/市/运营商，最佳努力查询）。
  - 节点名形如 Baidu-CDN-01、Baidu-CDN-02…，与组成员列表一一对应。
  - 标记之外的内容（顶部配置、rules、DIRECT 兜底、以及“智能解析”常驻节点）
    完全不动；智能解析节点始终直接使用域名，不会被自动生成区覆盖。
"""

import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request

DOMAIN = os.environ.get("DOMAIN", "cloudnproxy.baidu.com")
YAML_FILE = os.environ.get("YAML_FILE", "baidu-cdn.yaml")

# Clash/mihomo fake-ip 模式会把所有域名解析到 198.18.0.0/15 保留段。
# 若运行环境被 fake-ip 拦截（例如本机开着 Clash TUN），解析结果全落在该段，
# 此时不应写入，否则会污染 GitHub 上已填好的真实 IP。
FAKE_IP_PREFIX = (198, 18)

# 原 proxy 节点的请求头（伪装为百度 App 的 HTTP 请求），逐节点保留
HEADERS = [
    '      Host: "ascdn.baidu.com"',
    '      Proxy-Connection: "Keep-Alive"',
    '      X-T5-Auth: "1951164069"',
    '      User-Agent: "okhttp/3.11.0 SP-engine/2.71.0 Dalvik/2.1.0 '
    '(Linux; U; Android 9; HMA-AL00 Build/PQ3B.190801.002) '
    'baiduboxapp/13.33.0.11 (Baidu; P1 9)"',
]

PROXIES_START = "# >>>BAIDU-CDN-PROXIES-START>>>"
PROXIES_END = "# <<<BAIDU-CDN-PROXIES-END<<<"
GROUP_START = "# >>>BAIDU-CDN-GROUP-START>>>"
GROUP_END = "# <<<BAIDU-CDN-GROUP-END<<<"


def resolve_ips(domain: str, attempts: int = 20) -> list:
    """通过重复查询收集 round-robin 返回的 A 记录 IP，去重排序。"""
    ips = set()
    for _ in range(attempts):
        try:
            # gethostbyname_ex 返回该主机名对应的全部 IPv4 地址
            _, _, addrs = socket.gethostbyname_ex(domain)
            ips.update(addrs)
        except socket.gaierror as e:
            print(f"[warn] resolve attempt failed: {e}")
            break
    return sorted(ips)


def is_fake_ip(ip: str) -> bool:
    """判断是否为 Clash fake-ip 保留段 198.18.0.0/15。"""
    try:
        parts = tuple(int(p) for p in ip.split("."))
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    return parts[0] == FAKE_IP_PREFIX[0] and parts[1] == FAKE_IP_PREFIX[1]


def _fmt_ipwho(data: dict) -> str:
    if not data.get("success"):
        return ""
    parts = [
        data.get("country"),
        data.get("region"),
        data.get("city"),
        (data.get("connection") or {}).get("isp"),
    ]
    return " · ".join(p for p in parts if p)


def _fmt_ipinfo(data: dict) -> str:
    if data.get("bogon") or data.get("error"):
        return ""
    parts = [
        data.get("country"),
        data.get("region"),
        data.get("city"),
        data.get("org"),
    ]
    return " · ".join(p for p in parts if p)


def geo_lookup(ip: str) -> str:
    """查询 IP 的物理位置（国家/省/市/运营商）。最佳努力，失败返回空串。

    依次尝试 ipwho.is（HTTPS 免 key）与 ipinfo.io；任一成功即用其结果。
    仅用于注释标注，任何失败都不应阻断整体更新。
    """
    endpoints = [
        (f"https://ipwho.is/{ip}", _fmt_ipwho),
        (f"https://ipinfo.io/{ip}/json", _fmt_ipinfo),
    ]
    for url, fmt in endpoints:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            loc = fmt(data)
            if loc:
                return loc
        except Exception as e:
            print(f"[warn] geo lookup 失败 {ip} ({url}): {e}")
            continue
    return ""


def build_proxy_nodes(ips: list) -> str:
    lines = []
    for idx, ip in enumerate(ips, 1):
        # 物理地址标注（最佳努力）
        loc = geo_lookup(ip)
        tag = f"{ip}  {loc}" if loc else ip
        lines.append(f"  # {tag}")
        name = f"Baidu-CDN-{idx:02d}"
        lines.append(f'  - name: "{name}"')
        lines.append("    type: http")
        lines.append(f"    server: {ip}")
        lines.append("    port: 443")
        lines.append("    headers:")
        lines.extend(HEADERS)
        # 礼貌地稍作停顿，避免触发 GeoIP 服务的速率限制
        time.sleep(0.3)
    return "\n".join(lines)


def build_group_members(ips: list) -> str:
    lines = []
    for idx, _ in enumerate(ips, 1):
        name = f"Baidu-CDN-{idx:02d}"
        lines.append(f"      - {name}")
    return "\n".join(lines)


def replace_block(text: str, start: str, end: str, content: str) -> str:
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    if not pattern.search(text):
        raise RuntimeError(f"未找到标记对: {start!r} / {end!r}")
    replacement = start + "\n" + content + "\n" + end
    return pattern.sub(replacement, text, count=1)


def main() -> int:
    ips = resolve_ips(DOMAIN)
    if not ips:
        print(f"[error] 未解析到任何 IP: {DOMAIN}")
        return 1

    # 过滤掉 Clash fake-ip 段，避免本地被拦截时污染文件
    real_ips = [ip for ip in ips if not is_fake_ip(ip)]
    if not real_ips:
        fake_sample = ", ".join(ips[:3])
        print(
            f"[warn] 解析结果全部落在 fake-ip 保留段 198.18.0.0/15 "
            f"({fake_sample}...)，疑似运行环境被 Clash TUN 拦截。"
            f"已跳过写入，保持文件不变。"
        )
        return 0

    ips = real_ips
    print(f"[info] 解析到 {len(ips)} 个真实 IP ({DOMAIN}): {ips}")

    if not os.path.exists(YAML_FILE):
        print(f"[error] 找不到 YAML 文件: {YAML_FILE}")
        return 1

    with open(YAML_FILE, "r", encoding="utf-8") as f:
        text = f.read()

    text = replace_block(
        text, PROXIES_START, PROXIES_END, build_proxy_nodes(ips)
    )
    text = replace_block(
        text, GROUP_START, GROUP_END, build_group_members(ips)
    )

    with open(YAML_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

    print(f"[info] 已更新 {YAML_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
