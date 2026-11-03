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
  - 节点名称格式为「百度-地址-运营商」，例如「百度-中国河北保定-联通」，
    一眼即可看出物理位置；节点上方注释同时保留 IP 与完整物理地址。
  - 地址/运营商任一项无法解析时填「未知」。
  - 同一「地址-运营商」下若有多条 IP（必然发生），则在名称末尾追加
    「-2」「-3」… 去重，否则 Clash 会因重名节点拒绝加载配置。
  - 物理地址“只用中文”：优先 pconline（原生中文）/ ip-api(lang=zh-CN)；
    若运行环境（如 GitHub Actions 共享 IP）无法访问这些 HTTP 源而回退到
    英文 HTTPS 源（ipwho.is / ipinfo.io），也会通过内置中英文对照表把
    省/市翻译回中文，保证节点名不出现英文地名。
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

# 中文物理地址对照表（用于把英文 HTTPS 兜底源的省/市翻译回中文）
COUNTRY_MAP = {
    "China": "中国",
    "中国": "中国",
    "Hong Kong": "中国香港",
    "Macao": "中国澳门",
    "Macau": "中国澳门",
    "Taiwan": "中国台湾",
}

PROVINCE_MAP = {
    "Hebei": "河北", "Hebei Sheng": "河北",
    "Guangdong": "广东", "Guangdong Sheng": "广东",
    "Jiangsu": "江苏", "Jiangsu Sheng": "江苏",
    "Beijing": "北京", "Beijing Shi": "北京",
    "Shanghai": "上海", "Shanghai Shi": "上海",
    "Tianjin": "天津", "Chongqing": "重庆",
    "Zhejiang": "浙江", "Shandong": "山东", "Sichuan": "四川",
    "Henan": "河南", "Hubei": "湖北", "Hunan": "湖南",
    "Fujian": "福建", "Liaoning": "辽宁", "Jilin": "吉林",
    "Heilongjiang": "黑龙江", "Anhui": "安徽", "Jiangxi": "江西",
    "Guizhou": "贵州", "Yunnan": "云南", "Gansu": "甘肃",
    "Hainan": "海南", "Shanxi": "山西", "Shaanxi": "陕西",
    "Qinghai": "青海", "Taiwan": "台湾", "Xinjiang": "新疆",
    "Tibet": "西藏", "Ningxia": "宁夏",
    "Inner Mongolia": "内蒙古", "Nei Mongol": "内蒙古",
    "Guangxi": "广西", "Hong Kong": "香港", "Macao": "澳门",
}

CITY_MAP = {
    "Baoding": "保定", "Guangzhou": "广州", "Nanjing": "南京",
    "Suzhou": "苏州", "Dongguan": "东莞", "Beijing": "北京",
    "Shanghai": "上海", "Chengde": "承德", "Chengdu": "成都",
    "Hangzhou": "杭州", "Shenzhen": "深圳", "Wuhan": "武汉",
    "Xian": "西安", "Xi'an": "西安", "Xiamen": "厦门",
    "Tianjin": "天津", "Chongqing": "重庆", "Qingdao": "青岛",
    "Jinan": "济南", "Zhengzhou": "郑州", "Changsha": "长沙",
    "Harbin": "哈尔滨", "Shenyang": "沈阳", "Dalian": "大连",
    "Kunming": "昆明", "Guiyang": "贵阳", "Lanzhou": "兰州",
    "Taiyuan": "太原", "Hefei": "合肥", "Nanchang": "南昌",
    "Fuzhou": "福州", "Nanning": "南宁", "Urumqi": "乌鲁木齐",
    "Lhasa": "拉萨", "Yinchuan": "银川", "Xining": "西宁",
    "Haikou": "海口", "Sanya": "三亚",
}


def _norm(s: str) -> str:
    """去掉省/市/英文行政后缀，便于对照表匹配。"""
    return (
        (s or "")
        .replace("省", "")
        .replace("市", "")
        .replace("Shi", "")
        .replace("Sheng", "")
        .replace("Province", "")
        .replace("Municipality", "")
        .strip()
    )


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


def shorten_isp(isp: str) -> str:
    """把运营商字段归一为简短中文（联通/电信/移动），大小写不敏感；无法识别填“未知”。"""
    if not isp:
        return "未知"
    s = isp.lower()
    if "联通" in isp or "unicom" in s:
        return "联通"
    if "电信" in isp or "telecom" in s:
        return "电信"
    if "移动" in isp or "mobile" in s:
        return "移动"
    if "铁通" in isp:
        return "铁通"
    return "未知"


def make_address(country: str, region: str, city: str) -> str:
    """由 GeoIP 字段拼出写入节点名的简短物理地址（国家+省+市），强制中文。

    英文省/市会通过内置对照表翻译回中文；直辖市/自治区做去重
    （如“北京”+“北京市” → “中国北京”而非“中国北京北京”）。
    """
    country_s = COUNTRY_MAP.get((country or "").strip(), (country or "").strip())
    region_s = PROVINCE_MAP.get(_norm(region), _norm(region))
    city_s = CITY_MAP.get(_norm(city), _norm(city))
    # 直辖市/自治区去重：城市若以省份名开头则去掉省份部分
    if region_s and city_s.startswith(region_s):
        city_s = city_s[len(region_s):]
    parts = [p for p in [country_s, region_s, city_s] if p]
    return "".join(parts) or "未知"


def make_node_names(enriched: list) -> list:
    """返回与 enriched 等长的节点名列表。

    格式「百度-地址-运营商」；地址/运营商未知填「未知」。
    同一「地址-运营商」下若有多条 IP（必然发生），在名称末尾追加
    「-2」「-3」… 去重，避免 Clash 因重名节点拒绝加载。
    """
    base_names = []
    for (_ip, _raw, address, isp) in enriched:
        address_s = address if address and address != "未知" else "未知"
        isp_s = isp if isp and isp != "未知" else "未知"
        base_names.append(f"百度-{address_s}-{isp_s}")

    final = []
    seen = {}
    for name in base_names:
        if name in seen:
            seen[name] += 1
            final.append(f"{name}-{seen[name]}")
        else:
            seen[name] = 1
            final.append(name)
    return final


def _fmt_pconline(ip: str):
    """pconline（原生中文，GBK 编码）结果 → (raw, address, isp)；失败返回 None。"""
    url = f"https://whois.pconline.com.cn/ipJson.jsp?ip={ip}&json=true"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw_bytes = resp.read()
        data = json.loads(raw_bytes.decode("gbk", "replace"))
    except Exception as e:
        print(f"[warn] pconline 失败 {ip}: {e}")
        return None
    if not data or data.get("err") or not data.get("pro"):
        return None
    pro = data.get("pro", "") or ""
    city = data.get("city", "") or ""
    addr = (data.get("addr") or f"{pro}{city}").strip()
    # 运营商：addr 去掉“省份+城市”之后的剩余部分
    isp_raw = addr
    if pro and pro in isp_raw:
        isp_raw = isp_raw.replace(pro, "")
    if city and city in isp_raw:
        isp_raw = isp_raw.replace(city, "")
    isp_raw = isp_raw.strip("  -·")
    address = make_address("中国", pro, city)
    isp = shorten_isp(isp_raw)
    return (addr or f"{pro}{city}", address, isp)


def _fmt_ipapi(data: dict):
    """ip-api.com（lang=zh-CN）结果 → (raw, address, isp)；失败返回 None。"""
    if data.get("status") != "success":
        return None
    raw = " · ".join(
        p
        for p in [
            data.get("country"),
            data.get("regionName"),
            data.get("city"),
            data.get("isp"),
        ]
        if p
    )
    address = make_address(
        data.get("country"), data.get("regionName"), data.get("city")
    )
    isp = shorten_isp(data.get("isp"))
    return (raw, address, isp)


def _fmt_ipwho(data: dict):
    """ipwho.is 结果 → (raw, address, isp)；失败返回 None。"""
    if not data.get("success"):
        return None
    raw = " · ".join(
        p
        for p in [
            data.get("country"),
            data.get("region"),
            data.get("city"),
            (data.get("connection") or {}).get("isp"),
        ]
        if p
    )
    address = make_address(
        data.get("country"), data.get("region"), data.get("city")
    )
    isp = shorten_isp((data.get("connection") or {}).get("isp"))
    return (raw, address, isp)


def _fmt_ipinfo(data: dict):
    """ipinfo.io 结果 → (raw, address, isp)；失败返回 None。"""
    if data.get("bogon") or data.get("error"):
        return None
    raw = " · ".join(
        p
        for p in [
            data.get("country"),
            data.get("region"),
            data.get("city"),
            data.get("org"),
        ]
        if p
    )
    address = make_address(data.get("country"), data.get("region"), data.get("city"))
    isp = shorten_isp(data.get("org"))
    return (raw, address, isp)


# HTTP(中文) 源是否整体不可用；首个 IP 若两个 HTTP 源都失败则置 True，
# 后续 IP 直接走 HTTPS 兜底，避免每次都白等超时。
_http_dead = False


def geo_lookup(ip: str):
    """查询 IP 的物理位置，返回 (raw, address, isp)。

    raw     完整物理地址（用于节点上方注释）；
    address 简短中文物理地址（用于节点名称「百度-地址-运营商」的前半）；
    isp     归一后的运营商（用于节点名称后半，无法识别为“未知”）。
    优先中文源（pconline / ip-api(lang=zh-CN)，均为 HTTP）；
    若运行环境访问不到 HTTP（如 GitHub 共享 IP 被限），回退到英文 HTTPS 源，
    并通过内置对照表把省/市翻译回中文，保证节点名不出现英文地名。
    """
    global _http_dead
    if not _http_dead:
        for fetcher in (_fmt_pconline, _fmt_ipapi):
            try:
                res = fetcher(ip)
                if res:
                    return res
            except Exception as e:
                print(f"[warn] geo lookup 失败 {ip} ({fetcher.__name__}): {e}")
        # 两个 HTTP 中文源都失败 → 标记，后续 IP 不再尝试 HTTP
        _http_dead = True

    for fetcher in (_fmt_ipwho, _fmt_ipinfo):
        try:
            res = fetcher(ip)
            if res:
                return res
        except Exception as e:
            print(f"[warn] geo lookup 失败 {ip} ({fetcher.__name__}): {e}")
    return ("", "未知", "未知")


def enrich(ips: list) -> list:
    """为每个 IP 附加 (ip, raw, address, isp)，并对 GeoIP 做礼貌性限速。"""
    result = []
    for ip in ips:
        raw, address, isp = geo_lookup(ip)
        result.append((ip, raw, address, isp))
        time.sleep(0.3)
    return result


def build_proxy_nodes(enriched: list) -> str:
    names = make_node_names(enriched)
    lines = []
    for (ip, raw, _address, _isp), name in zip(enriched, names):
        # 节点上方注释保留 IP 与完整物理地址
        tag = f"{ip}  {raw}" if raw else ip
        lines.append(f"  # {tag}")
        # 节点名称：百度-地址-运营商
        lines.append(f'  - name: "{name}"')
        lines.append("    type: http")
        lines.append(f"    server: {ip}")
        lines.append("    port: 443")
        lines.append("    headers:")
        lines.extend(HEADERS)
    return "\n".join(lines)


def build_group_members(enriched: list) -> str:
    names = make_node_names(enriched)
    lines = [f"      - {name}" for name in names]
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
    print(f"[info] 解析到 {len(ips)} 个真实 IP ({DOMAIN})")

    enriched = enrich(ips)
    for (ip, raw, address, isp), name in zip(enriched, make_node_names(enriched)):
        print(f"[info]   {ip}  {raw}  -> 节点名: {name}")

    if not os.path.exists(YAML_FILE):
        print(f"[error] 找不到 YAML 文件: {YAML_FILE}")
        return 1

    with open(YAML_FILE, "r", encoding="utf-8") as f:
        text = f.read()

    text = replace_block(
        text, PROXIES_START, PROXIES_END, build_proxy_nodes(enriched)
    )
    text = replace_block(
        text, GROUP_START, GROUP_END, build_group_members(enriched)
    )

    with open(YAML_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

    print(f"[info] 已更新 {YAML_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
