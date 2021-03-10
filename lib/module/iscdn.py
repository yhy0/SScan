'''
判断cdn
参考oneforall
https://github.com/shmilylty/OneForAll/blob/master/modules/iscdn.py
'''

import socket
from lib.config import setting
from lib.config.log import logger
import requests
requests.packages.urllib3.disable_warnings()
import re
import asyncio
import ipaddress
import geoip2.database
# 忽略https证书验证
import ssl
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context
import dns.resolver
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from lib.common.utils import load_json, get_host, intranet_ip


data_dir = setting.data_storage_dir


# from https://github.com/al0ne/Vxscan/blob/master/lib/iscdn.py
cdn_ip_cidr = load_json(data_dir.joinpath('cdn_ip_cidr.json'))
cdn_asn_list = load_json(data_dir.joinpath('cdn_asn_list.json'))

# from https://github.com/Qclover/CDNCheck/blob/master/checkCDN/cdn3_check.py
cdn_cname_keyword = load_json(data_dir.joinpath('cdn_cname_keywords.json'))
cdn_header_key = load_json(data_dir.joinpath('cdn_header_keys.json'))


def get_cname(cnames, cname):  # get cname
    try:
        answer = dns.resolver.resolve(cname, 'CNAME', lifetime=10)
        cname = [_.to_text() for _ in answer][0]
        cnames.append(cname)
        get_cname(cnames, cname)
    except Exception:
        pass


def get_cnames(cnames, url):    # get all cname
    if url.find('://') < 0:
        netloc = url[:url.find('/')] if url.find('/') > 0 else url
    else:
        scheme, netloc, path, params, query, fragment = urlparse(url, 'http')
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        answer = resolver.resolve(netloc,'CNAME')
    except Exception:
        cnames = None
    else:
        cname = [_.to_text() for _ in answer][0]
        cnames.append(cname)
        get_cname(cnames, cname)
    return str(cnames)


# get headers  url 要以http:// 或者https:// 开头，这里简单判断一下，没有则加上http://
def get_headers(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        response = requests.get(url, headers=setting.default_headers, timeout=3, verify=False)
        headers = str(response.headers).lower()
    except Exception:
        headers = None
    return headers


def get_ip_list(url):
    host, scheme = get_host(url)
    try:
        ip = socket.gethostbyname(host)
        # 判断解析出来的ip是否为内网ip和是否已存在
        if not intranet_ip(ip):
            return ip
        return ip
    except Exception:
        logger.log('ERROR', f'Invalid domain: {url}')
        return 'Invalid'


def check_cdn_cidr(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except Exception as e:
        logger.log('DEBUG', f'{e}')
        return False
    for cidr in cdn_ip_cidr:
        if ip in ipaddress.ip_network(cidr):
            return True

def check_cname_keyword(cname):
    for name in cname:
        for keyword in cdn_cname_keyword.keys():
            if keyword in name.lower():
                return True

def check_header_key(headers):
    for key in cdn_header_key:
        if key in headers:
            return True

def check_cdn_asn(ip):
    try:
        # https://www.maxmind.com/en/accounts/410249/geoip/downloads
        with geoip2.database.Reader(setting.data_storage_dir.joinpath('GeoLite2-ASN.mmdb')) as reader:
            response = reader.asn(ip)
            asn = response.autonomous_system_number
            if str(asn) in cdn_asn_list:
                return True
    except Exception:
        return False



def run(target, checkcdn, progress_bar, progress):
    flag = False
    targets = []
    ip = get_ip_list(target)

    # 无效域名不加入目标
    if ip == 'Invalid':
        progress.advance(progress_bar)
        return [], ''

    targets.append(target)

    # cdn 是否检测
    if checkcdn:
        # 只对域名做 CDN 检测，排除目标中的ip
        if re.match(r".*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*", target):
            return [target], target

        data = [{'cname': get_cnames([], target), 'headers': get_headers(target), 'ip': ip}]
        for index, item in enumerate(data):
            cname = item.get('cname')
            if cname:
                if check_cname_keyword(cname):
                    flag = True
                    break
            try:
                headers = item.get('headers')
                if headers:
                    headers = eval(headers).keys()
                    if check_header_key(headers):
                        flag = True
                        break
            except Exception as e:
                logger.log('DEBUG', f'{e}')
                pass

            ip_tmp = item.get('ip')
            if check_cdn_cidr(ip_tmp) or check_cdn_asn(ip_tmp):
                flag = True
                break
    progress.advance(progress_bar)
    # 存在cdn 只检测url，否则，url、ip一起检测
    if flag:
        return targets, target
    else:
        targets.append(ip)
        return targets, target

# 5000 多域名解析和检测cdn用时 3 分钟多
def check_cdn(original_targets, checkcdn):
    targets = []         # 有效的目标，加上解析出的ip
    valid_targets = []   # 有效的目标

    # 创建一个事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 创建一个线程池，开启100个线程
    threads = ThreadPoolExecutor(100)
    # 这一步很重要, 使用线程池访问，使用loop.run_in_executor()函数:内部接受的是阻塞的线程池，执行的函数，传入的参数
    tasks = []

    # 进度条设置
    from rich.progress import (
        BarColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
        Progress,
    )
    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        "[bold green]{task.completed}/{task.total}",
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
        transient=True,  # 100%后隐藏进度条
    )

    with progress:
        progress_bar = progress.add_task("[cyan]DNS, CDN detection...", total=len(original_targets))
        for target in original_targets:
            target = target.replace('\n', '').replace('\r', '').strip()
            tasks.append(loop.run_in_executor(threads, run, target, checkcdn, progress_bar, progress))

        if len(tasks) > 0:
            # 使用uvloop加速asyncio, 目前不支持Windows
            import platform
            if platform.system() != "Windows":
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

            # 等待所有的任务完成
            tasks_result = asyncio.wait(tasks)
            loop.run_until_complete(tasks_result)

            for i in tasks:
                url_ip_list, valid_domain = i.result()
                targets.extend(url_ip_list)
                if valid_domain:
                    valid_targets.append(valid_domain)

    return list(set(targets)), valid_targets
