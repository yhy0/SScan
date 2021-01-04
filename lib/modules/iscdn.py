'''
判断cdn
参考oneforall
https://github.com/shmilylty/OneForAll/blob/master/modules/iscdn.py
'''

import socket
from config import setting
from config.log import logger
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
import time
from concurrent.futures import ThreadPoolExecutor
from lib.common.utils import load_json

data_dir = setting.data_storage_dir


# from https://github.com/al0ne/Vxscan/blob/master/lib/iscdn.py
cdn_ip_cidr = load_json(data_dir.joinpath('cdn_ip_cidr.json'))
cdn_asn_list = load_json(data_dir.joinpath('cdn_asn_list.json'))

# from https://github.com/Qclover/CDNCheck/blob/master/checkCDN/cdn3_check.py
cdn_cname_keyword = load_json(data_dir.joinpath('cdn_cname_keywords.json'))
cdn_header_key = load_json(data_dir.joinpath('cdn_header_keys.json'))


def get_cname(cnames, cname):  # get cname
    try:
        answer = dns.resolver.resolve(cname, 'CNAME')
        cname = [_.to_text() for _ in answer][0]
        cnames.append(cname)
        get_cname(cnames, cname)
    except dns.resolver.NoAnswer:
        pass


def get_cnames(cnames, url): # get all cname

    if url.find('://') < 0:
        netloc = url[:url.find('/')] if url.find('/') > 0 else url
    else:
        scheme, netloc, path, params, query, fragment = urlparse(url, 'http')
    try:
        answer = dns.resolver.resolve(netloc,'CNAME')
    except Exception as e:
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
        response = requests.get(url, headers=setting.default_headers, timeout=10, verify=False)
        headers = str(response.headers).lower()
    except Exception as e:
        # logger.log('ERROR', f'url: {url}  {repr(e)}')

        headers = None
    return headers


def get_ip_list(url):
    if url.find('://') < 0:
        netloc = url[:url.find('/')] if url.find('/') > 0 else url
    else:
        scheme, netloc, path, params, query, fragment = urlparse(url, 'http')
    ip_list = []
    try:
        addrs = socket.getaddrinfo(netloc, None)
        for item in addrs:
            if item[4][0] not in ip_list:
                ip_list.append(item[4][0])
    except Exception as e:
        logger.log('ERROR', f'url: {url}  {netloc}  {repr(e)}')
        pass
    return ip_list


def check_cdn_cidr(ips):
    for ip in ips:
        try:
            ip = ipaddress.ip_address(ip)
        except Exception as e:
            logger.log('DEBUG', e.args)
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
            for i in ip:
                response = reader.asn(i)
                asn = response.autonomous_system_number
                if str(asn) in cdn_asn_list:
                    return True
    except Exception as e:
        pass
    return False


# data = [{'cname' : cnames, 'headers' : headers, 'ip' : ip_list, 'url' : 'https://www.baidu.com'}]
def run(url):
    flag = False
    ip = get_ip_list(url)
    data = [{'cname': get_cnames([], url), 'headers': get_headers(url), 'ip': ip}]
    for index, item in enumerate(data):
        cname = item.get('cname')
        if cname:
            if check_cname_keyword(cname):
                flag = True
        try:
            headers = item.get('headers')
            if headers:
                headers = eval(headers).keys()
                if check_header_key(headers):
                    flag = True
        except Exception as e:
            logger.log('FATAL', f'{url}  {repr(e)}')
            pass

        ip = item.get('ip')
        if check_cdn_cidr(ip) or check_cdn_asn(ip):
            flag = True

    if flag:
        logger.log("DEBUG", f' {url} 存在CDN ')
        return ''
    else:
        return ip


def check_cdn(processed_targets):
    ips = []
    logger.log('INFOR', f'Start CDN check module')
    start_time = time.time()
    # 创建一个事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # 创建一个线程池，开启6个线程
    p = ThreadPoolExecutor(6)
    # 这一步很重要, 使用线程池访问，使用loop.run_in_executor()函数:内部接受的是阻塞的线程池，执行的函数，传入的参数
    tasks = []

    for target in processed_targets:
        target = target.replace('\n', '').replace('\r', '').strip()
        # 只对域名做CDN 检测，排除目标中的ip
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", target):
            ips.append(target)
        else:
            tasks.append(loop.run_in_executor(p, run, target))

    if len(tasks) > 0:
        # 使用uvloop加速asyncio, 目前不支持Windows
        import platform
        if platform.system() != "Windows":
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

        # 等待所有的任务完成
        result = asyncio.wait(tasks)
        loop.run_until_complete(result)
        logger.log("INFOR", f'=---------------')
        for i in tasks:
            ips.extend(i.result())

    loop.close()
    logger.log("INFOR", f'CDN check over in %.1f seconds!' % (time.time() - start_time))
    return ips

