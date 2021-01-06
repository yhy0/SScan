#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy
import re
import json
from ipaddress import IPv4Address
from urllib.parse import urlparse

from config.log import logger


def ip_to_int(ip):
    if isinstance(ip, int):
        return ip
    try:
        ipv4 = IPv4Address(ip)
    except Exception as e:
        logger.log('ERROR', repr(e))
        return 0
    return int(ipv4)


def load_json(path):
    with open(path) as fp:
        return json.load(fp)


def clear_queue(this_queue):
    try:
        while True:
            this_queue.get_nowait()
    except Exception as e:
        return


def get_html(headers, resp):
    if headers.get('content-type', '').find('text') >= 0 \
            or headers.get('content-type', '').find('html') >= 0 \
            or int(headers.get('content-length', '0')) <= 20480:  # 1024 * 20
        # 解决中文乱码
        html_doc = decode_response_text(resp.content)
    else:
        html_doc = ''
    return html_doc


# 解决中文乱码
def decode_response_text(txt, charset=None):
    if charset:
        try:
            return txt.decode(charset)
        except Exception as e:
            pass
    for _ in ['UTF-8', 'GBK', 'GB2312', 'iso-8859-1', 'big5']:
        try:
            return txt.decode(_)
        except Exception as e:
            pass
    try:
        return txt.decode('ascii', 'ignore')
    except Exception as e:
        pass
    raise Exception('Fail to decode response Text')


def get_domain_sub(host):
    if re.search(r'\d+\.\d+\.\d+\.\d+', host.split(':')[0]):
        return ''
    else:
        return host.split('.')[0]


def save_script_result(self, status, url, title, vul_type=''):
    if url not in self.results:
        self.results[url] = []
    _ = {'status': status, 'url': url, 'title': title, 'vul_type': vul_type}

    self.results[url].append(_)


def escape(html):
    return html.replace('&', '&amp;').\
        replace('<', '&lt;').replace('>', '&gt;').\
        replace('"', '&quot;').replace("'", '&#39;')


# 探测端口是否开放
# host: www.baidu.com 或者 ip
# def is_port_open(host, port):
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.settimeout(3.0)
#         if s.connect_ex((host, int(port))) == 0:
#             return True
#         else:
#             return False
#     except Exception as e:
#         logger.log('ERROR', f'{repr(e)}')
#         return False
#     finally:
#         try:
#             # 关闭 TCP 连接
#             s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
#             s.close()
#         except Exception as e:
#             pass

# def scan_given_ports(confirmed_open, confirmed_closed, host, ports):
#     checked_ports = confirmed_open.union(confirmed_closed)
#     ports_open = set()
#     ports_closed = set()
#
#     for port in ports:
#         if port in checked_ports:   # 不重复检测已确认端口
#             continue
#         if is_port_open(host, port):
#             ports_open.add(port)
#         else:
#             ports_closed.add(port)
#
#     return ports_open.union(confirmed_open), ports_closed.union(confirmed_closed)


# 计算给定URL的深度，返回元组(URL, depth)
def cal_depth(self, url):
    if url.find('#') >= 0:
        url = url[:url.find('#')]  # cut off fragment
    if url.find('?') >= 0:
        url = url[:url.find('?')]  # cut off query string

    # 当存在一下三种情况时，判断不是当前超链不是当前域名，或者没有http服务，则不加入队列
    if url.startswith('//'):
        return '', 10000  # //www.baidu.com/index.php

    if not urlparse(url, 'http').scheme.startswith('http'):
        return '', 10000  # no HTTP protocol

    if url.lower().startswith('http'):
        _ = urlparse(url, 'http')
        if _.netloc == self.host:  # same hostname
            url = _.path
        else:
            return '', 10000  # not the same hostname

    while url.find('//') >= 0:
        url = url.replace('//', '/')

    if not url:
        return '/', 1  # http://www.example.com

    if url[0] != '/':
        url = '/' + url

    url = url[: url.rfind('/') + 1]

    if url.split('/')[-2].find('.') > 0:
        url = '/'.join(url.split('/')[:-2]) + '/'

    depth = url.count('/')
    return url, depth


# # 将 ['https://jd.com']  转换为 [('jd.com', 'https')]
# def format_url(urls):
#
#     format_url = []
#     for url in urls:
#         url = url.replace('\n', '').replace('\r', '').strip()
#         if url.find('://') < 0:
#             netloc = url[:url.find('/')] if url.find('/') > 0 else url
#             scheme = 'http'
#         else:
#             scheme, netloc, path, params, query, fragment = urlparse(url, 'http')
#         # host port
#         if netloc.find(':') >= 0:
#             _ = netloc.split(':')
#             host = _[0]
#         else:
#             host = netloc
#         url_tuple = (url, scheme)
#         format_url.append(url_tuple)
#     print(format_url)
#     return format_url
