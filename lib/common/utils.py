#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy
import re
import json
import ipaddress
from urllib.parse import urlparse
from lib.config.log import logger
from lib.config.setting import fofaApi, default_headers
import requests
import sys
import os

# ctrl c 退出时，屏幕上不输出丑陋的traceback信息
def ctrl_quit(_sig, _frame):
    logger.log('ALERT', f'Scan aborted.')
    os._exit(0)


def check_fofa():
    # 当配置 fofa api 时, 检查api是否可用
    if fofaApi['email'] and fofaApi['key']:
        logger.log('INFOR', f'正在验证fofa Api...')
        email = fofaApi['email']
        key = fofaApi['key']
        url = "https://fofa.so/api/v1/info/my?email={0}&key={1}".format(email, key)
        try:
            status = requests.get(url, headers=default_headers, timeout=10, verify=False).status_code
            if status != 200:
                logger.log('ERROR', f'状态码{status}, 请确保config/setting.py中fofaApi配置正确')
                exit(-1)
            logger.log('INFOR', f'fofa Api调用正常')
        except requests.exceptions.ReadTimeout as e:
            logger.log('ERROR', f'请求超时 {e}')
            exit(-1)
        except requests.exceptions.ConnectionError as e:
            logger.log('ERROR', f'网络超时 {e}')
            exit(-1)


# 读取rules目录下的相关规则
def read_rules(rule_files):
    text_to_find = []
    regex_to_find = []
    text_to_exclude = []
    regex_to_exclude = []
    rules_set = set()
    rules_set_root_only = set()

    p_tag = re.compile('{tag="(.*?)"}')
    p_status = re.compile(r'{status=(\d{3})}')
    p_content_type = re.compile('{type="(.*?)"}')
    p_content_type_no = re.compile('{type_no="(.*?)"}')

    _files = rule_files
    # 读取规则
    for rule_file in _files:
        with open(rule_file, 'r', encoding='utf-8') as infile:
            vul_type = os.path.basename(rule_file)[:-4]
            for url in infile.readlines():
                url = url.strip()
                if url.startswith('/'):
                    _ = p_tag.search(url)
                    tag = _.group(1) if _ else '' # 没有tag字段时，赋空

                    _ = p_status.search(url)
                    status = int(_.group(1)) if _ else 0

                    _ = p_content_type.search(url)
                    content_type = _.group(1) if _ else ''

                    _ = p_content_type_no.search(url)
                    content_type_no = _.group(1) if _ else ''

                    root_only = True if url.find('{root_only}') >= 0 else False
                    rule = (url.split()[0], tag, status, content_type, content_type_no, root_only, vul_type)

                    if root_only:
                        if rule not in rules_set_root_only:
                            rules_set_root_only.add(rule)
                        else:
                            logger.log('ERROR', f'Duplicated root only rule: {rule}')
                    else:
                        if rule not in rules_set:
                            rules_set.add(rule)
                        else:
                            logger.log('ERROR', f'Duplicated rule: {rule}')

    # 读取匹配黑/白名单
    re_text = re.compile('{text="(.*)"}')
    re_regex_text = re.compile('{regex_text="(.*)"}')
    white_file_path = 'pocs/rules/white.list'
    if not os.path.exists(white_file_path):
        logger.log('ERROR', f'File not exist: {white_file_path}')
        return
    for _line in open(white_file_path, 'r', encoding='utf-8'):
        _line = _line.strip()
        if not _line or _line.startswith('#'):
            continue
        _m = re_text.search(_line)
        if _m:
            text_to_find.append(_m.group(1))
        else:
            _m = re_regex_text.search(_line)
            if _m:
                regex_to_find.append(re.compile(_m.group(1)))

    black_file_path = 'pocs/rules/black.list'
    if not os.path.exists(black_file_path):
        logger.log('ERROR', f'File not exist: {black_file_path}')
        return
    for _line in open(black_file_path, 'r', encoding='utf-8'):
        _line = _line.strip()
        if not _line or _line.startswith('#'):
            continue
        _m = re_text.search(_line)
        if _m:
            text_to_exclude.append(_m.group(1))
        else:
            _m = re_regex_text.search(_line)
            if _m:
                regex_to_exclude.append(re.compile(_m.group(1)))
    return text_to_find, regex_to_find, text_to_exclude, regex_to_exclude, rules_set, rules_set_root_only


def ip_to_int(ip):
    if isinstance(ip, int):
        return ip
    try:
        ipv4 = ipaddress.IPv4Address(ip)
    except Exception as e:
        logger.log('ERROR', f'{repr(e)}')
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
            or headers.get('content-type', '').find('html') >= 0:
            # or int(headers.get('content-length', '0')) <= 20480:  # 1024 * 20
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


def get_host(url):
    if url.find('://') < 0:
        netloc = url[:url.find('/')] if url.find('/') > 0 else url
        scheme = 'http'
    else:
        scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

    # host port
    if netloc.find(':') >= 0:
        _ = netloc.split(':')
        host = _[0]
    else:
        host = netloc

    return host, scheme

'''
验证是否为内网IP
私有IP： A类 10.0.0.0-10.255.255.255
        B类 172.16.0.0-172.31.255.255
        C类 192.168.0.0-192.168.255.255
当然，还有 127.0.0.1 这个环回地址
'''
def intranet_ip(ip):
    if re.match(r"^10\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$", ip):
        return True

    if re.match(r"^172\.(1[6789]|2[0-9]|3[01])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$", ip):
        return True

    if re.match(r"^192\.168\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$", ip):
        return True
    if ip == '127.0.0.1':
        return True

# 根据指定的掩码，添加ip
def add_ip(args, queue_targets):
    ip_subnet = []
    # 筛选目标中的ip， 当指定其它掩码时，根据该ip添加目标（当目标存在cdn时不会添加该段的其它目标）
    ip_targets = []
    for target in queue_targets:
        if re.match(r".*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).*",
                    target):
            host, scheme = get_host(target)
            ip_targets.append(host)

    # 当指定子网掩码时的处理逻辑, 将对应网段ip加入处理目标中
    if args.network != 32:
        for ip in ip_targets:
            if ip.find('/') > 0:    # 网络本身已经处理过 118.193.98/24
                continue
            _network = u'%s/%s' % ('.'.join(ip.split('.')[:3]), args.network)
            if _network in ip_targets:
                continue
            ip_targets.append(_network)
            if args.network >= 20:
                sub_nets = [ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).hosts()]
            else:
                sub_nets = ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).subnets(new_prefix=22)

            for sub_net in sub_nets:
                if sub_net in ip_targets:
                    continue
                if type(sub_net) == ipaddress.IPv4Network:    # add network only
                    ip_targets.append(str(sub_net))
                for _ip in sub_net:
                    _ip = str(_ip)
                    if _ip not in ip_targets:
                        ip_subnet.append(_ip)

    return ip_subnet
