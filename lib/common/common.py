#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

from lib.config.log import logger
from urllib.parse import urlparse
from lib.common.scanner import Scanner
from lib.module.iscdn import check_cdn
from lib.module.fofa import Fofa
from lib.module.PortScan import PortScan
from lib.common.utils import add_ip
from lib.config.setting import web_ports


# 漏洞扫描
def scan_process(targets):
    target, q_results, args = targets[0], targets[1], targets[2]
    scanner = Scanner(args=args)
    try:
        '''
        {'scheme': 'https', 'host': '127.0.0.1', 'port': 443, 'path': '',
         'ports_open': [443, 8088], 'script': True, 'has_http': True}
        '''
        # logger.log('INFOR', f'{target}')
        # 处理目标信息，加载规则，脚本等等
        ret = scanner.init_from_url(target)
        if ret:
            host, results = scanner.scan()
            if results:
                q_results.put((host, results))

    except Exception as e:
        logger.log('DEBUG', f'{e}')
    finally:
        return target


# 处理目标需要的80、443、指定端口、脚本端口
def get_host_port_list(queue_targets, args):
    host_port_list = []

    for _target in queue_targets:
        url = _target
        # scheme netloc path
        if url.find('://') < 0:
            scheme = 'unknown'
            netloc = url[:url.find('/')] if url.find('/') > 0 else url
            path = ''
        else:
            # scheme='http', netloc='www.baidu.com:80', path='', params='', query='', fragment=''
            scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

        # 指定端口时需要，检查指定的端口是否开放
        if netloc.find(':') >= 0:
            _ = netloc.split(':')
            host = _[0]
            http_port = int(_[1])
        else:
            host = netloc
            http_port = None

        if scheme == 'https' and http_port is None:
            http_port = 443
        elif scheme == 'http' and http_port is None:
            http_port = 80

        if scheme == 'unknown':
            if http_port == 80:
                scheme = 'http'
            elif http_port == 443:
                scheme = 'https'

        # 只使用脚本时，不扫描指定、80、443端口
        if not args.scripts_only:
            # (host, port, scheme, path, port) 最后一位 port 是指当前目标web服务的端口，
            # 通过检查该端口是否开放，来验证目标是否存在web服务，若存在则进行规则扫描
            if http_port: # url中指定了端口
                host_port_list.append((host, http_port, scheme, path, http_port))
            else:    # url中没指定扫描, 将要扫描的 web 端口 加进去
                http_port = 80
                for port in web_ports:
                    host_port_list.append((host, port, scheme, path, port))

        # 没有禁用插件时，把插件中需要扫描的端口加进去
        if not args.no_scripts:
            for s_port in args.require_ports:
                host_port_list.append((host, s_port, scheme, path, http_port))

    return host_port_list


# 对目标进行封装，格式化
# {'127.0.0.1': {'scheme': 'http', 'host': '127.0.0.1', 'port': 80, 'path': '', 'ports_open': [80, 3306], 'script': True}
def get_target(ps_result, q_fofa):
    targets = {}
    for target in ps_result:
        # target: ('127.0.0.1', 8001, 'open', 'unknown', '', 80)
        if target[2] == 'open':
            host = target[0]
            scheme = target[3]
            path = target[4]
            if host in targets:
                ports_open = targets[host]['ports_open']
                port = target[1]
                if port not in ports_open:
                    ports_open.append(port)
                    targets[host].update(ports_open=ports_open)
            else:
                targets[host] = {'scheme': scheme, 'host': host, 'port': target[5], 'path': path, 'ports_open': [target[1]], 'script': True}
    if q_fofa:
        # 处理 fofa 的结果
        for _target in q_fofa:
            url = _target[0]
            # scheme='http', netloc='www.baidu.com:80', path='', params='', query='', fragment=''
            scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

            host_port = netloc.split(':')
            host = host_port[0]
            if len(host_port) == 2:
                port = int(host_port[1])
            else:
                port = 80
            if host in targets.keys() and (port == 80 or port == 443):
                pass
            else:
                # fofa搜索的结果host是否已存在目标中，若存在的话，给个标记，不再进行脚本探测
                if host in targets.keys():
                    fofa_target = {'scheme': scheme, 'host': netloc, 'port': port, 'path': path, 'ports_open': [port], 'script': False}
                else:
                    fofa_target = {'scheme': scheme, 'host': netloc, 'port': port, 'path': path, 'ports_open': [port], 'script': True}
                targets[netloc] = fofa_target

    return targets

# 使用异步协程， 检测目标80、443、给定端口是否开放
def process_targets(queue_targets, q_targets, args, q_fofa):
    # 对目标和要扫描的端口做处理，格式化
    # queue_targets  ['http://127.0.0.1:8080', 'www.baidu.cn']
    # host_port_list [('127.0.0.1', 8080, 'http', '/', 8080), ('www.baidu.cn', 80, 'unknown', '/', 80), ('www.baidu.cn', 443, 'unknown', '/', 443)]

    host_port_list = get_host_port_list(queue_targets, args)

    # 使用协程进行端口扫描
    ps = PortScan(host_port_list, 2000)
    # ps_result  {'127.0.0.1': [80], '127.0.0.1': [443, 80]}
    ps_result = ps.async_tcp_port_scan()

    # logger.log('INFOR', f'ps_result: {ps_result}')

    # 对目标进行封装，格式化
    targets = get_target(ps_result, q_fofa)

    for host in targets:
        target = targets[host]
        ports_open = target['ports_open']
        if 80 in ports_open and 443 in ports_open:
            target.update(port=443)
            target.update(scheme='https')

        elif 80 in ports_open:
            target.update(port=80)
            target.update(scheme='http')
        elif 443 in ports_open:
            target.update(port=443)
            target.update(scheme='https')

        if target['port'] in ports_open or 80 in ports_open or 443 in ports_open:
            target['has_http'] = True
        else:
            target['has_http'] = False
        # 添加目标，最终的扫描目标
        # {'scheme': 'http', 'host':'127.0.0.1', 'port': 8088, 'path':'/', 'ports_open': [8088], 'script': True,'has_http': True}
        q_targets.put(target)

def prepare_targets(targets, q_targets, args, fofa_result):
    # 筛选有效目标、url解析、检查是否存在cdn
    # todo queue_targets 没有进行去重、当['127.0.0.1', 'http://127.0.0.1'] ,存在重复
    # queue_targets 有效的目标加上解析出的ip,  valid_targets 有效的目标, 供fofa检测使用
    queue_targets, valid_targets = check_cdn(targets, args)

    # fofa 扫到的并且存活的web资产
    q_fofa = []

    # 当配置 fofa api 时, 对 valid_targets 目标进行fofa搜索，扩大资产范围
    if args.fofa and valid_targets:
        fofa = Fofa(valid_targets, fofa_result)
        q_fofa = fofa.run()

    # exit()
    # 筛选目标中的ip， 当指定其它掩码时，根据该ip添加目标（当目标存在cdn时不会添加该段的其它目标）
    ip_subnet = add_ip(args, queue_targets)

    # 目标合并, 去重
    queue_targets.extend(ip_subnet)
    queue_targets = list(set(queue_targets))

    # q_fofa [('http://127.0.0.1:3790', '403 Forbidden'), ('http://127.0.0.1', 'Welcome to CentOS')]
    # 使用异步协程， 检测目标80、443、给定端口是否开放
    # 检测目标的80、443、给定端口是否开放，并格式化，加入扫描队列 q_targets

    process_targets(queue_targets, q_targets, args, q_fofa)