# -*- coding:utf-8 -*-
# !/usr/bin/python3
# @Time   : 2021/2/3 17:16
# @Author : yhy

# 参考 https://github.com/s7ckTeam/Glass/blob/main/lib/proxy.py

import os
import ssl
import time
import json
import random
import urllib3
import requests
import threading
from lib.config.setting import USER_AGENTS, threadNum, relative_directory, proxyList, country
from lib.config.log import logger

ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings()
lock = threading.Lock()

# 验证代理是否为高质量代理
class ProxyInfo(threading.Thread):
    def __init__(self, types, host, port, sem):
        super(ProxyInfo, self).__init__()
        self.types = types
        self.host = host
        self.port = port
        self.sem = sem
        self.headers = {
            "User-Agent": random.choice(USER_AGENTS),
        }

    def run(self):
        s = requests.Session()
        s.keep_alive = False  # 关闭多余连接
        s.headers = self.headers
        proxy = f"{self.types}://{self.host}:{self.port}"
        s.proxies = {
            self.types: proxy
        }
        try:
            req = s.get("https://httpbin.org/ip", timeout=5)
            lock.acquire()
            codes = req.text
            if ',' in codes:
                pass
            elif self.host in codes:
                proxyList.append({self.types: proxy})
            req.close()
            lock.release()
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, urllib3.exceptions.ReadTimeoutError, urllib3.exceptions.ProtocolError,):
            pass
        except KeyboardInterrupt:
            lock.release()
            pass
        self.sem.release()


def getPage():
    s = requests.Session()
    s.headers = {
        "User-Agent": random.choice(USER_AGENTS),
    }
    s.keep_alive = False
    proxyGit = "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list"
    proxyPage = "http://proxylist.fatezero.org/proxy.list"
    datasGit = []
    datasPage = []
    try:
        datasGit = s.get(proxyGit).text.split('\n')
    except requests.exceptions.ConnectionError:
        try:
            datasPage = s.get(proxyPage).text.split('\n')
        except requests.exceptions.ConnectionError as e:
            logger.log('ERROR', f'网络超时，代理获取失败，请重新获取  {e}')
            exit(0)

    datas = datasGit + datasPage
    proxyDatas = []
    for proxy_str in datas:
        if proxy_str:
            proxy_json = json.loads(proxy_str)
            if country == "cn":
                if proxy_json['country'] == "CN":
                    host = proxy_json['host']
                    port = proxy_json['port']
                    types = proxy_json['type']
                    proxyDatas.append([types, host, port])
            else:
                host = proxy_json['host']
                port = proxy_json['port']
                types = proxy_json['type']
                proxyDatas.append([types, host, port])

    return proxyDatas


def getProxy(files):
    logger.log('INFOR', f'正在获取代理IP')
    proxyDatas = getPage()
    logger.log('INFOR', f'总共获取{len(proxyDatas)}条代理IP')
    logger.log('INFOR', f'正在验证高质量代理IP')
    threads = []
    sem = threading.Semaphore(threadNum)
    try:
        for i in proxyDatas:
            types = i[0]
            host = i[1]
            port = i[2]
            sem.acquire()
            t = ProxyInfo(types, host, port, sem)
            t.setDaemon(True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass
    if proxyList:
        logger.log('INFOR', f'获取{len(proxyList)}条高质量IP')
        for p in proxyList:
            with open(files, 'a', encoding="utf-8") as f:
                f.write(str(p))
                f.write('\n')
    else:
        logger.log('ERROR', f'在线获取失败')


def checkProxyFile():
    files = os.path.join(relative_directory, 'proxy.txt')
    if os.path.isfile(files):
        fileTamp = os.stat(files).st_mtime  # 获取文件创建时间
        timeArray = time.localtime(fileTamp)
        fileTime = time.strftime("%Y%m%d%H%M", timeArray)
        osTime = time.strftime("%Y%m%d%H%M", time.localtime())
        contrast = int(osTime) - int(fileTime)
        # 代理文件创建超过15分钟，才会重新获取代理
        if contrast >= 15:
            os.remove(files)
            getProxy(files)
        else:
            try:
                with open(files, 'r', encoding="utf-8") as f:
                    for pro in f.readlines():
                        p = pro.strip()
                        _proxy = eval(p)
                        proxyList.append(_proxy)
                logger.log('INFOR', f'共获取 {len(proxyList)} 条高质量代理IP')
            except FileNotFoundError as e:
                logger.log('DEBUG', f'{str(e)}')
                pass
    else:
        getProxy(files)