#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import json
import base64
import random
import requests
# 禁用安全请求警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.common.connectionPool import conn_pool
from config.setting import fofaApi, fofaSize, fofaCountry
from config.setting import USER_AGENTS
from config.setting import threadNum,  default_headers

# 进度条设置
from rich.progress import (
    BarColumn,
    TimeRemainingColumn,
    Progress,
)

progress = Progress(
    "[progress.description]{task.description}",
    BarColumn(),
    "[progress.percentage]{task.percentage:>3.0f}%",
    TimeRemainingColumn(),
    "[bold red]{task.completed}/{task.total}",
    transient=True
)


class Fofa:
    def __init__(self, ip):
        super(Fofa, self).__init__()
        self.email = fofaApi['email']
        self.key = fofaApi['key']
        self.headers = {
            "Cache-Control": "max-age=0",
            "User-Agent": random.choice(USER_AGENTS),
            "Upgrade-Insecure-Requests": "1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        }
        self.ip = ip
        self.urls = []          # fofa 查询到的web服务列表
        self.life_urls = []     # 验证存活的web服务列表

    def run(self):
        keywordsBs = base64.b64encode(self.ip.encode('utf-8'))
        keywordsBs = keywordsBs.decode('utf-8')

        url = "https://fofa.so/api/v1/search/all?email={0}&key={1}&qbase64={2}&full=true&fields=ip,title,port,domain,protocol,host,country&size={3}".format(
            self.email, self.key, keywordsBs, fofaSize)
        try:
            session = conn_pool()
            target = session.get(url, timeout=10)
            # logger.log('INFOR', f'正在检测IP: {self.ip}')
            # logger.log('INFOR', '正在通过API获取信息...')
            datas = json.loads(target.text)
            self.ip_info(datas['results'])
            session.close()

            self.is_life()
            return self.life_urls

        except requests.exceptions.ReadTimeout:
            pass
            # logger.log('ERROR', '请求超时')
        except requests.exceptions.ConnectionError as e:
            pass
            # logger.log('ERROR', f'网络超时  {e}')
        except json.decoder.JSONDecodeError:
            pass
            # logger.log('ERROR', '获取失败，请重试')
        finally:
            return self.life_urls

    def ip_info(self, datas):
        for data in datas:
            # ip,title,port,domain,protocol,host,country
            # ['127.0.0.1', 'Metasploit - Setup and Configuration', '3790', '', '', 'https://127.0.0.1:3790', 'CN']
            # 只要限定国家的信息， 默认为CN
            if data[6] == fofaCountry:
                if data[4] == "http" or data[4] == "https":
                    url = "{0}://{1}".format(data[4], data[5])
                    if url not in self.urls:
                        self.urls.append(url)

    # 筛选存活的web服务
    def is_life(self):
        if len(self.urls) == 0:
            return
        session = conn_pool()
        for url in self.urls:
            try:
                status_code = session.get(url, headers=default_headers, timeout=5).status_code
                if status_code < 500:
                    self.life_urls.append(url)
            except requests.exceptions.ConnectionError:
                pass
        session.close()


def run(ip, task):
    fofa = Fofa(ip)
    result = fofa.run()
    progress.update(task, advance=1)
    return result


def fmain(ips):
    # result ['http://127.0.0.1:3790', 'http://127.0.0.1:80', 'https://127.0.0.1:443']
    result = []

    try:
        # 进度条
        with progress:
            task = progress.add_task("[cyan]FOFA search、Filtering the surviving Web services ", total=len(ips), start=False)

            executor = ThreadPoolExecutor(max_workers=threadNum)

            all_task = [executor.submit(run, ip, task) for ip in ips]

            for future in as_completed(all_task):
                data = future.result()
                result.extend(data)
    except KeyboardInterrupt:
        pass
    finally:
        return result

