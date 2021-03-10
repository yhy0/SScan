# -*- coding:utf-8 -*-
# !/usr/bin/python3
# @Time   : 2021/3/7 15:15
# @Author : yhy

import aiohttp
import asyncio
from functools import partial
import random
import re
import json
import platform
import base64
from concurrent.futures import ThreadPoolExecutor
from lib.common.connectionPool import conn_pool
from lib.config.setting import fofaApi, fofaSize, USER_AGENTS, fofa_list, fofaCountry
from lib.config.log import logger

# 进度条设置
from rich.progress import (
    BarColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
    Progress,
)

class Fofa:
    def __init__(self, targets, fofa_result):
        super(Fofa, self).__init__()
        self.email = fofaApi['email']
        self.key = fofaApi['key']
        self.fofa_result = fofa_result
        self.targets = targets
        self.result_urls = []  # fofa 查询到的web服务列表
        self.urls_list = []  # 去重
        self.life_urls = []  # 验证存活的web服务列表
        self.urls = []  # fofa查询的 url 列表, 供异步协程使用
        self.count = 30  # fofa 一次性查多少个
        self.session = conn_pool()  # 使用连接池
        self.headers = {
            "Cache-Control": "max-age=0",
            "User-Agent": random.choice(USER_AGENTS),
            "Upgrade-Insecure-Requests": "1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        }

        self.process = Progress(
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
        self.fofa_progress_bar = self.process.add_task("[cyan]FOFA search...", total=len(self.targets))

        self.web_progress_bar = None

    def run(self):
        try:
            with self.process:
                self.target_formatting()  # fofa 查询url 初始化

                loop = asyncio.get_event_loop()
                loop.run_until_complete(self.fetch_all(loop))   # fofa 搜索

                self.session.close()
                self.is_life()      # 对fofa搜到的结果，取出其中的web服务，然后对web服务进行验证是否可以访问
        except Exception as e:
            logger.log("ERROR", e)
        return self.life_urls

    # 为了防止查询过快被fofa封IP, 这里将目标分割，每30个为一组，组内使用 || 语法拼接，一次性查询多个
    def target_formatting(self):
        for i in range(0, len(self.targets), self.count):
            keyword = ''
            targets = self.targets[i:i + self.count]
            for host in targets:
                host = host.replace('\n', '').replace('\r', '').strip()
                keyword += f'"{host}" || '

            keyword = keyword[:-4]  # 去除最后的 ||
            keywordsBs = base64.b64encode(keyword.encode('utf-8'))
            keywordsBs = keywordsBs.decode('utf-8')

            url = "https://fofa.so/api/v1/search/all?email={0}&key={1}&qbase64={2}&full=true&fields=ip,title,port,domain,protocol,host,country,header&size={3}".format(
                self.email, self.key, keywordsBs, fofaSize)

            self.urls.append(url)

    # 回调函数, 刷新进度条
    def callback(self, future, progress_bar, count):
        self.process.advance(progress_bar, advance=count)

    async def fetch_all(self, loop):
        # loop = asyncio.get_event_loop()
        # asyncio.set_event_loop(loop)

        tasks = []
        # 写完才发现 aiohttp 不支持https代理, 改用 loop.run_in_executor()函数 执行阻塞的requests库
        # async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False), headers=headers) as session:
        threads = ThreadPoolExecutor(10)
        for url in self.urls:
            # task = asyncio.ensure_future(self.fetch(session, url, sem))
            task = loop.run_in_executor(threads, self.fetch, url)
            task.add_done_callback(partial(self.callback, progress_bar=self.fofa_progress_bar, count=self.count))
            tasks.append(task)
        if platform.system() != "Windows":
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

        await asyncio.wait(tasks)

    def fetch(self, url):
        try:
            self.session.headers = self.headers

            # self.session.proxies = {
            #     "https": "http://127.0.0.1:8080"
            # }

            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                datas = json.loads(response.text)
                # 查询结果没有出错时
                if not datas['error']:
                    self.target_info(datas['results'])
            else:
                logger.log("ERROR", f'fofa 查询失败，{response.status_code }')
        except Exception as e:
            logger.log("ERROR", e)
            pass

    def target_info(self, datas):
        for data in datas:
            # ip,title,port,domain,protocol,host,country,header
            # ['127.0.0.1', 'Welcome to CentOS', '443', '', '', '127.0.0.1:443', 'CN', 'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4833\r\nAccept-Ranges: bytes\r\nContent-Type: text/html\r\nDate: Sun, 22 Nov 2020 10:40:22 GMT\r\nEtag: "53762af0-12e1"\r\nLast-Modified: Fri, 16 May 2014 15:12:48 GMT\r\nServer: nginx/1.16.1']
            # 只要限定国家的信息， 默认为CN
            if data[6] == fofaCountry:
                # if data[4] == "http" or data[4] == "https" or "http" in data[5]:
                if 'HTTP/1.' in data[7]:
                    if "http://" in data[5] or "https://" in data[5]:
                        url = data[5]
                    elif not data[4]:
                        url = "http://{1}".format(data[4], data[5])
                    else:
                        url = "{0}://{1}".format(data[4], data[5])
                    self.result_urls.append(url)

    async def crawler(self, url, semaphore):
        async with semaphore:
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False),
                                                 headers=self.headers) as session:
                    async with session.get(url, timeout=6) as resp:
                        if url in self.urls_list or url in fofa_list:  # 已存在
                            return
                        fofa_list.append(url)
                        text = await resp.text()
                        m = re.search('<title>(.*?)</title>', text)
                        title = m.group(1) if m else ''
                        status = resp.status
                        if status == 200 or status == 404 or status == 403:
                            self.urls_list.append(url)
                            self.life_urls.append((url, title))
                            self.fofa_result.put((url, title))
            except Exception:
                pass

    # 筛选存活的web服务
    def is_life(self):
        if len(self.result_urls) == 0:
            return

        self.fofa_progress_bar = self.process.add_task("[cyan]FOFA Web results verify valid...",
                                                       total=len(self.result_urls))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        sem = asyncio.Semaphore(2000)  # 限制并发量
        tasks = []
        for url in self.result_urls:
            task = loop.create_task(self.crawler(url, sem))
            task.add_done_callback(partial(self.callback, progress_bar=self.fofa_progress_bar, count=1))
            tasks.append(task)

        loop.run_until_complete(asyncio.wait(tasks))


