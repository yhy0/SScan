# -*- coding:utf-8 -*-
# !/usr/bin/python3
# @Time   : 2021/2/25 10:44
# @Author : yhy
import asyncio
import random
import platform
from lib.common.utils import get_host
# 进度条设置
from rich.progress import (
    BarColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
    Progress,
)

# 使用协程进行端口扫描
class PortScan(object):
    def __init__(self, targets, rate=2000, timeout=3):
        super(PortScan, self).__init__()
        self.targets = targets
        self.hosts = []
        self.rate = rate                # 限制并发量
        self.timeout = timeout
        self.result = []
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
        self.progress_bar = self.process.add_task("[cyan]port scan...", total=len(self.targets))

    async def async_port_check(self, semaphore, target):
        # target ('127.0.0.1', 8080, 'http', '/', 8080)
        async with semaphore:
            host, port = target[0], target[1]
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                conn.close()
                # '127.0.0.1 80' open 'unknown' '/test.html' 80
                return host, port, 'open', target[2], target[3], target[4]
            except Exception:
                conn.close()
                return host, port, 'close', target[2], target[3], target[4]

    # 回调函数，更新进度条，存储开放的端口
    def callback(self, future):
        # future.result() '127.0.0.1' 80 open 'unknown' '/test.html' 80
        result = future.result()
        self.process.advance(self.progress_bar, advance=1)
        if result[2] == "open":
            self.result.append(result)
        else:
            pass

    def async_tcp_port_scan(self):
        try:
            sem = asyncio.Semaphore(self.rate) # 限制并发量
            loop = asyncio.get_event_loop()

            # self.targets [('127.0.0.1', 8080, 'http', '/', 8080), ('www.baidu.cn', 80, 'unknown', '/', 80), ('www.baidu.cn', 443, 'unknown', '/', 443)]
            # 打乱一下，随机排序
            random.shuffle(self.targets)

            tasks = list()
            with self.process:
                for target in self.targets:
                    task = asyncio.ensure_future(self.async_port_check(sem, target))
                    task.add_done_callback(self.callback)
                    tasks.append(task)

                if platform.system() != "Windows":
                    import uvloop
                    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                loop.run_until_complete(asyncio.wait(tasks))
        except Exception:
            pass
        return self.result
