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
    def __init__(self, targets, port_list, rate=2000, timeout=3):
        super(PortScan, self).__init__()
        self.targets = targets
        self.hosts = []
        self.rate = rate                # 限制并发量
        self.timeout = timeout
        self.open_list = {}
        self.port_list = port_list      # 待扫描的端口列表
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
        self.progress_bar = self.process.add_task("[cyan]port scan...", total=len(self.targets) * len(self.port_list))

    async def async_port_check(self, semaphore, host_port):
        async with semaphore:
            host, port = host_port
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                conn.close()
                return host, port, 'open'
            except Exception:
                conn.close()
                return host, port, 'close'

    # 回调函数，更新进度条，存储开放的端口
    def callback(self, future):
        host, port, status = future.result()
        self.process.advance(self.progress_bar, advance=1)
        if status == "open":
            # print(ip,port,status)
            try:
                if host in self.open_list:
                    self.open_list[host].append(port)
                else:
                    self.open_list[host] = [port]
            except Exception as e:
                print(e)
        else:
            pass

    def async_tcp_port_scan(self):
        # 不支持带协议的url，比如 https://127.0.0.1，格式化一下目标
        for url in self.targets:
            host, scheme = get_host(url)
            self.hosts.append(host)

        host_port_list = [(host, int(port)) for host in self.hosts for port in self.port_list]

        print(host_port_list)
        sem = asyncio.Semaphore(self.rate) # 限制并发量
        loop = asyncio.get_event_loop()

        # 打乱一下，随机排序
        random.shuffle(host_port_list)

        tasks = list()
        with self.process:
            for host_port in host_port_list:
                task = asyncio.ensure_future(self.async_port_check(sem, host_port))
                task.add_done_callback(self.callback)
                tasks.append(task)

            if platform.system() != "Windows":
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            loop.run_until_complete(asyncio.wait(tasks))

        return self.open_list

if __name__ == '__main__':
    # 不支持带协议的，比如 https://127.0.0.1
    hosts = ['127.0.0.1', '127.0.0.1']
    ports = [80,443,3389,22,21,3750]
    import time
    now = time.time

    start = now()
    ps = PortScan(hosts, ports, 2000)
    # {'127.0.0.1': [80, 22], '127.0.0.1': [22, 443, 80]}
    print(ps.async_tcp_port_scan())
    print("Time:",now() - start)
