#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import pathlib
import multiprocessing

# 路径设置
relative_directory = pathlib.Path(__file__).parent.parent  # 项目代码相对路径
data_storage_dir = relative_directory.joinpath('lib/data')  # 检查cdn所用到的数据存放目录

stop_me = False

ports_saved_to_file = False

default_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
    "Connection": "close",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
}

tasks_count = multiprocessing.Value('i', 0)  # 任务计数器
