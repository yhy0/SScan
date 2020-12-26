#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import pathlib

# 路径设置
relative_directory = pathlib.Path(__file__).parent.parent  # 项目代码相对路径
data_storage_dir = relative_directory.joinpath('lib/data')  # 检查cdn所用到的数据存放目录

stop_me = False

ports_saved_to_file = False

default_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
    "Connection": "close"
}

