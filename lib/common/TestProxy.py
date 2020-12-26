# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import requests
from config.log import logger

# def testProxy(options,show):
def testProxy(show):
    try:
        url = "http://myip.ipip.net/"
        # proxy_data = {
        #     'http': options.proxy,
        #     'https': options.proxy,
        # }

        ipAddr = requests.get(url, timeout=7, verify=False).text[3:].strip()
        # ipAddr = requests.get(url, proxies=proxy_data, timeout=7, verify=False).text.strip()
        if show == 1:
            logger.log('INFOR', f'[+] 网络连通性检测通过，当前出口{ipAddr}')
        return True
    except:
        if show == 1:
            logger.log('ERROR', f'外网连接失败，请检查当前网络状况或者代理情况')
        return False

