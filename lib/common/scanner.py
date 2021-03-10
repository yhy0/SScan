#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import requests
import asyncio
from concurrent.futures import ThreadPoolExecutor
# 禁用安全请求警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import importlib
from yarl import URL
import traceback
import re
import time
import os
from bs4 import BeautifulSoup
from lib.config.log import logger
from lib.common.utils import get_domain_sub, cal_depth, get_html
from lib.config.setting import proxyList, default_headers

from lib.common.connectionPool import conn_pool


class Scanner(object):
    def __init__(self, args):
        self.args = args
        self.start_time = time.time()
        self.time_flag = True
        self.links_limit = 100  # max number of folders to scan
        self._init_rules()

        self._init_scripts()
        self.timeout = 10 * 60      # 每个目标的最大扫描分钟，默认为10分钟,
        self.session = conn_pool()  # 使用连接池

        self.url_list = list()  # all urls to scan 任务处理队列
        self.urls_processed = set()     # processed urls
        self.urls_enqueued = set()      # entered queue urls
        self.urls_crawled = set()

        self._302_url = set()  # 302 跳转后，页面符合黑名单规则的
        self._403_url = [] # 403 url 的 返回包

        self.results = {}
        self._404_status = -1

        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.max_depth = 0
        self.len_404_doc = 0
        self.has_http = None
        self.script = None
        self.ports_open = None
        self.ports_closed = None
        self.no_scripts = None
        self.status_502_count = 0
        self.flag = False
        self.check = True  # 当页面502 时，标记为False，不再检查

    def reset_scanner(self):
        self.start_time = time.time()
        self.url_list.clear()
        self.urls_processed.clear()
        self.urls_enqueued.clear()
        self.urls_crawled.clear()
        self.results.clear()
        self._404_status = -1
        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.status_502_count = 0

    # scan from a given URL
    '''
        {'scheme': 'http', 'host': '127.0.0.1', 'port': 8088, 'path': '/', 'ports_open':[8088], 'script': True, 'has_http': True}
    '''
    def init_from_url(self, target):
        self.reset_scanner()
        self.scheme = target['scheme']
        self.host = target['host']
        self.port = target['port']
        self.path = target['path']
        self.has_http = target['has_http']
        self.script = target['script']
        self.ports_open = target['ports_open']
        self.domain_sub = get_domain_sub(self.host)     # baidu.com >> baidu
        self.init_final()
        return True

    def init_final(self):
        if self.scheme == 'http' and self.port == 80 or self.scheme == 'https' and self.port == 443:
            self.base_url = f'{self.scheme}://{self.host}'
        elif self.scheme != 'unknown' and self.host.find(':') >= 0:
            self.base_url = f'{self.scheme}://{self.host}'
        else:
            self.base_url = f'{self.scheme}://{self.host}:{self.port}'

        if not self.has_http:
            logger.log('DEBUG', f'NO_HTTP_Scan %s:%s' % (self.host, self.port) if self.port else 'Scan %s' % self.host)

        # 脚本
        if self.script:
            for _ in self.user_scripts:
                self.url_list.append((_, '/'))

        if not self.has_http or self.args.scripts_only:  # 未发现HTTP服务 或  只依赖插件扫描
            return

        # todo  当url 类似 http://www.example.com , path:'' , max_depth = 1+5=6
        self.max_depth = cal_depth(self, self.path)[1] + 5

        self.check_404_existence()

        if self._404_status == -1:
            logger.log('DEBUG', f'HTTP 404 check failed %s' % self.base_url)
        elif self._404_status != 404:
            logger.log('DEBUG', f'%s has no HTTP 404.  {self._404_status}' % self.base_url)

        _path, _depth = cal_depth(self, self.path)

        # 加入队列
        self.enqueue('/')

    # 进行http请求
    def http_request(self, url, timeout=10):
        try:
            if not url:
                url = '/'
            if not self.session:
                return -1, {}, ''
            # 使用代理，但是代理效果不是很好，这里就不使用了
            # self.session.proxies = random.choice(proxyList)
            #
            # self.session.proxies = {
            #     "https": "https://127.0.0.1:8080",
            #     "http": "http://127.0.0.1:8080"
            # }

            resp = self.session.get(self.base_url + url, allow_redirects=False, headers=default_headers, timeout=timeout)

            headers = resp.headers
            status = resp.status_code

            # 502出现3次以上，排除该站点
            if status == 502:
                self.status_502_count += 1
                if self.status_502_count > 3:
                    self.url_list.clear()
                    try:
                        if self.session:
                            self.session.close()
                    except Exception as e:
                        logger.log('DEBUG', f'{str(e)}')
                        pass
                    self.session = None
            # 301 永久移动时，重新获取response
            if status == 301:
                target = headers.get('Location')
                if not target.startswith('/file:'):
                    try:
                        resp = self.session.get(URL(target, encoded=True), headers=default_headers, allow_redirects=False, timeout=timeout, verify=False)
                        headers = resp.headers
                    except Exception as e:
                        logger.log('DEBUG', f'{e},  {target}  {self.base_url + url}')
                        pass

            # 前面禁止重定向， 但有时，网页重定向后才会有东西
            if status == 302:
                new_url = headers["Location"]

                if new_url not in self._302_url:
                    resp = self.session.get(URL(new_url, encoded=True), headers=default_headers, timeout=timeout, verify=False)
                    headers = resp.headers
                    self._302_url.add(new_url)

            html_doc = get_html(headers, resp)

            # 页面不在黑名单规则里面时， 403 返回包 记录，扫描完成后计算大小，然后再判断是否进行403绕过
            # 若 403 返回包 的最终个数小于20，则不进行绕过测试，认为是一种网站防扫描措施
            if not self.find_exclude_text(html_doc) and status == 403:
                self._403_url.append(url)

            logger.log('DEBUG', f'{self.base_url + url}   status: {status}')
            return status, headers, html_doc
        except requests.exceptions.RetryError as e:
            logger.log('DEBUG', f'{str(e)}   {self.base_url + url}')
            return -1, {}, ''
        except requests.exceptions.ReadTimeout as e:
            logger.log('DEBUG', f'{str(e)}   {self.base_url + url}')
            return -1, {}, ''
        except requests.exceptions.ConnectionError as e:
            logger.log('DEBUG', f'IP可能被封了  {str(e)}    {self.base_url + url}')
            return -1, {}, ''
        except TypeError as e:
            logger.log('DEBUG', f'{str(e)}   {self.base_url + url}')
            return -1, {}, ''
        except Exception as e:
            logger.log('DEBUG', f'{str(e)}   {self.base_url + url}')
            logger.log('DEBUG', f'{traceback.format_exc()}')
            return -1, {}, ''

    def bypass_403(self, url_403, timeout=5):
        try:
            resp = self.session.get(self.base_url + url_403, allow_redirects=False, headers=default_headers,
                                      timeout=timeout)
            OriginalUrl = url_403
            Rurl = url_403
            if OriginalUrl == "/test-scan-404-existence-check":
                return

            if Rurl != "/":
                Rurl = url_403.rstrip("/")

            PreviousPath = '/'.join(str(Rurl).split('/')[:-1])
            LastPath = str(Rurl).split('/')[-1]

            payloads = ["%2e/" + LastPath, "%2f/" + LastPath, LastPath + "/.", LastPath + "/./.",
                        LastPath + "/././", LastPath + "/./", "./" + LastPath + "/./", LastPath + "%20/",
                        LastPath + "%09/", "%20" + LastPath + "%20/", LastPath + "/..;/", LastPath + "..;/",
                        LastPath + "?", LastPath + "??", LastPath + "???", LastPath + "//", LastPath + "/*",
                        LastPath + "/*/", "/" + LastPath + "//", LastPath + "/", LastPath + "/.randomstring"]
            for p in payloads:
                url = PreviousPath + "/" + p
                resp_p = self.session.get(self.base_url + url, allow_redirects=False, headers=default_headers,
                                          timeout=timeout)
                # 当状态码为200时，且该页面的 Content-Length 不与首页相等时，认为可以绕过403
                if resp_p.status_code == 200 and resp_p.headers.get('Content-Length') != resp.headers.get('Content-Length'):
                    if OriginalUrl not in self.results:
                        self.results[OriginalUrl] = []
                    _ = {'status': resp_p.status_code, 'url': '%s%s' % (self.base_url, OriginalUrl),
                         'title': f'绕过payload: {self.base_url}{url}', 'vul_type': "403绕过"}
                    if _ not in self.results[OriginalUrl]:
                        self.results[OriginalUrl].append(_)
                    break

            hpayloads = [{"X-Rewrite-URL": OriginalUrl}, {"X-Original-URL": OriginalUrl}, {"Referer": "/" + LastPath},
                         {"X-Custom-IP-Authorization": "127.0.0.1"}, {"X-Originating-IP": "127.0.0.1"},
                         {"X-Forwarded-For": "127.0.0.1"}, {"X-Remote-IP": "127.0.0.1"},
                         {"X-Client-IP": "127.0.0.1"}, {"X-Host": "127.0.0.1"}, {"X-Forwarded-Host": "127.0.0.1"}]

            for hp in hpayloads:
                # 这个headers 是为了防止update时，连续添加入字典，不能使用default_headers，不然会连续增加，default_headers会发生变化
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36(KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
                    "Connection": "close",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
                }
                key, = hp
                value, = hp.values()
                new_url = ""
                if key == "X-Original-URL":
                    new_url = Rurl + "4nyth1ng"
                if key == "X-Rewrite-URL":
                    new_url = "/"

                # Add header
                headers.update(hp)

                if new_url:
                    url = new_url
                else:
                    url = OriginalUrl

                resp_hp = self.session.get(self.base_url + url, allow_redirects=False, headers=headers, timeout=timeout)
                # 当状态码为200时，且该页面的 Content-Length 不与首页相等时，认为可以绕过403
                if resp_hp.status_code == 200 and resp_hp.headers.get('Content-Length') != resp.headers.get(
                        'Content-Length'):
                    if OriginalUrl not in self.results:
                        self.results[OriginalUrl] = []
                    _ = {'status': resp.status_code, 'url': '%s%s' % (self.base_url, OriginalUrl),
                         'title': f'绕过payload: {self.base_url}{url}, Header payload: {key}: {value}',
                         'vul_type': "403绕过"}
                    if _ not in self.results[OriginalUrl]:
                        self.results[OriginalUrl].append(_)
                    break
        except Exception:
            pass

    # 检查状态404是否存在
    def check_404_existence(self):
        try:
            try:
                self._404_status, _, html_doc = self.http_request('/test-scan-404-existence-check')
            except Exception as e:
                logger.log('DEBUG', f'HTTP 404 check failed: {self.base_url} {str(e)}')
                self._404_status, _, html_doc = -1, {}, ''
            if self._404_status != 404:
                self.len_404_doc = len(html_doc)
        except Exception as e:
            logger.log('DEBUG', f'[Check_404] Exception {self.base_url} {str(e)}')


    # 将检查完的 path 加入队列，加载规则和脚本
    def enqueue(self, path):
        try:
            path = str(path)
        except Exception as e:
            logger.log('DEBUG', f'{str(e)}')
            return False
        try:
            # BBScan 中 当 path 中存在数字时，将url中的数字替换成 {num}  /asdas12asd >> /asdas{num}asd
            # todo 看不懂在干嘛
            # url_pattern = re.sub(r'\d+', '{num}', path)

            url_pattern = path

            if url_pattern in self.urls_processed or len(self.urls_processed) >= self.links_limit:
                return False

            self.urls_processed.add(url_pattern)
            if self.args.crawl:  # 爬取网站的 a 标签
                self.crawl(path)
            else:
                self.index_status, self.index_headers, self.index_html_doc = self.http_request('/')

            if self._404_status != -1:  # valid web service
                # 网站主目录下扫描全部rule, 即rule和root_only标记的rule, 其他目录下扫描 只扫描rule
                rule_set_to_process = [self.rules_set, self.rules_set_root_only] if path == '/' else [self.rules_set]
                # 加载规则
                for rule_set in rule_set_to_process:
                    for _ in rule_set:
                        # _  ('/scripts/samples', 'IIS', 200, '', '', True, 'iis')
                        try:
                            full_url = path.rstrip('/') + _[0]
                        except Exception as e:
                            logger.log('DEBUG', f'{str(e)}')
                            continue
                        if full_url in self.urls_enqueued:
                            continue
                        url_description = {'prefix': path.rstrip('/'), 'full_url': full_url}
                        item = (url_description, _[1], _[2], _[3], _[4], _[5], _[6])
                        self.url_list.append(item)
                        self.urls_enqueued.add(full_url)

            # 本来若只找到 /asdd/asd/ 这种链接，没有/asdd/ 这个子目录，会将/asdd/子目录添加进去处理
            if path.count('/') >= 2:
                self.enqueue('/'.join(path.split('/')[:-2]) + '/')  # sub folder enqueue

            if path != '/' and not self.no_scripts:
                for script in self.user_scripts:
                    self.url_list.append((script, path))

            return True
        except Exception as e:
            logger.log('ERROR', f'[_enqueue.exception] %s' % str(e))
            logger.log('DEBUG', f'{traceback.format_exc()}')
            return False

    # 在页面中匹配rules的白名单规则
    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) >= 0:
                return True, 'Found [%s]' % _text
        for _regex in self.regex_to_find:
            if _regex.search(html_doc):
                return True, 'Found Regex [%s]' % _regex.pattern
        return False

    # 匹配黑名单规则
    def find_exclude_text(self, html_doc):
        for _text in self.text_to_exclude:
            if html_doc.find(_text) >= 0:
                return True
        for _regex in self.regex_to_exclude:
            if _regex.search(html_doc):
                return True
        return False

    # 循环爬取页面的超链接，放入队列self.enqueue()， 匹配rules的白名单规则
    def crawl(self, path, do_not_process_links=False):
        try:
            status, headers, html_doc = self.http_request(path)

            if path == '/':
                self.index_status, self.index_headers, self.index_html_doc = status, headers, html_doc
            if self.args.crawl and not do_not_process_links and html_doc:
                soup = BeautifulSoup(html_doc, "html.parser")
                # 循环爬取a标签
                for link in soup.find_all('a'):
                    url = link.get('href', '').strip()
                    if url.startswith('..'):
                        continue
                    if not url.startswith('/') and url.find('//') < 0:  # 相对路径
                        url = path + url
                    url, depth = cal_depth(self, url)

                    if depth <= self.max_depth:
                        self.enqueue(url)
                # 匹配rules的白名单规则
                ret = self.find_text(html_doc)
                if ret:
                    if '/' not in self.results:
                        self.results['/'] = []
                    m = re.search('<title>(.*?)</title>', html_doc)
                    title = m.group(1) if m else ''
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, path), 'title': title, 'vul_type': ret[1]}
                    if _ not in self.results['/']:
                        self.results['/'].append(_)

        except Exception as e:
            logger.log('ERROR', f'[crawl Exception] %s %s' % (path, str(e)))

    # 读取rules目录下的相关规则
    def _init_rules(self):
        self.text_to_find = self.args.text_to_find
        self.regex_to_find = self.args.regex_to_find
        self.text_to_exclude = self.args.text_to_exclude
        self.regex_to_exclude = self.args.regex_to_exclude
        self.rules_set = self.args.rules_set
        self.rules_set_root_only = self.args.rules_set_root_only

    def _init_scripts(self):
        self.user_scripts = []
        if self.args.no_scripts:  # 全局禁用插件，无需导入
            return
        for _script in self.args.script_files:
            # 跳过__init__.py
            if _script.startswith('pocs/scripts/__') or _script.startswith('pocs\\scripts\\__'):
                continue
            script_name_origin = os.path.basename(_script)
            script_name = script_name_origin.replace('.py', '')

            try:
                self.user_scripts.append(importlib.import_module('pocs.scripts.%s' % script_name))
            except Exception as e:
                logger.log('ERROR', f'Fail to load script %s,  {e}' % script_name)

    def scan_worker(self, item):
        if not self.flag and time.time() - self.start_time > self.timeout:
            self.flag = True
            if self.flag:
                self.url_list.clear()
                # self.flag = False
                logger.log('ERROR', f'Timed out task: %s' % self.base_url)
            return
        url, url_description, tag, status_to_match, content_type, content_type_no, root_only, vul_type, prefix = None, None, None, None, None, None, None, None, None

        try:
            if len(item) == 2:  # Script Scan
                check_func = getattr(item[0], 'do_check')
                check_func(self, item[1])
            else:
                # ({'prefix': '', 'full_url': '/trace'}, 'Spring boot serverProperties', 200, '', '', True, 'springboot')
                url_description, tag, status_to_match, content_type, content_type_no, root_only, vul_type = item
                prefix = url_description['prefix']
                url = url_description['full_url']

                '''
                {sub} 这个是规则里设置的， 主要是根据当前域名来做字典，
                比如{sub}.sql ,当前域名为baidu.com ，则规则改为 baidu.sql
                '''
                if url.find('{sub}') >= 0:
                    if not self.domain_sub:
                        return
                    url = url.replace('{sub}', self.domain_sub)

        except Exception as e:
            logger.log('ERROR', f'[scan_worker.1][%s %s] {e}' % (item[0], item[1]))
            return
        if not item or not url:
            return

        # 开始规则目录探测
        try:
            status, headers, html_doc = self.http_request(url)
            cur_content_type = headers.get('content-type', '')
            cur_content_length = headers.get('content-length', len(html_doc))

            if self.find_exclude_text(html_doc):  # 黑名单规则排除
                return
            if 0 <= int(cur_content_length) <= 10:  # text too short
                return
            if cur_content_type.find('image/') >= 0:  # exclude image
                return

            # 当指定 content_type 时,
            if content_type and content_type != 'json' and cur_content_type.find('json') >= 0:
                return
            # content type mismatch
            if (content_type and cur_content_type.find(content_type) < 0) or (
                    content_type_no and cur_content_type.find(content_type_no) >= 0):
                return
            if tag and html_doc.find(tag) < 0:
                return  # tag mismatch

            # 在页面中匹配rules的白名单规则
            if self.find_text(html_doc) and status == 200:
                valid_item = True
            else:
                # status code check
                if status_to_match == 206 and status != 206:
                    return
                if status_to_match in (200, 206) and status in (200, 206):
                    valid_item = True
                elif status_to_match and status != status_to_match:
                    return
                elif status in (403, 404) and status != status_to_match:
                    return
                else:
                    valid_item = True

                if status == self._404_status and url != '/':
                    len_doc = len(html_doc)
                    len_sum = self.len_404_doc + len_doc
                    if len_sum == 0 or (0.4 <= float(len_doc) / len_sum <= 0.6):
                        return

            if valid_item:
                m = re.search('<title>(.*?)</title>', html_doc)
                title = m.group(1) if m else ''
                if prefix not in self.results:
                    self.results[prefix] = []
                _ = {'status': status, 'url': '%s%s' % (self.base_url, url), 'title': title, 'vul_type': vul_type}
                if _ not in self.results[prefix]:
                    self.results[prefix].append(_)
        except Exception:
            logger.log('ERROR', f'[scan_worker.2][%s%s]' % (self.base_url, url))
            logger.log('DEBUG', f'{traceback.format_exc()}')


    # 使用多线程对目标进行扫描
    def scan(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            import platform
            if platform.system() != "Windows":
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

            executor = ThreadPoolExecutor(self.args.t)

            tasks = [loop.run_in_executor(executor, self.scan_worker, item) for item in self.url_list]
            # 这一步很重要，使用loop.run_in_executor()函数: 内部接受的是阻塞的线程池，执行的函数，传入的参数

            loop.run_until_complete(asyncio.wait(tasks))

            loop.close()

            # 扫描完成后， 计算 self._403_url 的大小
            if len(self._403_url) < 20:
                logger.log("DEBUG", f'对 {self.base_url} 进行 403 绕过测试')
                for resp in self._403_url:
                    self.bypass_403(resp)

            # 等待所有的任务完成
            for key in self.results.keys():
                # todo 为何？
                # 超过5个网址在这个文件夹下发现，保留第一个
                if len(self.results[key]) > 5:
                    self.results[key] = self.results[key][:1]
            return self.base_url.lstrip('unknown://').rstrip(':None'), self.results
        except Exception as e:
            logger.log('ERROR', f'[scan exception] {e}')
