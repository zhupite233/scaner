# --*-- coding:utf-8 --*--
import os
import urlparse
from time import sleep
from time import time
import chardet
import gevent
from gevent import monkey
from gevent import Greenlet
from gevent import pool
from gevent import queue
from gevent import event
from gevent import Timeout
from gevent import threadpool

monkey.patch_all()
import logging

from scan_spider.fetcher import Fetcher
from scan_spider.webkit import WebKit
from Data import UrlCache, UrlData
from scan_spider.crawler import Crawler
from utils import to_unicode

'''
基于gevent和多线程模型，支持WebKit引擎的DOM解析动态爬虫框架。
框架由两部分组成：
fetcher:下载器，负责获取HTML，送入crawler。
crawler:爬取器，负责解析并爬取HTML中的URL，送入fetcher。
fetcher和crawler两部分独立工作，互不干扰，通过queue进行链接
fetcher需要发送HTTP请求，涉及到阻塞操作，使用gevent池控制
crawler没有涉及阻塞操作，但为了扩展可以自选gevent池和多线程池两种模型控制
'''


class Spider(object):
    """爬虫主类"""
    logger = logging.getLogger("spider")

    def __init__(self, concurrent_num=20, crawl_tags=[], custom_headers={}, plugin=[], depth=10,
                 max_url_num=3000, internal_timeout=60, spider_timeout=1800, dir_max_url=15,
                 crawler_mode=0, same_origin=True, dynamic_parse=False, login_dict={}, scan_task_id=0):
        """
        concurrent_num    : 并行crawler和fetcher数量
        crawl_tags        : 爬行时收集URL所属标签列表
        custom_headers    : 自定义HTTP请求头
        plugin            : 自定义插件列表
        depth             : 爬行深度限制
        max_url_num       : 最大收集URL数量
        internal_timeout  : 内部调用超时时间
        spider_timeout    : 爬虫超时时间
        crawler_mode      : 爬取器模型(0:多线程模型,1:gevent模型)
        same_origin       : 是否限制相同域下
        dynamic_parse     : 是否使用WebKit动态解析
        """

        self.logger.setLevel(logging.DEBUG)
        hd = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        hd.setFormatter(formatter)
        self.logger.addHandler(hd)

        self.stopped = event.Event()
        self.internal_timeout = internal_timeout
        self.internal_timer = Timeout(internal_timeout)
        self.spider_stop_time = time()+spider_timeout
        self.crawler_mode = crawler_mode  # 爬取器模型
        self.concurrent_num = concurrent_num
        self.fetcher_pool = pool.Pool(self.concurrent_num)
        if self.crawler_mode == 0:
            self.crawler_pool = threadpool.ThreadPool(min(50, self.concurrent_num))
        else:
            self.crawler_pool = pool.Pool(self.concurrent_num)
        # self.fetcher_queue = queue.JoinableQueue(maxsize=self.concurrent_num*100)
        self.fetcher_queue = threadpool.Queue(maxsize=self.concurrent_num * 10000)
        self.crawler_queue = threadpool.Queue(maxsize=self.concurrent_num * 10000)

        self.fetcher_cache = UrlCache()
        self.crawler_cache = UrlCache()

        self.default_crawl_tags = ['script', 'a', 'base', 'iframe', 'frame', 'object']
        self.ignore_ext = ['js', 'css', 'png', 'jpg', 'gif', 'bmp', 'svg', 'exif', 'jpeg', 'exe', 'rar', 'zip', 'swf', 'ico']
        self.crawl_tags = list(set(self.default_crawl_tags) | set(crawl_tags))
        self.same_origin = same_origin
        self.depth = depth
        self.max_url_num = max_url_num
        self.dir_max_url = dir_max_url
        self.dynamic_parse = dynamic_parse
        if self.dynamic_parse:
            self.webkit = WebKit(login_dict)
            if login_dict:
                self.webkit.auto_login()
            # elif custom_headers.get('Cookie'):
            #
            #     self.webkit.set_cookie(custom_headers)

        self.crawler_stopped = event.Event()

        self.plugin_handler = plugin  # 注册Crawler中使用的插件
        self.custom_headers = custom_headers
        self.scan_task_id = scan_task_id

    def _start_fetcher(self):
        '''
        启动下载器
        '''
        for i in xrange(self.concurrent_num):
            fetcher = Fetcher(self)
            self.fetcher_pool.start(fetcher)

    def _start_crawler(self):
        '''
        启动爬取器
        '''
        for _ in xrange(self.concurrent_num):
            crawler = Crawler(self)
            self.crawler_pool.spawn(crawler._run())

    def start(self):
        '''
        主启动函数
        '''
        self.logger.info("spider starting...")

        if self.crawler_mode == 0:
            self.logger.info("crawler run in multi-thread mode.")
        elif self.crawler_mode == 1:
            self.logger.info("crawler run in gevent mode.")

        self._start_fetcher()
        # sleep(60)
        self._start_crawler()
        print 2222222222222
        self.stopped.wait()  # 等待停止事件置位

        try:
            self.internal_timer.start()
            self.fetcher_pool.join(timeout=self.internal_timer)
            if self.crawler_mode == 1:
                self.crawler_pool.join(timeout=self.internal_timer)
            else:
                self.crawler_pool.join()
        except Timeout:
            self.logger.error("internal timeout triggered")
        finally:
            self.internal_timer.cancel()

        self.stopped.clear()
        if self.dynamic_parse:
            self.webkit.close()
        self.logger.info("crawler_cache:%s fetcher_cache:%s" % (len(self.crawler_cache), len(self.fetcher_cache)))
        self.logger.info("spider process quit.")

    def feed_url(self, url):
        '''
        设置初始爬取URL
        '''
        if isinstance(url, basestring):
            url = to_unicode(url)
            url = UrlData(url)

        if self.same_origin:
            url_part = urlparse.urlparse(unicode(url))
            self.origin = (url_part.scheme, url_part.netloc)

        self.fetcher_queue.put(url, block=True)

    def stop(self):
        '''
        终止爬虫
        '''
        self.stopped.set()


if __name__ == '__main__':
    url = 'http://zero.webappsecurity.com/'
    url_parse = urlparse.urlparse(url)
    custom_headers = {
        'Host': url_parse.netloc,
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0',
        'Accept-Encoding':'gzip,deflate,sdch',
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Referer": url,
        'Cookie': 'yd_cookie=6eb369f2-5f47-4d0e52fbf46c31ae4b581a19410917e1eb92;_uACOOKIE=0dfbcb328220039e29f8348215e2c06e'
    }
    # login_dict = {'login_url': 'http://192.168.3.86:8091/login', 'values': {'username': 'admin', 'password': 'abcd1234', 'auth_code': ''}}
    from datetime import datetime
    t_str = datetime.now().strftime('%m%d%H%M')

    print int(t_str)
    spider = Spider(concurrent_num=2, depth=20, max_url_num=300, crawler_mode=1, dynamic_parse=True, spider_timeout=25*60,
                    custom_headers=custom_headers, login_dict=None, scan_task_id=int(t_str))

    spider.feed_url(url)
    spider.start()
