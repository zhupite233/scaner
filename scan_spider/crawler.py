# --*-- coding: utf-8 --*--
import json
import os
import urlparse
from time import sleep, time

import chardet
import gevent
from gevent import queue, threadpool, pool, Greenlet

from scan_spider.fetcher import Fetcher
from scan_spider.html_analyzer import HtmlAnalyzer
from Data import UrlData
from scan_spider.url_filter import get_url_element
# from common.sql_orm import DBSession
from common.spider_models import ScanSpiderUrl as SpiderUrl, ScanSpiderUrlOther
from ext import db


class Crawler(object):
    def __init__(self, spider):
        self.spider = spider

        self.crawler_pool = self.spider.crawler_pool

    def crawler(self, dep=None):
        '''
        爬行器主函数
        '''
        link_params_keys_list = []
        url_elements_list = []
        url_elements_dict = {}
        while not self.spider.stopped.isSet() and not self.spider.crawler_stopped.isSet():
            # print 111111111111111
            try:
                # self._maintain_spider()  # 维护爬虫池
                url_data = self.spider.crawler_queue.get(block=False)
                refer = url_data.url
                # print 11111111111, refer
            except queue.Empty, e:
                if self.spider.crawler_queue.unfinished_tasks == 0 and self.spider.fetcher_queue.unfinished_tasks == 0:
                    self.spider.stop()

                else:
                    if self.spider.crawler_mode == 1:
                        gevent.sleep()
                sleep(10)
            else:
                pre_depth = url_data.depth
                curr_depth = pre_depth + 1
                if curr_depth > self.spider.depth:  # 最大爬行深度判断
                    if not self.spider.crawler_stopped.isSet():
                        self.spider.crawler_stopped.set()
                    self.spider.crawler_queue.task_done()
                    continue
                link_generator = HtmlAnalyzer.extract_links(url_data.html, url_data.url, self.spider.crawl_tags)
                # url_data_dict = {}
                url_data_list = []
                for url_obj in link_generator:
                    url_data_list.append(url_obj)
                    # url_data_dict[url_dict.keys()[0]] = url_dict.values()[0]
                if self.spider.dynamic_parse:
                    link_generator = self.spider.webkit.extract_links(url_data.url)
                    for url_obj in link_generator:
                        # url_data_dict[url_dict.keys()[0]] = url_dict.values()[0]
                        url_data_list.append(url_obj)
                # link_list = url_data_dict.keys()
                # for index, link in enumerate(link_list):
                for url in url_data_list:
                    # url = url_data_dict[link]
                    link = url.url
                    if self.check_url_usable(link, refer) and 'GET' == url.method.upper():
                        # continue
                        self.spider.fetcher_queue.put(url, block=True)
                    if time() > self.spider.spider_stop_time:  # 最大爬虫时间
                        if self.spider.crawler_stopped.isSet():
                            break
                        else:
                            self.spider.crawler_stopped.set()
                            self.spider.logger.info('it is time to stop!!!!!')
                            break
                    if len(self.spider.fetcher_cache) == self.spider.max_url_num:  # 最大收集URL数量判断
                        if self.spider.crawler_stopped.isSet():
                            break
                        else:
                            self.spider.crawler_stopped.set()
                            break
                    link = to_unicode(link)
                    url.depth = curr_depth

                    # self.spider.fetcher_cache.insert(url)
                    self.spider.fetcher_cache.insert(link.rstrip('?').rstrip('#').rstrip('/'))
                    # url 去重，
                    try:
                        if not link.startswith("http"):
                            continue

                        if self.spider.same_origin:
                            if not self._check_same_origin(link):
                                try:
                                    spider_url = ScanSpiderUrlOther(url=link, task_id=self.spider.scan_task_id, refer=refer)
                                    # session = DBSession()
                                    db.session.add(spider_url)
                                    db.session.commit()
                                    # session.close()
                                except Exception, e:
                                    # session.rollback()
                                    # session.close()
                                    pass
                                continue
                        # if 'GET' == url.method.upper():
                        url_elements = (url_dir, method, url_ext, params_keys) = get_url_element(link, url.params, url.method, url.post_data)
                        if url_ext.lower() in self.spider.ignore_ext:
                            continue

                        if (link, method, params_keys) not in link_params_keys_list:
                            if url_elements in url_elements_list:
                                if url_elements_dict.get((url_dir, method, url_ext), 0) >= self.spider.dir_max_url:
                                    continue
                                else:
                                    url_elements_dict[(url_dir, method, url_ext)] += 1

                            else:
                                url_elements_list.append(url_elements)
                                url_elements_dict[(url_dir, method, url_ext)] = 1
                            link_params_keys_list.append((link, method, params_keys))
                        else:
                            continue
                        # save the url to db
                        try:
                            spider_url = SpiderUrl(url=link,task_id=self.spider.scan_task_id, params=url.params, method=url.method, url_dir=url_dir
                                               , url_ext=url_ext, refer=refer, params_keys=json.dumps(list(params_keys)))
                            # session = DBSession()
                            db.session.add(spider_url)
                            db.session.commit()
                            # session.close()
                        except Exception, e:
                            # session.rollback()
                            # session.close()
                            self.spider.logger.info(e)

                    except Exception,e:
                        pass
                    # if 'GET' == url.method.upper():
                    #     self.spider.fetcher_queue.put(url, block=True)


                # for plugin_name in self.spider.plugin_handler:  # 循环动态调用初始化时注册的插件
                #     try:
                #         plugin_obj = eval(plugin_name)()
                #         plugin_obj.start(url_data)
                #     except Exception, e:
                #         import traceback
                #         traceback.print_exc()

                self.spider.crawler_queue.task_done()

    def _run(self):
        self.crawler()

    def _maintain_spider(self):
        '''
        维护爬虫池:
        1)从池中剔除死掉的crawler和fetcher
        2)根据剩余任务数量及池的大小补充crawler和fetcher
        维持爬虫池饱满
        '''
        if self.spider.crawler_mode == 1:
            for greenlet in list(self.crawler_pool):
                if greenlet.dead:
                    self.crawler_pool.discard(greenlet)
            for i in xrange(min(self.spider.crawler_queue.qsize(),self.crawler_pool.free_count())):
                crawler = Crawler(self.spider)
                self.crawler_pool.spawn(crawler._run())

        for greenlet in list(self.spider.fetcher_pool):
            if greenlet.dead:
                self.spider.fetcher_pool.discard(greenlet)
        for i in xrange(min(self.spider.fetcher_queue.qsize(),self.spider.fetcher_pool.free_count())):
            fetcher = Fetcher(self.spider)
            self.spider.fetcher_pool.start(fetcher)

    def check_url_usable(self, link, refer=None):
        '''
        检查URL是否符合可用规则
        '''
        # if link in self.spider.fetcher_cache or link.rstrip('?').rstrip('#') in self.spider.fetcher_cache:
        if link.rstrip('?').rstrip('#').rstrip('/') in self.spider.fetcher_cache:
            return False

        if not link.startswith("http"):
            return False

        if self.spider.same_origin:
            if not self._check_same_origin(link):
                # print 3333333, link
                try:
                    spider_url = ScanSpiderUrlOther(url=link, task_id=self.spider.scan_task_id, refer=refer)
                    # session = DBSession()
                    db.session.add(spider_url)
                    db.session.commit()
                    # session.close()
                except Exception, e:
                    pass
                return False

        link_ext = os.path.splitext(urlparse.urlsplit(link).path)[-1][1:]
        if link_ext.lower() in self.spider.ignore_ext:
            return False

        return True

    def _check_same_origin(self,current_url):
        '''
        检查两个URL是否同源
        '''
        current_url = to_unicode(current_url)
        url_part = urlparse.urlparse(current_url)
        url_origin = (url_part.scheme,url_part.netloc)
        return url_origin == self.spider.origin


def to_unicode(data, charset=None):
    '''
    将输入的字符串转化为unicode对象
    '''
    unicode_data = ''
    if isinstance(data,str):
        if not charset:
            try:
                charset = chardet.detect(data).get('encoding')
            except Exception,e:
                pass
        if charset:
            unicode_data = data.decode(charset,'ignore')
        else:
            unicode_data = data
    else:
        unicode_data = data
    return unicode_data