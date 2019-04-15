# --*-- coding: utf-8 --*--
import uuid
from time import sleep

import gevent
import requests
from gevent import Greenlet
from gevent import queue
from gevent import monkey

from common.spider_models import ScanSpiderUrlOther
# from common.sql_orm import DBSession
from ext import db


monkey.patch_all()
def monkey_patch():
    '''
    requests库中文乱码补丁
    '''
    prop = requests.models.Response.content
    def content(self):
        _content = prop.fget(self)
        if self.encoding == 'ISO-8859-1':
            encodings = requests.utils.get_encodings_from_content(_content)
            if encodings:
                self.encoding = encodings[0]
                _content = _content.decode(self.encoding, 'replace').encode('utf8', 'replace')
            # 当页面只有js时找不到coding mcj
            # else:
                # self.encoding = self.apparent_encoding
            # _content = _content.decode(self.encoding, 'replace').encode('utf8', 'replace')
            self._content = _content
        return _content
    requests.models.Response.content = property(content)

monkey_patch()

class Fetcher(Greenlet):
    """抓取器(下载器)类"""
    def __init__(self,spider):
        Greenlet.__init__(self)
        self.fetcher_id = str(uuid.uuid1())[:8]
        self.TOO_LONG = 1048576 # 1M
        self.spider = spider
        self.fetcher_cache = self.spider.fetcher_cache
        self.crawler_cache = self.spider.crawler_cache
        self.fetcher_queue = self.spider.fetcher_queue
        self.crawler_queue = self.spider.crawler_queue
        self.logger = self.spider.logger

    def _fetcher(self):
        '''
        抓取器主函数
        '''
        self.logger.info("fetcher %s starting...." % (self.fetcher_id,))
        while not self.spider.stopped.isSet():
            # sleep(5)
            # print 333333333333
            try:
                url_data = self.fetcher_queue.get(block=False)
            except queue.Empty,e:
                if self.spider.crawler_stopped.isSet() and self.fetcher_queue.unfinished_tasks == 0:
                    self.spider.stop()
                elif self.crawler_queue.unfinished_tasks == 0 and self.fetcher_queue.unfinished_tasks == 0:
                    self.spider.stop()
                else:
                    gevent.sleep()
            else:
                if not url_data.html:
                    try:
                        if url_data not in set(self.crawler_cache):
                            html = ''
                            with gevent.Timeout(self.spider.internal_timeout,False) as timeout:
                                html = self._open(url_data.url)
                            if not html.strip():
                                self.spider.fetcher_queue.task_done()
                                continue
                            self.logger.info("fetcher %s accept %s" % (self.fetcher_id,url_data))
                            url_data.html = html
                            if not self.spider.crawler_stopped.isSet():
                                self.crawler_queue.put(url_data,block=True)
                                # use for testing Fetcher single
                                # url_data.html = ''
                                # self.fetcher_queue.put(url_data)
                            self.crawler_cache.insert(url_data)
                    except Exception,e:
                        import traceback
                        traceback.print_exc()
                self.spider.fetcher_queue.task_done()

    def _run(self):
        self._fetcher()


    def _open(self, url):
        '''
        获取HTML内容
        '''
        human_headers = {
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36',
            'Accept-Encoding':'gzip,deflate,sdch'
        }
        if self.spider.custom_headers:
            human_headers.update(self.spider.custom_headers)
        try:

            r = requests.get(url, headers=human_headers, stream=True, verify=False)

        except Exception, e:
            try:
                spider_url = ScanSpiderUrlOther(url=url, task_id=self.spider.scan_task_id, type=0)
                # session = DBSession()
                db.session.add(spider_url)
                db.session.commit()
                # session.close()
            except:
                pass
            # self.logger.warn("%s %s" % (url_data.url,str(e)))
            return u''
        else:
            if r.status_code == 404:
                try:
                    spider_url = ScanSpiderUrlOther(url=url, task_id=self.spider.scan_task_id, type=0)
                    # session = DBSession()
                    db.session.add(spider_url)
                    db.session.commit()
                    # session.close()
                except:
                    pass
            if r.headers.get('content-type','').find('text/html') < 0:
                r.close()
                return u''
            # if int(r.headers.get('content-length',self.TOO_LONG)) > self.TOO_LONG:
            #     r.close()
            #     return u''
            try:
                html = r.content
                # print html
                html = html.decode('utf-8','ignore')
            except Exception,e:
                print e
                # self.logger.warn("%s %s" % (url_data.url,str(e)))
            finally:
                r.close()
                if vars().get('html'):
                    # print html
                    return html
                else:
                    return u''

