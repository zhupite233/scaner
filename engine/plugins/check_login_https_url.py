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
        pattern = r'(login|sigin)'

        result = []
        if not re.search(pattern, path, re.I):
            pass
        elif re.search(r'(.js|.css)', path, re.I):
            pass
        else:
            url_parse = urlparse(path)
            scheme = url_parse.scheme
            if 'HTTPS' != scheme.upper():
                res = {'status': '200','content-location': path, 'pragma': 'no-cache', 'cache-control':
                    'no-cache, must-revalidate', "content-type": 'text/html;charset=utf-8'}
                response = getResponse(res)
                request = getRequest(path, domain=ob['domain'])

                detail = "用户凭证没有以HTTPS或者加密形式发送"
                result.append(getRecord(ob, path, ob['level'], detail, request, response))

        return result

    except Exception, e:
        logger.error("File:check_login_https_url.py, run_url function :%s" % (str(e)))
        return result

