#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
from httplib2 import Http
#from engine.logger import scanLogger as logger
from engine.engine_utils.common import getResponse, getRequest, getRecord
from engine.engine_utils.params import post_query2dict, dict2query
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
        method = item['method']
        timeout = ob.get('webTimeout')
        http = Http(timeout=timeout)
        url_parse = urlparse(path)
        netloc = url_parse.netloc
        source_ip = ob.get('source_ip')
        if source_ip:
            netloc = source_ip
        query_dict = post_query2dict(path)
        result = []
        for key in query_dict.keys():
            url2 = getDomain(query_dict[key])

            print url2
            if url2:
                query_dict[key] = 'http://openresty.org/cn/'
                print(query_dict[key])
        new_query = dict2query(query_dict)
        new_url = "%s://%s%s?%s" % (url_parse.scheme, netloc, url_parse.path, new_query)
        # print new_url
        res, content = http.request(new_url, 'GET', headers=header)

        c = re.search('''OpenResty 是一个基于 NGINX 和 LuaJIT 的 Web 平台。''', content)
        if c:
            response = getResponse(res, content, 'OpenResty 是一个基于 NGINX 和 LuaJIT 的 Web 平台。')
            request = getRequest(path, 'POST', headers=header, domain=ob['domain'])
            detail = "存在任意网址跳转漏洞"
            result.append(getRecord(ob, path, ob['level'], detail, request, response))
            return result

    except Exception, e:
        logger.error("File:PageredirectsScript_yd.py, run_url function :%s" % (str(e)))
        return result

def getDomain(s):
    #res = s
    domainS = ["\.org","\.com", "\.cn", "\.com\.cn", "\.gov", "\.net", "\.edu\.cn", "\.net\.cn", "\.org\.cn", "\.co\.jp", "\.gov\.cn","\.co\.uk",\
               "ac\.cn", "\.edu", "\.tv","\.info", "\.ac", "\.ag", "\.am", "\.at", "\.be", "\.biz", "\.bz","\.cc", "\.de", "\.es", \
               "\.eu", "\.fm", "\.gs", "\.hk", "\.in", "\.info", "\.io", "\.it", "\.jp", "\.la","\.md", "\.ms", "\.name", "\.nl", \
               "\.nu",  "\.pl", "\.ru", "\.sc", "\.se", "\.sg", "\.sh", "\.tc","\.tk", "\.tv", "\.tw", "\.us", "\.co","\.uk",\
               "\.vc", "\.vg", "\.ws", "\.il", "\.li", "\.nz"]
    for h in domainS:
        pa = r'[0-9a-zA-Z_\-]+%s' % h
        regex = re.compile(pa)
        m = regex.findall(s)
        if len(m) > 0:
            return m[0]
        else:
            pass
    return ''
