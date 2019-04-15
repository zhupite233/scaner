#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import base64
import time
import json
import requests
from random import choice
import string
from copy import deepcopy
from urllib import urlencode
from engine.engine_utils.inj_functions import query_inject, body_inject, header_inject
from httplib2 import Http
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
        pattern = r'(/WebResource.axd)'
        scheme = ob['scheme']

        result = []
        if not re.search(pattern, path, re.I):
            pass
        else:
            error_i = 0
            bglen = 0
            url_parse = urlparse(path)
            netloc = url_parse.netloc
            source_ip = ob.get('source_ip')
            if source_ip:
                netloc = source_ip
            for k in range(0, 255):
                IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + chr(k)
                bgstr = 'A' * 21 + '1'
                enstr = base64.b64encode(IV).replace('=', '').replace('/', '-').replace('+', '-')
                exp_url = "%s://%s/WebResource.axd?d=%s" % (scheme, netloc, enstr + bgstr)
                try:
                    res, content = http.request(exp_url, 'GET', headers=header)
                    import urllib2
                except urllib2.URLError, e:
                    error_i += 1
                    if error_i >= 3:
                        break
                if int(res['status']) == 200 or int(res['status']) == 500:
                    if k == 0:
                        bgcode = int(res['status'])
                        bglen = len(content)
                    else:
                        necode = int(res['status'])
                        if (bgcode != necode) or (bglen != len(content)):
                            detail = "MS10-070 ASP.NET Padding Oracle信息泄露漏洞"
                            response = getResponse(res)
                            request = getRequest(exp_url, 'GET', headers=header, domain=ob['domain'])
                            result.append(getRecord(ob, exp_url, ob['level'], detail, request, response))
        return result

    except Exception, e:
        logger.error("File:MS10_070_url.py.py, run_url function :%s" % (str(e)))
        return result