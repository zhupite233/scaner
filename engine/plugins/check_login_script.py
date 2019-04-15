#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
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
        url = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'(login|sigin)'
        p_para = r'("type":\s*"password")'
        result = []
        if not (re.search(pattern, url, re.I) or re.search(p_para, json.dumps(params), re.I)):
            pass
        elif re.search(r'(.js|.css)', url, re.I):
            pass
        else:
            url_parse = urlparse(url)
            scheme = url_parse.scheme
            netloc = url_parse.netloc
            path = url_parse.path
            query = url_parse.query
            source_ip = ob.get('source_ip')
            if source_ip:
                netloc = source_ip
            if query:
                new_url = "%s://%s%s?%s" % (scheme, netloc, path, query)
            else:
                new_url = "%s://%s%s" % (scheme, netloc, path)

            res, content = http.request(new_url, 'GET', headers=header)
            #pattern = r'.+(<input.*?(type="password"|type="text").*?){3}'
            #se = re.search(pattern, content, re.S | re.I)
            pattern1 = r'(<input.*?(type="text"))'
            pattern2 = r'(<input.*?(type="password"))'

            p1 = re.compile(pattern1)
            p2 = re.compile(pattern2)

            text_count = len(p1.findall(content))
            pwd_count = len(p2.findall(content))
            if pwd_count == 0:
                pass
            else:
                if text_count/pwd_count >= 2:
                    pass
                else:
                    response = getResponse(res, content)
                    request = getRequest(new_url, domain=ob['domain'])
                    detail = "登录页面未设置验证码校验"
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

        return result

    except Exception, e:
        logger.error("File:check_login_script.py, run_url function :%s" % (str(e)))
        return result

