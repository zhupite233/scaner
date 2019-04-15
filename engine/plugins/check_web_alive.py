#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
'''
此插件用于检测网站存活性。但实际不参与检测，仅仅将网站当前状态追加到扫描结果，以便生成报告时可以看到相关记录
实际检测网站存活性的代码在ScanSite.py中实现
'''


def run_domain(http,ob):
    result = []
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        cookie = ob['cookie']
        header = {'Host': domain, 'Cookie': cookie}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s" % (scheme, domain)
        res, content = None, None
        try:
            res, content = http.request(new_url, headers=header)
        except Exception, e:
            content = str(e)
        detail = '网站无法访问'
        request = getRequest(new_url, domain=ob['domain'])
        response = getResponse(res, content)
        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:check_web_alive.py, run_domain function :%s" % (str(e)))

    return result