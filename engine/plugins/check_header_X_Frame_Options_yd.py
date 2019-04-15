#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        result_list = []
        new_header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/" % (scheme,domain)
        res, content = http.request(new_url, "HEAD", headers=new_header)
        if not res.has_key('x-frame-options') and not res.has_key('frame-options'):
            detail = "响应头未检测到X-Frame-Options或Frame-Options字段 "
            request = getRequest(new_url, domain=ob['domain'])
            response = getResponse(res)
            result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response, output=""))
        return result_list
    except Exception,e:
        logger.error("File:check_header_X_Frame_Options_yd.py, run_domain function :%s" % (str(e)))
        return []

