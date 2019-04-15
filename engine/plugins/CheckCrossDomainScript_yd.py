#!/usr/bin/python
# -*- coding: utf-8 -*-
import re

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    result = []
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/%s" % (scheme, domain, "crossdomain.xml")
        res, content = http.request(new_url, headers=header)
        if res and res.get('status') == 200 and content:
            if re.search(r'(?:"\*"|"all"|"false")', content, re.I):  #domain="*" secure="false" permitted-cross-domain-policies="all" 是不安全的配置
                detail = '检测到不安全的crossdomain.xml配置'
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res, content, '(?:"\*"|"all"|"false")')
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:CheckCrossDomainScript_yd.py, run_domain function :%s" % (str(e)))

    return result

