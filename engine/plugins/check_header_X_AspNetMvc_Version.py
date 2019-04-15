# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    result_list = []
    try:
        scheme = ob.get('scheme')
        domain = ob.get('domain')
        new_header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/" % (scheme, domain)
        res, content = http.request(new_url, "HEAD", headers=new_header)
        aspnet_version = res.get('x-aspnetmvc-version')
        if aspnet_version:
            detail = "响应头检测到X-AspNetMvc-Version字段，可能泄露敏感信息: %s" % aspnet_version
            request = getRequest(new_url, new_header, domain=ob['domain'])
            response = getResponse(res)
            result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response, output=""))
        return result_list
    except Exception,e:
        logger.error("File:check_header_X_AspNetMvc_Version_yd.py, run_domain function :%s" % (str(e)))
        return []