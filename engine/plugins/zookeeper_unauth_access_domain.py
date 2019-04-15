#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    result = []
    try:

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
        port = 2181
        s.connect((ip, port))
        flag = "envi"
        # envi
        # dump
        # reqs
        # ruok
        # stat
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'Environment' in data:
            new_url = "%s:%s" % (ip, port)

            detail = "Zookeeper未授权访问"
            request = new_url
            result.append(getRecord(ob, new_url, ob['level'], detail, request, data))

    except Exception, e:
        logger.error("File:zookeeper_unauth_access_domain.py, run_domain function :%s" % (str(e)))

    return result



