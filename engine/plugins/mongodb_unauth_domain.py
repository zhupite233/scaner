#!/usr/bin/python
# -*- coding: utf-8 -*-
import binascii

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    result = []
    try:

        # db_flag = ob.get('db')
        # full_db = ['mysql', 'oracle', 'sqlserver', 'mongodb']
        # del full_db['mongodb']
        # if db_flag and db_flag not in full_db:
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

        s.connect((ip, 27017))
        data = binascii.a2b_hex(
            "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
        s.send(data)
        result = s.recv(1024)
        s.close()
        if "ismaster" in result:
            getlog_data = binascii.a2b_hex(
                "480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
            s.send(getlog_data)
            result = s.recv(1024)
            if "totalLinesWritten" in result:
                new_url = "%s:%s" % (ip, 27017)
                detail = "MongoDB未授权访问"
                request = new_url
                result.append(getRecord(ob, new_url, ob['level'], detail, request, result))

    except Exception, e:
        logger.error("File:mongodb_unauth_domain.py, run_domain function :%s" % (str(e)))

    return result



