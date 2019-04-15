#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    '''
    Rejetto HTTP File Server‘ParserLib.pas’代码注入漏洞
    CVE-2014-6287
    CNNVD-201409-986
    此插件仅通过响应header的server字段判断是否存在低版本HFS
    HFS(HTTP File Server)是一款专为个人用户所设计的HTTP文件服务器，它提供虚拟档案系统，支持新增、移除虚拟档案资料夹等。
    Rejetto HTTP File Server 2.3c及之前版本中的parserLib.pas文件中的‘findMacroMarker’函数中存在安全漏洞，该漏洞源于parserLib.pas文件没有正确处理空字节。远程攻击者可借助搜索操作中的‘%00’序列利用该漏洞执行任意程序。

    CVSS分值:	7.5	[严重(HIGH)]
    CWE-94	[对生成代码的控制不恰当（代码注入）]
    '''
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        result_list = []
        new_header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/" % (scheme, domain)
        res, content = http.request(new_url, "HEAD", headers=new_header)
        server = res.get('server')
        if server and re.search('HFS\s2\.3', server, re.I):
            detail = "HFS 2.3X版本存在远程命令执行漏洞: %s" % server
            request = getRequest(new_url, new_header, domain=ob['domain'])
            response = getResponse(res)
            result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response, output=""))
        return result_list
    except Exception,e:
        logger.error("File:hfs_version_check.py, run_domain function :%s" % (str(e)))
        return []
