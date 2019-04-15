#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob,inj_dir=""):
    '''
    CVE-2009-2265
    CNNVD-200907-058
    FCKeditor是一款开放源码的HTML文本编辑器。
    FCKeditor2.6.4.1及更早版本的editor/filemanager/browser/default/connectors/php/connector.php模块中存在文件上传限制漏洞,由于166-170行仅检查了MIME类型的上传请求，因此远程攻击者可以通过pht扩展名向Web服务器上传恶意脚本。

    CVSS分值:	7.5	[严重(HIGH)]
    '''
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
            "/FCKeditor/_samples/default.html",
            "/FCKeditor/editor/filemanager/browser/default/browser.html",
            "/FCKeditor/editor/filemanager/browser/default/connectors/test.html"
            "/FCKeditor/editor/filemanager/upload/test.html",
            "/FCKeditor/editor/filemanager/connectors/test.html",
            "/FCKeditor/editor/filemanager/connectors/uploadtest.html",
            #
            "/fckeditor/editor/filemanager/browser/default/browser.html",
            "/fckeditor/editor/filemanager/browser/default/connectors/test.html",
            "/fckeditor/editor/filemanager/upload/test.html",
            "/fckeditor/editor/filemanager/connectors/test.html",
            "/fckeditor/editor/filemanager/connectors/uploadtest.html",
        ]

        inj_path_list_jsp = [
            "/FCKeditor/editor/filemanager/connectors/jsp/connector.jsp",
            "/fckeditor/editor/filemanager/connectors/jsp/connector.jsp"
        ]
        inj_path_list_asp = [
            "/FCKeditor/editor/filemanager/connectors/asp/connector.asp",
            "/fckeditor/editor/filemanager/connectors/asp/connector.asp"
        ]
        inj_path_list_php = [
            "/FCKeditor/editor/filemanager/connectors/php/connector.php",
            "/fckeditor/editor/filemanager/connectors/php/connector.php"
        ]
        inj_path_list_net = [
            "/FCKeditor/editor/filemanager/connectors/aspx/connector.aspx",
            "/fckeditor/editor/filemanager/connectors/aspx/connector.aspx"
        ]

        frame = ob.get('siteType')
        if frame:
            if frame == 'php':
                inj_path_list += inj_path_list_php
            elif frame == 'jsp':
                inj_path_list += inj_path_list_jsp
            elif frame == 'asp':
                inj_path_list += inj_path_list_asp
            elif frame == 'aspx':
                inj_path_list += inj_path_list_net
        else:
            inj_path_list += inj_path_list_jsp + inj_path_list_asp + inj_path_list_php + inj_path_list_net

        for inj_path in inj_path_list:
            url = "%s://%s/%s%s" % (scheme,domain,inj_dir,inj_path)
            res, content = http.request(url, 'GET', headers=header)
            if res and res.get('status') == '200':
                if page_similar(res.get('status'), content, ob.get('404_page')):
                    continue
                if page_similar(res.get('status'), content, ob.get('waf_page')):
                    continue
                detail = "检测到FCKeditor上传点"
                request = getRequest(url, domain=ob['domain'])
                response = getResponse(res,content)
                result.append(getRecord(ob,url,ob['level'],detail,request,response))

    except Exception,e:
        logger.error("File:FCKeditorUploadScript_yd.py, run_domain function :%s" % (str(e)))

    return result



