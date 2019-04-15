#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2012-4000
    CNNVD-201206-446
    FCKEditor ‘spellchecker.php’跨站脚本漏洞
    FCKeditor是一款开放源码的HTML文本编辑器。
    FCKEditor中存在跨站脚本漏洞，该漏洞源于对用户提供的输入未经验证。攻击者可利用该漏洞在受影响站点上下文中不知情用户浏览器中执行任意脚本代码，窃取基于cookie的认证证书并发起其他攻击。FCKEditor 2.6.7版本中存在漏洞，其他版本也可能受到影响。

    CVSS分值:	4.3	[中等(MEDIUM)]

    CWE-79	[在Web页面生成时对输入的转义处理不恰当（跨站脚本）]
    '''
    result = []

    return result

