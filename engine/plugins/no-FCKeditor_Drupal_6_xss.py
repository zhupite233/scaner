#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2012-2066
    CNNVD-201209-030
    Drupal FCKeditor/CKEditor模块 跨站脚本漏洞
    Drupal是一款开源CMS，可以作为各种网站的内容管理平台。
    Drupal中的FCKeditor模块6.x-2.3之前的6.x-2.x版本和CKEditor模块6.x-1.9之前的6.x-1.x版本、7.x-1.7之前的7.x-1.x版本中存在跨站脚本(XSS)漏洞。远程认证用户可利用该漏洞通过未明向量注入任意web脚本或HTML。

    CVSS分值:	4.3	[中等(MEDIUM)]
    CWE-79	[在Web页面生成时对输入的转义处理不恰当（跨站脚本）]
    '''
    result = []

    return result

