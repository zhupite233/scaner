#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2009-4875
    CNNVD-201005-362
    FCKeditor.Java 拒绝服务漏洞
    FCKeditor.Java 2.4存在拒绝服务攻击漏洞，远程攻击者可以通过畸形的包含"ctrl"字符的请求参数导致拒绝服务攻击(死循环)。
    CVSS分值:	5	[中等(MEDIUM)]
    CWE-399	[资源管理错误]
    '''
    result = []

    return result

