#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2010-1097
    CNNVD-201003-342
    DedeCms是免费的PHP网站内容管理系统。
    DeDeCMS 5.5 GBK的脚本include/userlogin.class.php存在授权问题漏洞。远程攻击者可以借助_SESSION[dede_admin_id]参数的值设置为1，绕过认证，获取管理员访问权限。
    CWE (弱点类目) CWE-287	[认证机制不恰当]
    '''
    result = []

    return result

