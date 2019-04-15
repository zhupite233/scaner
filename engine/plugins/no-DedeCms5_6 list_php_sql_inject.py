#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2011-5200
    CNNVD-201112-515
    DeDeCMS是最强大的中文开源CMS网站管理项目，使用PHP+MySQL架构。
    DeDeCMS 5.6版本中存在多个SQL注入漏洞。远程攻击者可利用这些漏洞通过传送到(1)list.php(2)members.php或(3)book.php脚本中的id参数，执行任意SQL命令。

    CVSS分值:	7.5	[严重(HIGH)]
    CWE-89	[SQL命令中使用的特殊元素转义处理不恰当（SQL注入）]
    '''
    result = []

    return result

