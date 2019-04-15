#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2009-2270
    CNNVD-200907-008
    Dedecms 5.3版本下的member/uploads_edit.php中的未限制文件上传漏洞允许远程攻击者通过上传一个有两个扩展的文件名的文件，
    然后借助未知向量访问该文件而执行任意代码。这已经通过带.jpg.php的文件名所证实。
    CVSS分值:	6.8	[中等(MEDIUM)]
    CWE-94	[对生成代码的控制不恰当（代码注入）]
    '''
    result = []

    return result

