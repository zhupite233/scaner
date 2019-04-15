#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2014-4037
    CNNVD-201406-085
    CKSource FCKEditor‘spellchecker.php’跨站脚本漏洞
    CKSource FCKeditor（现称CKEditor）是波兰CKSource公司的一套开源的、基于网页的文字编辑器。该编辑器具有轻量化、易于安装等特点。
    CKSource FCKeditor 2.6.10及之前版本的editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php脚本中存在跨站脚本漏洞。远程攻击者可借助‘textinputs[]’参数中的数组key利用该漏洞注入任意Web脚本或HTML。

    CVSS分值:	4.3	[中等(MEDIUM)]

    CWE-79	[在Web页面生成时对输入的转义处理不恰当（跨站脚本）]
    '''
    result = []

    return result

