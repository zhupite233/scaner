# coding: utf-8
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urllib import urlencode
from engine.engine_utils.rule_result_judge import page_similar

'''
CVE-2011-0644
CNNVD-201101-364
phpCMS是一款基于PHP的内容服务程序。
PHPCMS 2008 V2版本中的include/admin/model_field.class.php中存在SQL注入漏洞。远程攻击者可以借助向flash_upload.php传递的modelid参数执行任意SQL命令。
CVSS分值:	7.5	[严重(HIGH)]
CWE-89	[SQL命令中使用的特殊元素转义处理不恰当（SQL注入）]
'''

def run_domain(http,ob):
    result = []
    return result