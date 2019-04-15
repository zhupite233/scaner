#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar
from time import sleep


def run_domain(http,ob):
    result = []
    try:

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}

        # path = ob['path']
        http = HttpRequest({'timeout': 10, 'follow_redirects': False})
        # 格式化path
        # if not path:
        #     path = '/'  # path 为空补全/
        # elif path[-1] == '/':
        #     pass  # path以/结尾不处理，包括path == '/'的情况
        # else:  # path 不以/结尾
        #     tail = path.split('/')[-1]
        #     if re.search('\.', tail):  # path 最后一截包含. 比如/test/test.php
        #         n = len(tail)
        #         path = path[0:-n]  # 去掉最后包含.的一截
        #     else:
        #         path += '/'  # path最后一截不包含. 在末尾补全/

        inj_path_list = [
            domain + ".conf",
            domain.split(".")[1] + ".conf",
            domain.split(".", 1)[0] + ".conf",
            domain.split(".", 1)[1] + ".conf",

            "common.inc",
            "conn.inc",
            "debug.inc"
            ".htaccess",

            ".git/config",
            ".svn/entries",

            "WEB-INF/classes/applicationContext.xml",
            "WEB-INF/classes/applicationContext-jms.xml",
            "WEB-INF/struts-config.xml",
            "_vti_pvt/service.cnf",

        ]

        php_list = [
            "p.php",
            "phpinfo.php",
            "php_info.php",
            "user.php",
            "connect.php",
            "config.php.swp"
        ]

        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        frame = ob.get('frame')
        if frame and frame in ['jsp', 'asp', 'aspx']:
            pass
        else:
            inj_path_list.extend(php_list)

        dir_list = ob.get('site_dir')
        if not dir_list:
            dir_list = ['/']
        dir_list = dir_list[:10]
        for inj_dir in dir_list:
            if not inj_dir or inj_dir[-1] != '/':
                inj_dir += '/'
            for inj_path in inj_path_list:
                sleep(0.05)
                new_url = "%s://%s%s%s" % (scheme, domain, inj_dir, inj_path)
                try:
                    res, content = http.request(new_url, 'HEAD', headers=header)
                    if res and res.get('status') == '200':
                        res2, content2 = http.request(new_url, 'GET', headers=header)
                        if res2 and res2.get('status') == '200' and content2:
                            detail = "检测到可能含有敏感信息的文件"
                            if re.search('.*?php|jsp|asp|aspx$', inj_path, re.I):
                                if page_similar(res2.get('status'), content2, ob.get('app_404_page')):
                                    continue
                            else:
                                if page_similar(res2.get('status'), content2, ob.get('404_page')):
                                    continue
                            if page_similar(res2.get('status'), content2, ob.get('waf_page')):
                                continue
                            request = getRequest(new_url, domain=ob['domain'])
                            response = getResponse(res2, content2)
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                except Exception, e:
                    logger.error("File:ConfigFileCheckScript_yd.py, run_domain function :%s" % (str(e)))

    except Exception, e:
        logger.error("File:ConfigFileCheckScript_yd.py, run_domain function :%s" % (str(e)))

    return result



