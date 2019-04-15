#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    result = []
    try:

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}

        http = HttpRequest({'timeout': 10, 'follow_redirects': False})
        source_ip = ob.get('source_ip')
        site_dirs = ob['site_dirs']
        if not site_dirs:
            site_dirs = ['/']
        site_dirs = site_dirs[:10]
        if source_ip:
            domain = source_ip

        # # 格式化path
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
            domain,
            domain.split(".")[1],
            domain.split(".", 1)[0],
            domain.split(".", 1)[1],
            "shell",
            "webshell",
            "hack",
            "spy",
            "phpspy",
            "eval",
            "eval1",
            "eval(1)",
            "eval1(1)",
            "exehack",
            "angle",
            "browser",
            "JFolder",
            "a",
            "s",
            "test",
            "do",
            "1",
            "1(1)",
            "123",
            "12",
            "2016",
            "2017",
            "one"
        ]

        postfix_list = []
        frame = ob.get('siteType')
        if not frame or frame == 'unknown':
            postfix_list = [".php", ".asp", ".jsp", ".apsx"]
        else:
            if "php" == frame:
                postfix_list.append(".php")
            elif "asp" == frame:
                postfix_list.append(".asp")
            elif "jsp" == frame:
                postfix_list.append(".jsp")
            elif "aspx" == frame:
                postfix_list.append(".aspx")

        for inj_path in inj_path_list:
            for postfix in postfix_list:
                for path in site_dirs:
                    if path[-1] != '/':
                        path += '/'
                    new_url = "%s://%s%s%s%s" % (scheme, domain, path, inj_path, postfix)
                    try:
                        res, content = http.request(new_url, 'HEAD', redirections=5, headers=header)
                        if res and res.get('status') == '200':
                            res, content = http.request(new_url, 'GET', redirections=5, headers=header)
                            if res and res.get('status') == '200' and content:
                                if page_similar(res.get('status'), content, ob.get('app_404_page')):
                                    continue
                                if page_similar(res.get('status'), content, ob.get('waf_page')):
                                    continue
                                detail = "检测到疑似木马文件"
                                request = getRequest(new_url, domain=ob['domain'])
                                response = getResponse(res, content)
                                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    except:
                        pass

    except Exception, e:
        logger.error("File:WebShellCheckScript_yd.py, run_domain function :%s" % (str(e)))

    return result



