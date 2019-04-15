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
        path = ob['path']
        header = {'Host': domain}
        http = HttpRequest({'timeout': 6, 'follow_redirects': False})

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
            domain,
            domain.split(".")[1],
            domain.split(".", 1)[0],
            domain.split(".", 1)[1],
            "1",
            "2017",
            "acl",
            "admin",
            "asp",
            "aspx",
            "back",
            "backup",
            "bbs",
            "beifen",
            "ceshi",
            "code",
            "copy",
            "databackup",
            "database",
            "db",
            "do",
            "error",
            "ftp",
            "help",
            "htdoc",
            "htdocs",
            "index",
            "info.php",
            "jsp",
            "manage",
            "leapftp",
            "log",
            "php",
            "phpinfo.php",
            "php_info.php",
            "rar",
            "root",
            "sem",
            "sql",
            "sqldump",
            "src",
            "test",
            "tool",
            "tools",
            "upload",
            "web",
            "WEB-INF",
            "wse",
            "www",
            "wwwroot",
            "xml"
        ]

        postfix_list = [
            ".zip",
            ".gzip",
            ".rar",
            ".tar",
            ".tar.gz",
            # ".tgz",
            # ".7z"
        ]
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip

        dir_list = ob.get('site_dir')
        if not dir_list:
            dir_list = ['/']
        dir_list = dir_list[:10]
        for inj_dir in dir_list:
            if not inj_dir or inj_dir[-1] != '/':
                inj_dir += '/'
            for inj_path in inj_path_list:
                for postfix in postfix_list:
                    sleep(0.05)
                    new_url = "%s://%s%s%s%s" % (scheme, domain, inj_dir, inj_path, postfix)
                    try:
                        res, content = http.request(new_url, 'HEAD', headers=header)
                        if res and res.get('status') == '200':
                            res2, content2 = http.request(new_url, 'GET', headers=header)
                            if res2 and res2.get('status') == '200' and content2:
                                if page_similar(res2.get('status'), content2, ob.get('404_page')):
                                    continue
                                if page_similar(res2.get('status'), content2, ob.get('waf_page')):  # 敏感文件扫描暂不用waf拦截页面判断
                                    continue
                                detail = "检测到可能含有敏感信息的文件"
                                request = getRequest(new_url, domain=ob['domain'])
                                response = getResponse(res2, content2)
                                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    except Exception, e:
                        logger.error("File:BakFileCheckScript_yd.py, run_domain function :%s" % (str(e)))

    except Exception, e:
        logger.error("File:CompressFileCheckScript_yd.py, run_domain function :%s" % (str(e)))

    return result



