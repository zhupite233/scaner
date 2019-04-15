#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.engine_utils.rule_result_judge import page_similar
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    result = []
    try:
        os = ob.get('os')
        if os == 'windows':
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        path = ob['path']
        http = HttpRequest({'timeout': 10, 'follow_redirects': False})
        # 格式化path
        if not path:
            path = '/'  # path 为空补全/
        elif path[-1] == '/':
            pass  # path以/结尾不处理，包括path == '/'的情况
        else:  # path 不以/结尾
            tail = path.split('/')[-1]
            if re.search('\.', tail):  # path 最后一截包含. 比如/test/test.php
                n = len(tail)
                path = path[0:-n]  # 去掉最后包含.的一截
            else:
                path += '/'  # path最后一截不包含. 在末尾补全/

        inj_path_list = [
            ".bash_history",
            "root/.bash_history",
            "home/test/.bash_history",
            "web/.bash_history",
            "../../../../../../../../../../../../.bash_history",
            "../../../../../../../../../../../../root/.bash_history",
            "../../../../../../../../../../../../home/test/.bash_history",
            "../../../../../../../../../../../../home/web/.bash_history"

        ]
        new_header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        for inj_path in inj_path_list:
            new_url = "%s://%s%s%s" % (scheme, domain, path, inj_path)
            try:
                res, content = http.request(new_url, 'HEAD', redirections=5, headers=new_header)
                if res and res.get('status') == '200':
                    res2, content2 = http.request(new_url, 'GET', redirections=5, headers=new_header)

                    if res2 and res2.get('status') == '200' and content2:
                        if page_similar(res.get('status'), content2, ob.get('404_page')):
                            continue
                        if page_similar(res.get('status'), content2, ob.get('waf_page')):
                            continue
                        detail = "检测到可能含有敏感信息的文件"
                        request = getRequest(new_url, new_header, domain=ob['domain'])
                        response = getResponse(res2, content2)
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
            except:
                pass
    except Exception, e:
        logger.error("File:BashhistoryDisclosureScript_yd.py, run_domain function :%s" % (str(e)))

    return result



