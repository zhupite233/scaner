#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import MySQLdb.cursors
from engine.engineConfig import *
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urlparse import urlparse
from bs4 import BeautifulSoup


def find_friend_links(content):
    friend_link_list = []
    soup = BeautifulSoup(content, 'lxml')
    friends = soup.find(text=re.compile(u'.*?(友情链接|合作伙伴).*?'))
    if not friends:
        return []
    i = 0
    while not friends.find_all('a') and i < 4:
        try:
            friends = friends.parent
        except:
            pass
        i += 1
    for friend in friends.find_all('a'):
        friend_link = friend.get('href')
        if friend_link:
            net_loc = urlparse(friend_link).netloc
            if net_loc and not re.match('^(\d{1,3}\.){3}\d{1,3}(:\d{1,6})?$', net_loc):  # ip地址不是友情链接
                friend_link_list.append(net_loc)
    return friend_link_list


def run_domain(http, ob):
    '''
    黑链暗链检测插件
    '''
    result = []
    try:
        scheme = ob.get('scheme')
        domain = ob.get('domain')
        path = ob.get('path')
        res, content = http.request('%s://%s%s' % (scheme, domain, path))
        friend_link_list = find_friend_links(content)
        friend_link_set = set(friend_link_list)

        task_id = ob.get('taskId')
        # type = 1 表示域名与当前扫描网站不符
        sql = "SELECT spider_url_other.url FROM spider_url_other WHERE task_id=%s AND TYPE=%s" % (task_id, 1)
        db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass=MySQLdb.cursors.DictCursor)
        cursor = db.cursor()
        cursor.execute(sql)
        other_url_list = cursor.fetchall()
        if other_url_list:
            detail = '检测到外站链接，如果不是友情链接或其他已知来源，则可能是暗链黑链等恶意链接'
            for other_url_dict in other_url_list:
                other_url = other_url_dict.get('url')
                other_domain = urlparse(other_url).netloc
                other_domain = other_domain.split(':')[0]
                if other_domain.split('.', 1)[1] == domain.split('.', 1)[1]:  # 子域名
                    continue
                if other_domain not in friend_link_set:  # 不在友情链接内
                    result.append(getRecord(ob, other_url, ob['level'], detail, request=other_url, response=''))
    except Exception, e:
        logger.error("File:TrojanCheckScript_yd.py, run_domain function :%s" % (str(e)))
    return result

    # result = []
    # domain = ob['domain']
    # try:
    #     task_id = ob['taskId']
    #     # other_urls = db.session.query(SpiderUrlOther.url).filter(SpiderUrlOther.task_id == task_id, SpiderUrlOther.type == 1).all()
    #     sql = "SELECT spider_url_other.url FROM spider_url_other WHERE task_id=%s AND TYPE=%s" % (task_id, 1)
    #     db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass=MySQLdb.cursors.DictCursor)
    #     cursor = db.cursor()
    #     cursor.execute(sql)
    #     other_url_list = cursor.fetchmany()
    #     if other_url_list:
    #         for other_url_dict in other_url_list:
    #             other_url = other_url_dict.get('url')
    #             other_domain = urlparse(other_url).netloc
    #             other_domain = other_domain.split(':')[0]
    #             if domain.find(other_domain) == -1 and other_domain.find(domain) == -1 and domain.find(other_domain.split('.', 1)[1]) == -1:
    #                 detail = '检测到外站链接，如果不是友情链接或其他已知来源，则可能是暗链黑链木马等恶意链接'
    #                 # res, content = http.request(other_url.url,"HEAD")
    #                 # request = getRequest(other_url)
    #                 result.append(getRecord(ob, other_url, ob['level'], detail, request=other_url, response=''))
    # except Exception, e:
    #     logger.error("File:TrojanCheckScript_yd.py, run_domain function :%s" % (str(e)))
    #
    # return result
