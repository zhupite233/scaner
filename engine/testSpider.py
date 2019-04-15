# -*- coding: utf-8 -*-
import json
import time

import MySQLdb
import MySQLdb.cursors

from engineConfig import SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, SCANER_SPIDER_DOWNLOAD_DIR


#从数据库中查询单条URL进行扫描
#row = getTaskById(1)
def getTaskById(taskid=None):
    '''根据任务ID获取任务数据
    '''
    taskid = int(taskid)
    sql = "select * from task where id=%d" % taskid
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    row = cursor.fetchone()
    db.close()
    return dict2obj(row)

def getSiteById(siteid=None):
    '''根据任务ID获取任务数据
    '''
    siteid = int(siteid)
    sql = "select * from sites where id=%d" % siteid
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    row = cursor.fetchone()
    db.close()
    return dict2obj(row)

def dict2obj(args):
    '''把字典递归转化为类
    '''
    class obj(object):
        def __init__(self, d):
            for a, b in d.items():
                if isinstance(b, (list, tuple)):
                    setattr(self, a, [obj(x) if isinstance(x, dict) else x for x in b])
                else:  
                    setattr(self, a, obj(b) if isinstance(b, dict) else b)
    return obj(args)

#获取任务数据
#taskid=341
#siteid = 750

taskid = 783
siteid = 1247
task = getTaskById(taskid)
site = getSiteById(siteid)

target = json.loads(task.target)
if target[0].has_key('cookie'):
    cookie =  target[0]['cookie']
else:
    cookie =  ''

#开启爬虫，当扫描指定的URL时，不需要爬虫
spiderCnf = {}
spiderCnf['taskId'] = task.id
spiderCnf['assetTaskId'] = task.asset_task_id
spiderCnf['siteId'] = siteid
spiderCnf['spiderUrlCount'] = task.spider_url_count
spiderCnf['webScanTime'] = task.web_scan_timeout
spiderCnf['policy'] = task.web_scan_policy
spiderCnf['scheme'] = site.scheme
spiderCnf['domain'] = site.domain
spiderCnf['path'] = site.path
spiderCnf['maxTimeCount'] = 30
spiderCnf['webScanTimeout'] = task.web_scan_timeout
spiderCnf['endTime'] = time.time() + 1800
spiderCnf['maxnum'] = task.spider_url_count
spiderCnf['title'] = site.title
spiderCnf['ip'] = site.ip
spiderCnf['cookie'] = cookie
spiderCnf['webSearchSiteState'] = task.web_search_site_state
spiderCnf['webSearchSiteTimeout'] = task.web_search_site_timeout
spiderCnf['includeUrl'] = site.include_url
spiderCnf['excludeUrl'] = site.exclude_url
spiderCnf['downloadDir'] = SCANER_SPIDER_DOWNLOAD_DIR
#import plugins.lib.common
#argv['rec'] = plugins.lib.common.request_exception_counter(200)
spiderCnf['rec'] = None

import Spider2 as Spider
# import Spider
'''
if task.spider_type == 2:
    import Spider2 as Spider
else:
    import Spider
'''
spider = Spider.Spider(spiderCnf)
spider.start()

# url="http://192.168.5.135:8503/vulnerabilities/sqli/"
# spider.startTester(url)

