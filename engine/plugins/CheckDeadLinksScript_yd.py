#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import MySQLdb.cursors
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engineConfig import *


def run_domain(http,ob):
    result = []
    try:
        task_id = ob['taskId']
        # dead_urls = db.session.query(SpiderUrlOther.url).filter(SpiderUrlOther.task_id == task_id, SpiderUrlOther.type == 0).all()
        sql = "SELECT spider_url_other.url FROM spider_url_other WHERE task_id=%s AND TYPE=%s" % (task_id, 0)
        db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
        cursor = db.cursor()
        cursor.execute(sql)
        dead_url_list = cursor.fetchmany(20)
        if len(dead_url_list)>0:
            for dead_url in dead_url_list:
                detail = '检测到网站死链'
                # request = getRequest(dead_url)
                result.append(getRecord(ob, dead_url.get('url'), ob['level'], detail, request=dead_url.get('url'), response=''))

    except Exception, e:
        logger.error("File:CheckDeadLinksScript_yd.py, run_domain function :%s" % (str(e)))

    return result

