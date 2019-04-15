# --*-- coding:utf-8 --*--
import json

import httplib2
import urllib
from flask import url_for, request, jsonify
from config import SPIDER_URL, SPIDER_TOKEN
from web import logger, db
from web.api_1_0 import api
from web.models.cron import SpiderJob, ApJobsTaskRef
from web.models.task import Task
from web.utils.web_job import run_engine
from web.utils.decorater import permission_required_notify

header = {'token': SPIDER_TOKEN,'Content-Type': 'application/x-www-form-urlencoded'}
http = httplib2.Http()


@permission_required_notify('spider_notify')
@api.route('/spider/notify', methods=['POST'])
def spider_notify():
    try:
        # print 11111111111111
        data_str = request.data
        data = json.loads(data_str)
        spider_task_id = data.get('task_id')
        execute_id = data.get('execute_id')
        # spider_task_id = 235
        # execute_id = 6247

        spider_job = db.session.query(SpiderJob).filter(SpiderJob.spider_task_id==spider_task_id).first()
        spider_job.spider_exe_id = execute_id
        times = spider_job.notify_times
        spider_job.notify_times = times-1
        db.session.add(spider_job)
        db.session.commit()
        task_id = spider_job.task_id
        action = 'start'
        task = db.session.query(Task).filter(Task.id == task_id).first()
        # 未启动的任务
        if task.state == 1:
            job = run_engine.apply_async(args=[task_id, action, execute_id], countdown=10)
            job_task_ref = ApJobsTaskRef(job.id, task_id, 'PENDING')
            db.session.add(job_task_ref)

            db.session.commit()
        return 'ok'
    except Exception, e:
        logger.error(e)
        # print e
        return 'failed'


def add_spider_task(start_urls, limit_time=1800, execute_delay=60, token=None):

    post_data = {
        'start_urls': start_urls,
        'type':'spider',
        'limit_depth':15,
        'limit_total':1000,
        'limit_time': limit_time,
        'limit_image':0,
        'limit_subdomain':0,
        'limit_js': 1,
        'url_unique_mode':'url-query',
        'notify_url': str(url_for('api.spider_notify', _external=True))+"?token="+token,
        'source_ip':'',
        'proxies':'',
        'crontab':'',
        'execute_at': '',
        'execute_delay': execute_delay
    }
    body = urllib.urlencode(post_data)
    spider_task_id = None

    try:
        res, content = http.request(SPIDER_URL+'/task/save', 'POST', body=body, headers=header)
        con = json.loads(content)
        if res.get('status')=='200' and con.get('status')=='ok':
            spider_task_id = con.get('data').get('task_id')
            msg=con.get('msg')
            return spider_task_id, msg
        else:
            msg = con.get('msg')
    except Exception, e:
        logger.error(e)
        msg = str(e)
    return spider_task_id, msg


def del_spider_task(scan_task_id=None):

    spider_task = db.session.query(SpiderJob).filter(SpiderJob.task_id == scan_task_id).first()
    # spider_task_id = 200
    if spider_task:
        try:
            post_data = {'ids': spider_task.spider_task_id}
            body = urllib.urlencode(post_data)
            res, content = http.request(SPIDER_URL+'/task/delete', 'POST', body=body, headers=header)
            print res, content
            con = json.loads(content)
            if res.get('status') == '200' and con.get('status') == 'ok':
                return True
        except Exception,e:
            logger.error(e)
        return False

if __name__ == '__main__':
    # print add_spider_task('http://demo.aisec.cn/demo/')
    del_spider_task()