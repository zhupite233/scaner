# --*-- coding: utf-8 --*--
from datetime import datetime

from flask import jsonify

from web import celery
from web import db
from web.models.cron import ApJobsTaskRef
from web.models.task import Task, Sites
from web.models.web_policy_db import WebVulPolicyRef
from web.utils.logger import mylogger as logger
from web.utils.report import Report
from engine.WebScanEngine import WebScanEngine


@celery.task(bind=True)
def run_engine(self, task_id, action):
    print 'run_engine'
    self.update_state(state='STARTED')
    job_id = self.request.id
    job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
    job = self.AsyncResult(job_id)
    job_task_ref.job_status = 2
    job_task_ref.job_state = job.state
    db.session.add(job_task_ref)
    db.session.commit()

    web_scan_engine = WebScanEngine(task_id, action)
    web_scan_engine.run()
    print 'finish_run_engine'
    job_task_ref.job_state = job.status
    job_task_ref.job_status = 3
    job_task_ref.end_time = datetime.now()
    db.session.add(job_task_ref)
    db.session.commit()
    task = db.session.query(Task).filter(Task.id == job_task_ref.task_id).first()
    task.start_time = job_task_ref.run_time
    task.end_time = job_task_ref.end_time
    # task.state = 3
    db.session.add(task)
    db.session.commit()
    # rep = Report()
    # report_id = rep.storage(task_id, job_id)
    job_rep = run_report.apply_async(args=[task_id, job_id], countdown=5)

    return {'current': 100, 'total': 100, 'status': 3, 'result': 100}

@celery.task(bind=True)
def run_report(self, task_id, job_id):
    try:
        logger.debug("扫描任务task_id:%s,job_id:%s执行报告生成任务  开始" % (task_id, job_id))
        rep = Report()
        report_id = rep.storage(task_id, job_id)
        if not report_id:
            rep.checkPdfExists()
        logger.debug("扫描任务task_id:%s,job_id:%s执行报告生成任务  结束" % (task_id, job_id))
    except Exception, e:
       logger.exception(e)
       logger.debug("扫描任务task_id:%s,job_id:%s执行报告生成任务  异常" % (task_id, job_id))

@celery.task(bind=True)
def run_spider(self, task_id, action):
    job_id = self.request.id
    print job_id
    job = self.AsyncResult(job_id)
    test_cron = TestCron(task_id, action)
    test_cron.run(job)


@celery.task(bind=True)
def run_script(self, task_id, action):
    print 'script:', task_id, action


class TestCron:
    def __init__(self, str1, str2):
        self.str1 = str1
        self.str2 = str2

    def run(self, job):
        print job.id, job.state
        print self.str1, self.str2


# 队列中取消JOB 及子任务
def revoke_job(job_id):
    # job = run_spider.AsyncResult(job_id)
    # job.revoke()
    try:
        celery.control.revoke(job_id)
        job_child_list = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.parent_id == job_id).all()
        if len(job_child_list) > 0:
            for job_child in job_child_list:
                celery.control.revoke(job_child.job_id)
        return True
    except Exception, e:
        print e
        logger.error(e)
        return False


# 数据库中删除JOB 及子任务
def del_job_db(job_id):
    try:
        db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.parent_id == job_id).delete()
        db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).delete()
        db.session.commit()
        return True
    except Exception, e:
        print e
        logger.error(e)
        return False


def task_progress(task_id):
    task_site = db.session.query(Sites).filter(Sites.task_id == task_id).all()
    task = db.session.query(Task).filter(Task.id == task_id).first()
    if task.start_time >= datetime.now():
        print task.start_time
        response = {
            'task_id': task_id,
            'state': '未开始'.decode('utf-8'),
            'current': 0,
            'total': 100,
            'status': 0
        }
        return response
    sites_count = len(task_site)
    if sites_count == 0:
        response = {
            'task_id': task_id,
            'state': '扫描准备中'.decode('utf-8'),
            'current': 0,
            'total': 100,
            'status': 1
        }
    else:
        current = 0
        for site in task_site:

            if site.state == 1:
                current += 100 * (1.0 / sites_count)

            elif site.spider_state != 1:
                if site.start_time is None:
                    pass
                else:
                    run_seconds = (datetime.now()-site.start_time).seconds
                    current_spider = (run_seconds/600)*10
                    if current_spider > 10:
                        current_spider = 10
                    current += current_spider * (1.0/sites_count)

            else:
                progress = site.progress.split('|')
                policy_script_count = db.session.query(WebVulPolicyRef).filter(WebVulPolicyRef.policy_id == site.policy).count()
                current_scan = 10+90*len(progress)/policy_script_count
                if current_scan > 100:
                    current_scan = 100
                current += (current_scan * (1.0/sites_count))

        if task.state == 3:
            response = {
                'task_id': task_id,
                'state': '扫描完成'.decode('utf-8'),
                'current': 100,
                'total': 100,
                'status': 3
            }
        else:
            response = {
                    'task_id': task_id,
                    'state': '扫描进行中'.decode('utf-8'),
                    'current': current,
                    'total': 100,
                    'status': 2
            }
    return response


def job_status(job_id):
    job = run_engine.AsyncResult(job_id)

    if job.state == 'PENDING':
        # job did not start yet
        response = {
            'state': job.state,
            'current': 0,
            'total': 1,
            'status': 1
        }
    elif job.state != 'FAILURE':
        response = {
            'state': job.state,
            'current': job.info.get('current', 0),
            'total': job.info.get('total', 1),
            'status': job.info.get('status', 2)
        }
        if 'result' in job.info:
            response['result'] = job.info['result']
    else:
        # something went wrong in the background job
        response = {
            'state': job.state,
            'current': 1,
            'total': 1,
            'status': 5,
            'exception': str(job.info),  # this is the exception raised
        }
    return jsonify(response)

if __name__ == '__main__':
    # run_engine.apply_async(args=[96, 'restart'], countdown=10)
    # revoke_job('013a0448-b3cd-4fa7-a400-5e70e6bf1f14')
    # run_engine(134, 'start')
    # resp = task_progress(216)
    # print resp
    # rep = Report()
    # report_id = rep.storage(323, 'ef2f725f-42bc-46b4-9d64-7f323cb51cb5')
    test = 1
