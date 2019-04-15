# --*-- coding: utf-8 --*--
import time
from datetime import datetime
from multiprocessing import Process

from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler

from web import db
from web.models.cron import ApJobsTaskRef
from web.utils.logger import mylogger as logger
from web.utils.report import Report
from config import SQLALCHEMY_DATABASE_URI
from engine import WebScanEngine

# jobstores = {
#     # 'mysql': SQLAlchemyJobStore(url=SQLALCHEMY_DATABASE_URI),
#     'default': MemoryJobStore()
# }
jobstores = {
    'default': SQLAlchemyJobStore(url=SQLALCHEMY_DATABASE_URI, tablename='apscheduler_jobs')
}
executors = {
    'default': ThreadPoolExecutor(10),
    'processpool': ProcessPoolExecutor(6)
}
job_defaults = {
    'coalesce': False,
    'max_instances': 10
}
scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults)
# scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()


def add_job(func, time_cell):
    job = scheduler.add_job(func, 'interval', seconds=time_cell)  # hours,minutes,seconds
    # try:
    #     # This is here to simulate application activity (which keeps the main thread alive).
    #     while True:
    #         time.sleep(2)
    # except (KeyboardInterrupt, SystemExit):
    #     # Not strictly necessary if daemonic mode is enabled but should be done if possible
    #     scheduler.shutdown()

def add_job_date(func, run_time, args):
    job = scheduler.add_job(func, 'date', run_date=run_time, args=[args])  # hours,minutes,seconds
    # if scheduler.state == STATE_STOPPED:
    #     scheduler.start()
    # job_task_ref = ApJobsTaskRef(job.id, args[0], None, None, 'host1')
    # db.session.add(job_task_ref)
    # db.session.commit()

    # 单独跑脚本 才需要加下面模块，确保主线程alive
    try:
        # This is here to simulate application activity (which keeps the main thread alive).
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        # Not strictly necessary if daemonic mode is enabled but should be done if possible
        scheduler.shutdown()


def add_job_cron(func, **kwargs):

    scheduler.add_job(func, 'cron', **kwargs )
    try:
        scheduler.start()
    except Exception as e:
        logger.error(e)


def list_job():
    return scheduler.get_jobs(jobstore='default')


def get_job(id):
    return scheduler.get_job(id)


def del_job(job_id):
    try:
        job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
        if job_task_ref.job_status == 1:
            scheduler.remove_job(job_id)
            db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).delete()
            db.session.commit()
        return True
    except Exception, e:
        print e
        logger.error(e)
        return False


def pause_job(job_id):
    try:
        job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
        if job_task_ref.job_status == 2:
            scheduler.pause_job(job_id, jobstore=jobstores)
            job_task_ref.job_status = 4
            db.session.add(job_task_ref)
            db.session.commit()
        return True
    except Exception, e:
        print e
        logger.error(e)
        return False


def resume_job(job_id):
    try:
        job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
        if job_task_ref.job_status == 4:
            scheduler.resume_job(job_id, jobstore=jobstores)
            job_task_ref.job_status = 2
            db.session.add(job_task_ref)
            db.session.commit()
        return True
    except Exception, e:
        print e
        logger.error(e)
        return False


def run_report():
    report = Report()
    report.checkPdfExists()


def run_engine(args):
    print 'run_engine', args
    job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.task_id == args[0]).first()
    job_task_ref.job_status = 2
    db.session.add(job_task_ref)
    db.session.commit()

    web_scan_engine = WebScanEngine(args[0], args[1])
    web_scan_engine.run()

    job_task_ref.job_status = 3
    job_task_ref.end_time = datetime.now()
    db.session.add(job_task_ref)
    db.session.commit()


class TestCron:
    def __init__(self, str1, str2):
        self.str1 = str1
        self.str2 = str2

    def run(self):
        print self.str1, self.str2


def test_job(args):
    test_cron = TestCron(args[0], args[1])
    test_cron.run()


def run_pro(args):

    p = Process(target=run_engine, args=[args])
    p.start()

    print "p.pid:", p.pid
    print "p.name:", p.name
    print "p.is_alive:", p.is_alive()

if __name__ == '__main__':
    # run_time = dict(week=7, month=9, day=25,  hour=14, minute=39)
    # run_date = datetime(2016, 9, 25, 15, 53, 57)
    # i = timedelta(seconds=5)
    #
    # task_id = 2
    # action = 'restart'
    # add_job_date(test_job, datetime.now()+i, args=[task_id, action])
    # print list_job()
    # add_job(run_pro, 7, str(task_id), args=[task_id, action])
    test = 1
