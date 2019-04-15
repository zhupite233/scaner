# --*-- coding: utf-8 --*--
from datetime import datetime
from web import db


class ApSchedulerJobs(db.Model):
    __tablename__ = "apscheduler_jobs"
    id = db.Column(db.String(191), primary_key=True)
    next_run_time = db.Column(db.Float, nullable=True)
    job_state = db.Column(db.BLOB, nullable=False)

    def __init__(self, id, next_run_time, job_state):
        self.id = id
        self.next_run_time = next_run_time
        self.job_state = job_state


class ProcessTaskRef(db.Model):
    __tablename__ = "process_task_ref"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    process_id = db.Column(db.Integer, nullable=False)
    task_id = db.Column(db.Integer)
    is_running = db.Column(db.Boolean, nullable=True)

    def __init__(self, pid, task_id, is_running):
        self.process_id = pid
        self.task_id = task_id
        self.is_running = is_running


class ApJobsTaskRef(db.Model):
    __tablename__ = "ap_jobs_task_ref"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_id = db.Column(db.String(191), nullable=False)
    worker_name = db.Column(db.String(32), nullable=True)
    parent_id = db.Column(db.String(191), nullable=True)
    task_id = db.Column(db.Integer)
    job_state = db.Column(db.String(250), nullable=True)
    job_status = db.Column(db.Integer, default=1, nullable=False)  # 1: 未执行 2：执行中 3：完成 4:暂停 5:失败
    run_time = db.Column(db.DATETIME, default=datetime.now, nullable=False)
    end_time = db.Column(db.DATETIME, nullable=True)
    desc = db.Column(db.String(250), nullable=True)

    def __init__(self, job_id, task_id, job_state=None, run_time=None, job_status=1, parent_id=None, end_time=None, desc=None):
        self.job_id = job_id
        self.task_id = task_id
        self.job_state = job_state
        self.run_time = run_time
        self.job_status = job_status
        self.parent_id = parent_id
        self.end_time = end_time
        self.desc = desc
    ''' job_state
    ['PENDING', 'RECEIVED', 'STARTED', 'SUCCESS', 'FAILURE',
               'REVOKED', 'RETRY', 'IGNORED', 'READY_STATES', 'UNREADY_STATES',
               'EXCEPTION_STATES', 'PROPAGATE_STATES', 'precedence', 'state']
    '''


class JobStatus(db.Model):

    __tablename__ = 'job_status'

    status_id = db.Column(db.Integer, primary_key=True, autoincrement=False)
    status_name = db.Column(db.String(50), nullable=False)
    status_desc = db.Column(db.String(250), nullable=True)

    def __init__(self, status_id, status_name, status_desc=None):
        self.status_id = status_id
        self.status_name = status_name
        self.status_desc = status_desc


class SpiderJob(db.Model):

    __tablename__ = 'spider_job'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    spider_job_id = db.Column(db.String(50), nullable=True)
    spider_exe_id = db.Column(db.Integer, nullable=True)
    task_id = db.Column(db.Integer, nullable=True)
    spider_task_id = db.Column(db.Integer, nullable=True)
    worker_name = db.Column(db.String(32), nullable=True)
    spider_msg = db.Column(db.String(250), nullable=True)
    end_time = db.Column(db.DATETIME, nullable=True)
    create_time = db.Column(db.DATETIME, default=datetime.now, nullable=False)
    token = db.Column(db.String(50), nullable=True)
    notify_times = db.Column(db.Integer, default=3)
    domain_dirs = db.Column(db.Text, nullable=True)

    def __init__(self, task_id, spider_task_id, spider_job_id='', spider_exe_id=None, spider_msg=None, end_time=None,
                 create_time=None, token=None, notify_times=3, domain_dirs=''):
        self.spider_job_id = spider_job_id
        self.spider_exe_id = spider_exe_id
        self.task_id = task_id
        self.spider_task_id = spider_task_id
        self.spider_msg = spider_msg
        self.end_time = end_time
        self.create_time = create_time
        self.token = token
        self.notify_times = notify_times
        self.domain_dirs = domain_dirs
