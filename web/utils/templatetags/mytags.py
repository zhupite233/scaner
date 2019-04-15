# --*-- coding: utf-8 --*--
import json
from web import db
from web.models.user import User, Role
from web.models.cron import JobStatus
from web.models.web_policy_db import WebVulFamily
from ext import app


def get_role(user):
    # 获取用户角色
    user_role = db.session.query(Role).filter(Role.id == user.rid).first()
    return user_role.cname


def role_name2id(role_name):
    print role_name
    role = db.session.query(Role).filter(Role.cname == role_name).first()
    return role.id


def get_job_task_status(job_status_id):
    job_status = db.session.query(JobStatus).filter(JobStatus.status_id == job_status_id).first()
    return job_status.status_name


def get_task_scheme(task):
    target = json.loads(task.target)
    return target[0].get('scheme')


def get_task_domain(target):
    try:
        targets = json.loads(target)
        domains = ''
        for target in targets:
            domains += ', ' + target.get('domain')
        return domains.lstrip(',')
    except Exception, e:
        return ''


def get_task_cookie(task):
    target = json.loads(task.target)
    return target[0].get('cookie')


def get_family_name_by_id(family_id):
    family = db.session.query(WebVulFamily).filter(WebVulFamily.id == family_id).first()

    return family.desc if family else ''

env = app.jinja_env
env.filters['get_role'] = get_role
env.filters['role_name2id'] = role_name2id
env.filters['get_job_task_status'] = get_job_task_status
env.filters['get_task_scheme'] = get_task_scheme
env.filters['get_task_domain'] = get_task_domain
env.filters['get_task_cookie'] = get_task_cookie
env.filters['get_family_name_by_id'] = get_family_name_by_id
