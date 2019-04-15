# --*-- coding: utf-8 --*--
import json
from urlparse import urlparse
from datetime import datetime, timedelta
from flask import request, jsonify
from web.utils.decorater import permission_required, permission_required_inter
from flask_login import current_user, login_required
from sqlalchemy import func

from web.utils.logger import mylogger as logger
from web import web, db
from web.utils.decorater import verify_scan_key
from web.utils.templatetags.mytags import get_job_task_status, get_task_domain
from web.models.user import User, Group
from web.models.task import Task
from web.models.cron import ApJobsTaskRef
from web.models.rule import TaskRuleFamilyRef, RuleFamily
from web.models.web_policy_db import WebVulFamily
from web.utils.web_job import del_job_db, revoke_job
from web.utils.progress import task_progress
from web.api_1_0 import api
from web.utils.web_job import run_engine


@api.route('/tasks', methods=['POST'])
@web.route('/tasks', methods=['POST'])
@web.route('/tasks/<int:task_id>', methods=['PUT'])
# @login_required
@permission_required_inter('create_task')
def add_task(task_id=None):
    name = request.values.get('task_name')
    scheme = request.values.get('task_scheme')
    domain = request.values.get('task_domain')
    source_ip = request.values.get('source_ip')
    path = request.values.get('task_path')
    cookie = request.values.get('task_cookie')
    spider_type = request.values.get('spider_type')
    task_policy = request.values.get('task_policy')
    urls = request.values.get('urls')
    target = request.values.get('target')
    multiple_task = True if request.values.get('multiple_task') else False
    run_now = True if request.values.get('run_now') else False
    run_time = request.values.get('run_time')
    rules = request.values.get('rules')

    scan_key = request.values.get('scan_key')
    try:
        # 从接口提交的扫描任务，如果是全面扫描则扫描所有规则
        if scan_key:
            if not (name and urls and run_time and task_policy):
                raise Exception
            user_id = verify_scan_key(scan_key).id

            if task_policy == '509':
                rules = db.session.query(func.group_concat(WebVulFamily.id)).filter(WebVulFamily.parent_id != 0).first()[0]
                spider_type = 2

        else:
            username = current_user.name
            user_id = db.session.query(User).filter(User.name == username).first().id
    except Exception, e:
        logger.exception(e)
        return jsonify(dict(status=False, desc='添加更新失败'))
    if request.method == 'POST':
        try:
            if multiple_task:
                target_list = urls2target(urls)
                if source_ip:
                    target_list[0]['source_ip'] = source_ip
                target = json.dumps(target_list)
            else:
                target_dict = {'path': '/'}
                if scheme:
                    target_dict['scheme'] = scheme
                if domain:
                    target_dict['domain'] = domain
                if source_ip:
                    target_dict['source_ip'] = source_ip
                if path:
                    target_dict['path'] = path
                if cookie and cookie != 'None':
                    target_dict['cookie'] = cookie
                target = "[" + json.dumps(target_dict) + "]"
            if run_now:
                run_time = datetime.now()
            else:
                run_time = datetime.strptime(run_time, '%Y-%m-%d %H:%M:%S')

            task = Task()
            task.name = name
            task.target = target
            task.web_scan_policy = task_policy
            task.spider_type = spider_type
            task.web_scan_enable = 1
            task.user_id = user_id
            task.start_time = run_time
            db.session.add(task)
            db.session.commit()
            # 设置密码及scan_key
            # 创建扫描调度任务
            task_id = db.session.query(func.max(Task.id)).one()[0]
            if rules:
                rule_family_ids = rules.split(',')
                for rule_family_id in rule_family_ids:
                    task_rule_ref = TaskRuleFamilyRef(task_id, rule_family_id)
                    db.session.add(task_rule_ref)
                db.session.commit()
            # action = 'start'
            # i = timedelta(seconds=10)
            # if run_now:
            #     # 通过celery任务启动
            #     # run_time = datetime.now() + i
            #     job = run_engine.apply_async(args=[task_id, action], countdown=0)
            #
            # else:
            #     # 通过celery任务启动
            #     delay_seconds = (run_time - datetime.now()).seconds
            #     job = run_engine.apply_async(args=[task_id, action], countdown=delay_seconds)
            #
            # job_task_ref = ApJobsTaskRef(job.id, task_id, 'PENDING', run_time)
            # db.session.add(job_task_ref)
            # db.session.commit()

        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功', task_id=task_id))
    else:

        try:
            task = db.session.query(Task).filter(Task.id == task_id).first()
            task.name = name
            task.target = target
            task.web_scan_policy = task_policy
            task.spider_type = spider_type

            task.web_scan_enable = 1
            task.state = 2
            task.user_id = user_id
            db.session.add(task)
            db.session.commit()

            db.session.query(TaskRuleFamilyRef).filter(TaskRuleFamilyRef.task_id == task_id).delete()
            db.session.commit()
            if rules:
                rule_family_ids = rules.split(',')
                for rule_family_id in rule_family_ids:
                    task_rule_ref = TaskRuleFamilyRef(task_id, rule_family_id)
                    db.session.add(task_rule_ref)
                db.session.commit()

            # 更新task之前将未task未运行的job取消
            job_not_runs = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.task_id == task_id,
                                                                  ApJobsTaskRef.job_status == 1).all()
            for job in job_not_runs:
                revoke_job(job.job_id)
            db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.task_id == task_id,
                                                   ApJobsTaskRef.job_status == 1).delete()
            db.session.commit()
            action = 'restart'
            i = timedelta(seconds=10)
            if run_now:
                run_time = datetime.now() + i
                job = run_engine.apply_async(args=[task_id, action], countdown=10)

            else:
                run_time1 = datetime.strptime(run_time, '%Y-%m-%d %H:%M:%S')
                delay_seconds = (run_time1 - datetime.now()).seconds
                job = run_engine.apply_async(args=[task_id, action], countdown=delay_seconds)

            job_task_ref = ApJobsTaskRef(job.id, task_id, 'PENDING', run_time)
            db.session.add(job_task_ref)
            db.session.commit()

        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/tasks/<string:task_id>', methods=['DELETE'])
@login_required
@permission_required_inter('create_task')
def del_task_job(task_id):
    job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.task_id == task_id,
                                                          ApJobsTaskRef.parent_id == None).first()

    if job_task_ref.job_status != 1:
        return jsonify(dict(status=False, desc='任务已执行，无法删除'))
    try:
        res_del_db = None
        res_revoke = revoke_job(job_task_ref.job_id)
        if res_revoke:
            res_del_db = del_job_db(job_task_ref.job_id)
            if res_del_db:
                db.session.query(Task).filter(Task.id == task_id).delete()
                db.session.query(TaskRuleFamilyRef).filter(TaskRuleFamilyRef.task_id == task_id).delete()
                db.session.commit()
    except Exception as e:
        logger.exception(e)
        return jsonify(dict(status=False, desc='删除失败'))
    else:
        if res_del_db:
            return jsonify(dict(status=True, desc='删除成功'))
        else:
            return jsonify(dict(status=False, desc='删除失败'))


@web.route('/scheduler_job', methods=['POST'])
@login_required
@permission_required_inter('create_task')
def scheduler_job():
    if request.method == 'POST':
        task_id = request.values.get('job_id')
        action = request.values.get('operation')
        i = timedelta(seconds=10)
        run_time = datetime.now() + i
        try:
            task = db.session.query(Task).filter(Task.id == task_id).first()
            task.web_scan_enable = 1
            task.state = 2
            task.start_time = run_time
            db.session.add(task)
            db.session.commit()

            job = run_engine.apply_async(args=[task_id, action], countdown=10)

            job_task_ref = ApJobsTaskRef(job.id, task_id, 'PENDING', run_time)
            db.session.add(job_task_ref)
            db.session.commit()

        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='重启扫描失败'))
        else:
            return jsonify(dict(status=True, desc='重启扫描成功'))


@api.route('/tasks', methods=['GET'])
# @login_required
@permission_required_inter('list_task')
def tasks_list_api():
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        task_jobs = db.session.query(ApJobsTaskRef, Task).outerjoin(Task, ApJobsTaskRef.task_id == Task.id). \
            filter(ApJobsTaskRef.job_status != 3, ApJobsTaskRef.parent_id == None)
    else:
        task_jobs = db.session.query(ApJobsTaskRef, Task).outerjoin(Task, ApJobsTaskRef.task_id == Task.id). \
            filter(ApJobsTaskRef.job_status != 3, ApJobsTaskRef.parent_id == None, Task.user_id == user_id)
    res_data = [dict(task_id=row.Task.id, task_name=row.Task.name,
                     run_time=datetime.strftime(row.ApJobsTaskRef.run_time, '%Y-%m-%d %H:%M:%S'),
                     status=get_job_task_status(row.ApJobsTaskRef.job_status)) for row in task_jobs.all()]
    return jsonify(dict(resp=res_data))


@web.route('/tasks/progress')
@web.route('/tasks/progress/<string:job_id_list>')
def job_progress(job_id_list):
    job_id_list = job_id_list.split(',')
    resp = {}
    for job_id in job_id_list:

        response = task_progress(job_id)
        # response = {
        #         'task_id': job_id,
        #         'state': '爬虫进行中'.decode('utf-8'),
        #         'current': 10,
        #         'total': 100,
        #         'status': 1
        #     }
        resp[job_id] = response

    return jsonify(resp)


def urls2target(urls):
    # urls = '''http://www.sina.com/test1
    # http://www.sohu.com/test2'''
    url_list = urls.split('\n')
    target = []
    for url in url_list:
        target_dict = {}
        url_parse = urlparse(url.lstrip())
        print url_parse
        target_dict['scheme'] = url_parse.scheme
        target_dict['domain'] = url_parse.netloc
        target_dict['path'] = url_parse.path
        target.append(target_dict)
    # print json.dumps(target)
    # return json.dumps(target)
    return target


@api.route('/tasks/progress', methods=['GET', 'POST'])
@permission_required_inter('create_task')
def api_job_progress():
    try:
        job_id = request.values.get('job_id')

        job = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
        if not job:
            resp = {'errorMsg': '查询失败,job为None'.decode('utf-8'), 'resp_status': False}
            return jsonify(resp)
        task = db.session.query(Task).filter(Task.id == job.task_id).first()
        if job.job_status == 1:
            response = {
                'task_id': task.id,
                'state': '未开始'.decode('utf-8'),
                'current': 0,
                'total': 100,
                'status': 0
            }
        elif job.job_status == 3:
            response = {
                    'task_id': task.id,
                    'state': '扫描完成'.decode('utf-8'),
                    'current': 100,
                    'total': 100,
                    'status': 3
                }
        else:
            response = task_progress(job.task_id)
        resp = {}

        if job.run_time:
            start_time = datetime.strftime(job.run_time, '%Y-%m-%d %H:%M:%S')
        if job.end_time:
            end_time = datetime.strftime(job.end_time, '%Y-%m-%d %H:%M:%S')
        else:
            end_time = '0000-00-00 00:00:00'

        resp['resp_status'] = True
        resp['task'] = {'task_id': job.task_id, 'job_id': job.job_id, 'task_name': task.name,
                        'policy': task.web_scan_policy, 'start_time': start_time, 'end_time': end_time,
                        'state': response.get('state'), 'current': response.get('current'),
                        'total': response.get('total'), 'status': response.get('status')}
        print resp
        return jsonify(resp)
    except Exception as e:
        logger.exception(e)
        resp = {'errorMsg': '查询失败'.decode('utf-8'), 'resp_status': False}
        return jsonify(resp)


@api.route('/tasks/progress2', methods=['GET', 'POST'])
@permission_required_inter('create_task')
def api_job_progress2():

    job_ids = request.values.get('job_id')
    job_list = json.loads(job_ids).get('jobs')
    resp = {}
    for job_id in job_list:
        task_pro = {}
        try:
            job = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
            if not job:
                task_pro['resp_status'] = False
                task_pro['task_info'] = {'errorMsg': '查询失败,job为None'.decode('utf-8')}
            else:
                task = db.session.query(Task).filter(Task.id == job.task_id).first()
                if job.job_status == 1:
                    response = {
                        'task_id': task.id,
                        'state': '未开始'.decode('utf-8'),
                        'current': 0,
                        'total': 100,
                        'status': 0
                    }
                elif job.job_status == 3:
                    response = {
                            'task_id': task.id,
                            'state': '扫描完成'.decode('utf-8'),
                            'current': 100,
                            'total': 100,
                            'status': 3
                        }
                else:
                    response = task_progress(job.task_id)

                if job.run_time:
                    start_time = datetime.strftime(job.run_time, '%Y-%m-%d %H:%M:%S')
                if job.end_time:
                    end_time = datetime.strftime(job.end_time, '%Y-%m-%d %H:%M:%S')
                else:
                    end_time = '0000-00-00 00:00:00'

                task_pro['resp_status'] = True
                task_pro['task_info'] = {'task_id': job.task_id, 'task_name': task.name,
                                'policy': task.web_scan_policy, 'start_time': start_time, 'end_time': end_time,
                                'state': response.get('state'), 'current': response.get('current'),
                                'total': response.get('total'), 'status': response.get('status')}
            resp[job_id] = task_pro
        except Exception as e:
            logger.exception(e)
            task_pro['resp_status'] = False
            task_pro['task_info'] = {'errorMsg': '查询失败'.decode('utf-8')}
            resp[job_id] = task_pro
    return jsonify(resp)

