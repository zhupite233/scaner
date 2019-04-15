# --*-- coding: utf-8 --*--
import json
import uuid
from urlparse import urlparse
from datetime import datetime, timedelta
from flask import request, jsonify

from config import SPIDER_LIMIT_TIME
from spider_api import add_spider_task, del_spider_task
from web.utils.decorater import permission_required, permission_required_inter
from flask_login import current_user, login_required
from sqlalchemy import func, or_

from web.utils.logger import mylogger as logger
from web import web, db
from web.utils.decorater import verify_scan_key
from web.utils.templatetags.mytags import get_job_task_status, get_task_domain
from web.models.user import User, Group
from web.models.task import Task
from web.models.cron import ApJobsTaskRef, SpiderJob
from web.models.rule import TaskRuleFamilyRef, RuleFamily
from web.models.web_policy_db import WebVulFamily
from web.models.task import TaskRepModelRef
from web.models.report import PatchTask, ReportModel
from web.utils.web_job import run_engine, del_job_db, revoke_job
from web.utils.progress import task_progress
from web.api_1_0 import api
from markupsafe import escape
import re


@api.route('/tasks', methods=['POST'])
@web.route('/tasks', methods=['POST'])
@web.route('/tasks/<int:task_id>', methods=['PUT'])
# @login_required
@permission_required_inter('create_task')
def add_task(task_id=None):
    name = request.values.get('task_name')
    name = escape(name.decode('utf-8'))
    # scheme = request.values.get('task_scheme')
    # domain = request.values.get('task_domain')
    source_ip = request.values.get('source_ip')
    if source_ip and not re.match('^(\d{1,3}\.){3}\d{1,3}$', source_ip):
        return jsonify(dict(status=False, desc='添加失败, 源IP格式错误'))
    patch_no = request.values.get('patch_no')
    cookie = request.values.get('task_cookie')
    spider_enable = request.values.get('spider_enable')
    task_policy = request.values.get('task_policy')
    rep_model_id = request.values.get('rep_model')
    urls = request.values.get('urls')
    target = request.values.get('target')
    # multiple_task = True if request.values.get('multiple_task') else False
    run_now = True if request.values.get('run_now') else False
    run_time = request.values.get('run_time')
    rules = request.values.get('rules')

    scan_key = request.values.get('scan_key')
    try:
        if not rep_model_id:
            rep_model_id = db.session.query(ReportModel).filter(or_(ReportModel.company == '上海云盾信息技术有限公司',
                                                                ReportModel.model_name == '盾眼默认模板')).first().model_id
        # 从接口提交的扫描任务，如果是全面扫描则扫描所有规则
        if scan_key:
            if not (name and urls and task_policy):
                raise Exception
            user_id = verify_scan_key(scan_key).id

            # if task_policy == '509':
            #     rules = db.session.query(func.group_concat(WebVulFamily.id)).filter(WebVulFamily.parent_id != 0).first()[0]

        else:
            username = current_user.name
            user_id = db.session.query(User).filter(User.name == username).first().id
    except Exception, e:
        logger.exception(e)
        return jsonify(dict(status=False, desc='添加更新失败'))
    if request.method == 'POST':
        try:
            # if multiple_task:
            # target_list = urls2target(urls)
            url_list = urls.split('\n')
            target_list = []
            for url in url_list:
                target_dict = {}
                url_parse = urlparse(url.lstrip())
                # print url_parse
                if url_parse.scheme and url_parse.netloc:
                    target_dict['scheme'] = url_parse.scheme
                    target_dict['domain'] = url_parse.netloc
                    target_dict['path'] = url_parse.path if url_parse.path else '/'
                    target_list.append(target_dict)
                else:
                    return jsonify(dict(status=False, desc='添加失败, 存在格式错误的url，请检查'))

            if (source_ip or cookie) and len(target_list) > 1:
                return jsonify(dict(status=False, desc='添加失败, 多域名扫描不支持设置源IP或者cookie'))
            for dict_target in target_list:
                if source_ip:
                    dict_target['source_ip'] = source_ip
                if cookie:
                    dict_target['cookie'] = cookie
                target_str = json.dumps([dict_target])

                if run_now:
                    run_time = datetime.now()
                else:
                    run_time = datetime.strptime(run_time, '%Y-%m-%d %H:%M:%S')

                task = Task()
                task.name = name
                task.target = target_str
                task.web_scan_policy = task_policy
                task.web_scan_enable = 1
                task.user_id = user_id
                task.start_time = run_time
                task.state = 1
                db.session.add(task)
                db.session.flush()
                task_id = task.id
                # db.session.commit()
                # add spider_job use func add_spider_task in spider_api
                # s_uuid = uuid.uuid1()
                # l_uuid = str(s_uuid)
                # url = '%s://%s%s' % (dict_target['scheme'], dict_target['domain'], dict_target['path'])
                # spider_limit_time = SPIDER_LIMIT_TIME.get(task_policy, 1800)
                import time
                if run_now:
                    # t = time.localtime(time.time()+60)
                    execute_delay = 10
                else:
                    # t = datetime.timetuple(run_time)
                    execute_delay = (run_time - datetime.now()).seconds+10
                # cron = '%s %s %s %s *' % (t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon)

                # spider_task_id, spider_msg = add_spider_task(url, spider_limit_time, execute_delay, l_uuid)
                # if not spider_task_id:
                #     logger.error('%s:add spider task fail' % task_id)
                #     raise Exception
                # spider_job = SpiderJob(task_id, spider_task_id, spider_msg=spider_msg, token=l_uuid)
                # db.session.add(spider_job)
                # db.session.commit()
                # 创建全网态势批次记录
                if patch_no:
                    patch_task = PatchTask(task_id, patch_no)
                    db.session.add(patch_task)
                    db.session.commit()
                if rules:
                    rule_family_ids = rules.split(',')
                    for rule_family_id in rule_family_ids:
                        task_rule_ref = TaskRuleFamilyRef(task_id, rule_family_id)
                        db.session.add(task_rule_ref)
                    db.session.commit()
                action = 'start'
                spider_flag = 1
                if run_now:
                    # 通过celery任务启动
                    run_time = datetime.now()
                    job = run_engine.apply_async(args=[task_id, action, spider_flag], countdown=10)
                else:
                    # 通过celery任务启动
                    delay_seconds = (run_time - datetime.now()).seconds
                    job = run_engine.apply_async(args=[task_id, action, spider_flag], countdown=delay_seconds)

                job_task_ref = ApJobsTaskRef(job.id, task_id, 'PENDING', run_time)
                db.session.add(job_task_ref)
                db.session.commit()
                # job_task_ref_spider = ApJobsTaskRef(job_spider.id, task_id, 'PENDING', run_time, 1, job.id)
                # db.session.add(job_task_ref_spider)
                # db.session.commit()

                task_rep_model_ref = TaskRepModelRef(task_id, rep_model_id)
                db.session.add(task_rep_model_ref)
                db.session.commit()

        except Exception as e:
            logger.exception(e)
            db.session.rollback()
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功', task_id=task_id, job_id=job.id))
    else:

        try:
            task = db.session.query(Task).filter(Task.id == task_id).first()
            task.name = name
            task.target = target
            task.web_scan_policy = task_policy
            if not spider_enable:
                task.spider_enable=0
            task.web_scan_enable = 1
            task.state = 1
            task.user_id = user_id
            task.web_search_site_state = 0
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
            # # 取消爬虫任务
            # del_spider_task(task_id)
            action = 'restart'
            if not spider_enable:
                spider_flag = 0
            else:
                spider_flag = 1
            execute_id = None
            i = timedelta(seconds=10)
            if run_now:
                run_time = datetime.now() + i
                job = run_engine.apply_async(args=[task_id, action, spider_flag], countdown=10)

            else:
                run_time1 = datetime.strptime(run_time, '%Y-%m-%d %H:%M:%S')
                delay_seconds = (run_time1 - datetime.now()).seconds
                job = run_engine.apply_async(args=[task_id, action, spider_flag], countdown=delay_seconds)

            job_task_ref = ApJobsTaskRef(job.id, task_id, 'PENDING', run_time)
            db.session.add(job_task_ref)
            db.session.commit()

            task_rep_model_ref = db.session.query(TaskRepModelRef).filter(TaskRepModelRef.task_id==task_id).first()
            if task_rep_model_ref:
                task_rep_model_ref.rep_model_id = rep_model_id
            else:
                task_rep_model_ref = TaskRepModelRef(task_id, rep_model_id)
            db.session.add(task_rep_model_ref)
            db.session.commit()
            # else:
            #     # add spider_job use func add_spider_task in spider_api
            #     dict_target = json.loads(target)[0]
            #     url = '%s://%s%s' % (dict_target['scheme'], dict_target['domain'], dict_target['path'])
            #     spider_limit_time = SPIDER_LIMIT_TIME.get(task_policy, 1800)
            #     import time
            #     if run_now:
            #         # t = time.localtime(time.time()+60)
            #         execute_delay = 60
            #     else:
            #         # t = datetime.timetuple(run_time)
            #         execute_delay = (run_time - datetime.now()).seconds+60
            #     # cron = '%s %s %s %s *' % (t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon)
            #     s_uuid = uuid.uuid1()
            #     l_uuid = str(s_uuid)
            #     spider_task_id, spider_msg = add_spider_task(url, spider_limit_time, execute_delay, l_uuid)
            #     if not spider_task_id:
            #         logger.error('%s:add spider task fail' % task_id)
            #         raise Exception
            #     spider_job = db.session.query(SpiderJob).filter(SpiderJob.task_id == task_id).order_by(SpiderJob.id.desc()).first()
            #     spider_job.spider_task_id = spider_task_id
            #     spider_job.spider_msg = spider_msg
            #     spider_job.token = l_uuid
            #     db.session.add(spider_job)
            #     db.session.commit()
        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/tasks/<string:task_id>', methods=['DELETE'])
@login_required
@permission_required_inter('create_task')
def del_task_job(task_id):
    job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.task_id == task_id, ApJobsTaskRef.job_status==1,
                                                         ApJobsTaskRef.parent_id == None).first()

    try:
        if job_task_ref:
            if job_task_ref.job_status != 1:
                return jsonify(dict(status=False, desc='任务已执行，无法删除'))

            res_del_db = None
            res_revoke = revoke_job(job_task_ref.job_id)
            if res_revoke:
                res_del_db = del_job_db(job_task_ref.job_id)
            if not res_del_db:
                raise Exception
        db.session.query(Task).filter(Task.id == task_id).delete()
        db.session.query(TaskRuleFamilyRef).filter(TaskRuleFamilyRef.task_id == task_id).delete()
        db.session.commit()
        # 删除爬虫任务
        del_spider_task(task_id)
    except Exception as e:
        logger.exception(e)
        return jsonify(dict(status=False, desc='删除失败'))
    else:
        return jsonify(dict(status=True, desc='删除成功'))


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
        # print url_parse
        if url_parse.scheme and url_parse.netloc:
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

