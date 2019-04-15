# -*- coding: utf-8 -*-
from urlparse import urljoin

from flask import request, jsonify, abort, redirect, url_for
from web.utils.logger import mylogger as logger
from flask_login import login_required, current_user
from web import db, web
from web.models.cron import ApJobsTaskRef
from web.models.task import Task
from web.models.report import Report as ModelReport, ReportModel
from web.models.user import User, Group
from web.models.web_policy_db import WebVulList
from web.models.webResult import WebResult, WebResultData
from web.utils.report import Report
from web.utils.decorater import permission_required_inter, verify_scan_key, permission_required
from web.api_1_0 import api
from datetime import *
import json
import cgi
import re


@api.route('/reports/<string:task_id>', methods=['GET'])
# @login_required
@permission_required_inter('report_read')
def report_output(task_id):
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        tasks = db.session.query(Task).filter(Task.state == 3).order_by(Task.id).all()
        task_id_list = [task.id for task in tasks]
    else:
        tasks = db.session.query(Task).filter(Task.user_id == user_id, Task.state == 3).order_by(Task.id).all()
        task_id_list = [task.id for task in tasks]
    if int(task_id) not in task_id_list:
        abort(403)
    rep = Report()
    dictData = rep.formatResult(task_id)
    return jsonify(dictData)


@api.route('/report2', methods=['GET', 'POST'])
@permission_required_inter('report_read')
def report2():
    scan_key = request.values.get('scan_key')
    job_id = request.values.get('job_id')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id

    mReport  = db.session.query(ModelReport.id, ModelReport.task_id, ModelReport.job_id, ModelReport.domain, ModelReport.json_raw).filter(ModelReport.job_id == job_id).first()
    if not mReport:
        result = {"status":"failed", "error":"task is not exists", "data":{}}
        return jsonify(result)
    task_id = mReport.task_id

    if str(admin_id) in user.groups.split(','):
        tasks = db.session.query(Task).order_by(Task.id).all()
        task_id_list = [task.id for task in tasks]
    else:
        tasks = db.session.query(Task).filter(Task.user_id == user_id).order_by(Task.id).all()
        task_id_list = [task.id for task in tasks]
    if int(task_id) not in task_id_list:
        abort(403)

    report = Report()
    result = report.jsonRaw2Report2(json.loads(mReport.json_raw))
    return jsonify({"status":"success", "error":"", "data":result})

# @login_required
@api.route('/reports')
@permission_required_inter('report_read')
def report_list():
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        tasks = db.session.query(Task.id, Task.name, Task.target, Task.start_time, Task.end_time).filter(Task.state == 3).order_by(Task.id).all()

    else:
        tasks = db.session.query(Task.id, Task.name, Task.target, Task.start_time, Task.end_time).filter(Task.user_id == user_id, Task.state == 3).order_by(Task.id).all()
    reports = [dict(id=task.id, name=task.name, target=task.target, start_time=datetime.strftime(task.start_time, '%Y-%m-%d %H:%M:%S'), end_time=datetime.strftime(task.end_time, '%Y-%m-%d %H:%M:%S')) for task in tasks]
    return jsonify(reports)


@web.route('/report/viruse')
@web.route('/report/viruse/<int:id>/<int:vul_id>', methods=['GET'])
@login_required
@permission_required_inter('report_read')
def report_viruse(id=None, vul_id=None):
    webResult = db.session.query(WebResult.id, WebResult.vul_id, WebResult.task_id, WebResult.asset_task_id, WebResult.site_id, WebResult.url, WebResultData.request, WebResultData.response).filter(WebResult.id==id, WebResult.id==WebResultData.web_result_id).first()
    viruse = db.session.query(WebVulList).filter(WebVulList.vul_id == vul_id).first()
    viruseDict = viruse.to_dict()
    viruseDict['desc'] = viruseDict['desc'].replace("\n", "<br/>")
    viruseDict['solu'] = viruseDict['solu'].replace("\n", "<br/>")
    request = cgi.escape(webResult.request)
    response = cgi.escape(webResult.response)
    url=cgi.escape(webResult.url)
    return jsonify(dict(status=True, viruse=viruseDict, webResult={"id":webResult.id, "vul_id":webResult.vul_id, "task_id":webResult.task_id, "asset_task_id":webResult.asset_task_id, "site_id":webResult.site_id, "url":url, "request":request, "response":response}))


@web.route('/report/rebuild/<string:job_id>', methods=['GET'])
@login_required
@permission_required('report_audit')
def report_rebuild(job_id=None):
    try:
        #taskid = request.values.get('taskid')
        # job_id = request.values.get('job_id')
        job = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
        total = db.session.query(WebResult).filter(WebResult.task_id == job.task_id).count()
        message = 'web_result total is %s' % total

        report = Report()
        result = report.storage(job.task_id, job_id)
        return jsonify({'status':True, 'desc':'重新生成报告成功', 'reportid':int(result), 'message':message})
    except Exception, e:
        logger.exception(e)
        return jsonify({'status':False,'desc':'重新生成报告失败', 'reportid':0, 'mesage':e.message})


@api.route('/report/tester', methods=['GET'])
@login_required
def report_tester():
    report = Report()
    taskid=327
    jobid='be5ba41b-ca0d-4622-bc1c-eb1bb07d5fa7'
    #data = report.formatResult(taskid=taskid)
    data = report.formatResult2(taskid=taskid, jobid=jobid)
    #result = report.storage(taskid, jobid)
    return jsonify({'status':'ok', 'data':data})
    #result = report.storage(taskid, jobid)
    #result = report.savePdf2(jobid)
    mReport = db.session.query(ModelReport.id, ModelReport.create_time, ModelReport.task_id, ModelReport.job_id, ModelReport.domain, ModelReport.json_raw).filter(ModelReport.job_id == jobid).first()
    result = report.jsonRaw2Report2(json.loads(mReport.json_raw))
    return jsonify(result)


# @web.route('/report/processing')
@web.route('/report/processing/<int:id>', methods=['DELETE'])
@login_required
@permission_required('report_audit')
def rep_vul_audit(id=None):
    try:
        db.session.query(WebResult).filter(WebResult.id == id).delete()
        db.session.commit()
        return jsonify(dict(status=True, desc='删除成功'))
    except Exception, e:
        logger.exception(e)
        return jsonify(dict(status=False, desc='删除失败'))


@web.route('/report/processing/patch', methods=['POST'])
@login_required
@permission_required('report_audit')
def del_vul_patch():
    try:
        res_str = request.values.get('vul_str')
        task_id = request.values.get('task_id')
        res_list = res_str.rstrip(',').split(',')
        for res_id in res_list:
            db.session.query(WebResult).filter(WebResult.id == res_id).delete()
        db.session.commit()
        return redirect('/report/processing/%s' % task_id)
    except Exception, e:
        logger.exception(e)
        abort(404)


def add_vul_report(task_id, site_id, vul_id, url, detail='', request_content='', response_content=''):
    try:
        # 存入web_result表
        vul = db.session.query(WebVulList).filter(WebVulList.id == vul_id).first()
        level = vul.level
        res = WebResult(task_id=task_id, site_id=site_id, url=url, level=level, detail=detail, output='',
                        vul_id=vul_id, asset_task_id=0)
        db.session.add(res)
        db.session.flush()
        web_result_id = res.id
        db.session.commit()
    except Exception, e:
        logger.error('Insert data to table: web_result failed: %s' % str(e))
        return False

    try:
        # 存入web_result_data表
        res_data = WebResultData(web_result_id=web_result_id, request=request_content, response=response_content,
                                 task_id=task_id, asset_task_id=0, site_id=site_id)
        db.session.add(res_data)
        db.session.commit()
    except Exception, e:
        logger.error('Insert data to table: web_result_data failed: %s' % str(e))
        return False
    return True


# 列出WEB扫描报告PDF模板, 供adminv5平台调用
@api.route('/report/list_model', methods=['POST'])
@permission_required_inter('report_read')
def report_model_list():
    rep_models = db.session.query(ReportModel).all()
    rep_model_list = []
    for rep_model in rep_models:
        rep_model_dict = rep_model.to_dict()
        preview_path = '/report2/pdf/cover/?model_id=%s' % rep_model.model_id
        preview_url = urljoin(url_for('web.index', _external=True), preview_path)
        rep_model_dict['preview_url'] = preview_url
        rep_model_list.append(rep_model_dict)
    return jsonify(rep_model_list)