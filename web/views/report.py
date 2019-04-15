# --*-- coding: utf-8 --*--
import os
from flask import render_template, request, send_from_directory, abort, send_file
from flask_login import current_user, login_required
from web import web, db
from web.utils.logger import mylogger as logger
from web.models.web_policy_db import WebVulPolicy, WebVulList, WebVulFamily
from web.models.cron import ApSchedulerJobs, ApJobsTaskRef
from web.models.task import Task, Sites
from web.models.user import User, Group
from web.models.webResult import WebResult
from sqlalchemy import func, or_
from web.utils.decorater import verify_scan_key, permission_required_inter, permission_required
from web.utils.paginate import get_page_items, get_pagination
from web.utils.report import Report
from web.models.report import Report as ModelReport
from config import WEBROOT, STRSPIT, PDF_ROOT
import json
import re
from web.api_1_0.report import add_vul_report
from flask import jsonify
from web.models.report import ReportModel
from markupsafe import escape
from hashlib import md5
from time import time
from config import basedir, PDF_LOGO_PATH1, PDF_LOGO_PATH2
from werkzeug.utils import secure_filename
from web.api_1_0 import api
from PIL import Image


@web.route('/report')
@login_required
@permission_required_inter('report_read')
def report_list():
    try:
        scan_key = request.values.get('scan_key')
        search_msg = request.values.get('search_msg', '')
        if scan_key:
            user_id = verify_scan_key(scan_key).id
        else:
            user_id = current_user.id
        user = db.session.query(User).filter(User.id == user_id).first()
        admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
        if str(admin_id) in user.groups.split(','):
            query = db.session.query(Task).join(ApJobsTaskRef, ApJobsTaskRef.task_id == Task.id). \
            filter(ApJobsTaskRef.job_status == 3, ApJobsTaskRef.parent_id == None).order_by(Task.id.desc())
        else:
            query = db.session.query(Task).join(ApJobsTaskRef, ApJobsTaskRef.task_id == Task.id). \
            filter(ApJobsTaskRef.job_status == 3, ApJobsTaskRef.parent_id == None, Task.user_id == user_id).order_by(Task.id.desc())
        if search_msg:
            like_msg = '%%%s%%' % search_msg
            query = query.filter(or_(Task.id.like(search_msg), Task.name.like(like_msg),
                                     Task.target.like(like_msg)))
        page, per_page, offset, search_msg = get_page_items()
        tasks = query.limit(per_page).offset(offset).all()
        total = query.count()
        pagination = get_pagination(page=page,
                                    per_page=per_page,
                                    total=total,
                                    # record_name="server",
                                    format_total=True,
                                    format_number=True
                                    # search=True,
                                    # search_msg=search_msg
                                    )
        taskids = [task.id for task in tasks]
        reportList = db.session.query(ModelReport.job_id, ModelReport.task_id).filter(ModelReport.task_id.in_(taskids)).order_by(
            ModelReport.id.desc()).all()
        reports = {}
        for report in reportList:
            if not reports.has_key(report.task_id):
                reports[report.task_id] = report
        for task_id in taskids:
            if not reports.has_key(task_id):
                reports[task_id] = ('', task_id)
    except Exception, e:
        logger.exception(e)
        return render_template('error-not-safe.html')
    return render_template('report.html', pagination=pagination, per_page=per_page, tasks=tasks, level_one='task', level_two='list_report',
                           reports=reports)


@web.route('/report/preview/<int:reportid>')
@login_required
@permission_required_inter('report_read')
def report_preview(reportid=None):
    report = db.session.query(ModelReport).filter(ModelReport.id == reportid).first()
    reportData = json.loads(report.json)
    reportData['totalHigh'] = len(reportData['results']['HIGH'])
    reportData['totalMed'] = len(reportData['results']['MED'])
    reportData['totalLow'] = len(reportData['results']['LOW'])
    reportData['total'] = reportData['totalHigh'] + reportData['totalMed'] + reportData['totalLow']
    return render_template('report_preview.html', reportid=reportid, reportData=reportData)


# @web.route('/report/download')
@web.route('/report/download/<int:reportid>')
@login_required
@permission_required_inter('report_read')
def report_download(reportid=None):
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    report = db.session.query(ModelReport).filter(ModelReport.id == reportid).first()

    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        tasks = db.session.query(Task).filter(Task.state == 3).order_by(Task.id).all()
        task_id_list = [task.id for task in tasks]
    else:
        tasks = db.session.query(Task).filter(Task.user_id == user_id, Task.state == 3).order_by(Task.id).all()
        task_id_list = [task.id for task in tasks]
    if int(report.task_id) not in task_id_list:
        abort(403)
    file_dir = WEBROOT + STRSPIT + "app" + STRSPIT + "static" + STRSPIT + "pdf" + STRSPIT
    if os.path.isfile(os.path.join(file_dir, report.pdf)):
        return send_from_directory(file_dir, report.pdf)
    else:
        abort(404)


@web.route('/task/report/<int:task_id>')
@login_required
@permission_required_inter('report_read')
def report_list_for_task(task_id=None):
    task = db.session.query(Task).filter(Task.id == task_id).first()
    reports = db.session.query(ModelReport).filter(ModelReport.task_id == task_id).order_by(ModelReport.id.desc()).all()
    return render_template('report_list.html', task=task, target=json.loads(task.target), reports=reports)


# 任务列表
@web.route('/report/processing')
@web.route('/report/processing/<int:taskId>')
@login_required
@permission_required_inter('report_read')
def report_processing(taskId=None):

    viruses_high = db.session.query(WebResult.task_id, WebResult.id, WebResult.vul_id, WebResult.url, WebVulList.vul_name, WebVulList.family,
                               WebVulList.level).filter(WebResult.task_id == taskId, WebResult.level == 'HIGH',
                                                        WebResult.vul_id == WebVulList.vul_id).order_by(WebVulList.vul_id).all()
    viruses_other = db.session.query(WebResult.task_id, WebResult.id, WebResult.vul_id, WebResult.url, WebVulList.vul_name, WebVulList.family,
                               WebVulList.level).filter(WebResult.task_id == taskId, WebResult.level != 'HIGH',
                                                        WebResult.vul_id == WebVulList.vul_id).order_by(WebVulList.level.desc(), WebVulList.vul_id).all()
    viruses_high.extend(viruses_other)
    site = db.session.query(WebResult.site_id).filter(WebResult.task_id == taskId).first()
    if not site:
        site = db.session.query(Sites.id).filter(Sites.task_id == taskId).first()
    if site:
        site_id = site[0]
    else:
        site_id = 0
    return render_template('report_process.html', viruses=viruses_high, task_id=taskId, site_id=site_id)


# 追加漏报内容到扫描报告
@web.route('/report/add_vul')
@web.route('/report/add_vul/<int:task_id>/<int:site_id>', methods=['GET', 'POST'])
@login_required
@permission_required('report_audit')
def add_vul2report(task_id, site_id):
    '''
    供渗透测试和其他内部工作人员调用，当发现扫描报告存在漏报的内容时，可以直接追加漏洞详情到报告中
    '''
    if not re.match('^\d{1,11}$', str(task_id)):
        return jsonify(dict(status=False, desc='task数据格式错误'))
    if not re.match('^\d{1,11}$', str(site_id)):
        return jsonify(dict(status=False, desc='site数据格式错误'))
    if request.method == 'POST':
        vul_id = request.values.get('vul_id')
        url = request.values.get('url')
        detail = request.values.get('detail')
        request_content = request.values.get('request_content')
        response_content = request.values.get('response_content')
        if not re.match('^\d{1,11}$', str(vul_id)):
            return jsonify(dict(status=False, desc='vul数据格式错误' + str(type(vul_id))))

        vul_script = db.session.query(WebVulList).filter(WebVulList.id == vul_id).first()
        if not vul_script:
            return jsonify(dict(status=False, desc='此漏洞不存在对应的插件或规则，请先添加'))

        commit_res = add_vul_report(task_id=task_id, site_id=site_id, vul_id=vul_id, url=url, detail=detail,
                                    request_content=request_content, response_content=response_content)
        if not commit_res:
            return jsonify(dict(status=False, desc='提交失败'))

        return jsonify(dict(status=True, desc='提交成功'))

    else:
        '''返回页面'''
        vul_dict = {}
        familys = db.session.query(WebVulFamily.desc).filter(WebVulFamily.parent_id != 0).all()
        web_vuls = db.session.query(WebVulList.vul_id, WebVulList.vul_name, WebVulList.family).filter(WebVulList.scan_type != 3).all()
        for vul in web_vuls:
            if not vul_dict.has_key(vul.family):
                vul_dict[vul.family] = []
            vul_dict[vul.family].append({'vul_name': vul.vul_name, 'vul_id': vul.vul_id})
        return render_template('report_add_vul.html', vul_json=json.dumps(vul_dict), familys=familys, task_id=task_id, site_id=site_id)


# 列出WEB扫描报告PDF模板
@web.route('/report/list_model')
# @api.route('/report/list_model')
@login_required
@permission_required_inter('report_read')
def report_model_list():
    models = db.session.query(ReportModel.model_id, ReportModel.model_name, ReportModel.title, ReportModel.company, ReportModel.footer).all()
    return render_template('report_model_list.html', models=models)


# 创建WEB扫描报告PDF模板
@web.route('/report/add_model')
@login_required
@permission_required('report_audit')
def report_model_add():
    '''
    供内部工作人员调用，自定义PDF报告模板
    '''
    return render_template('report_add_model.html')


# 创建WEB扫描报告PDF模板
@web.route('/report/create_model', methods=['POST'])
@login_required
@permission_required_inter('report_audit')
def report_model_create():
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    model_name = request.values.get('model_name')
    title = request.values.get('title')
    company = request.values.get('company')
    footer = request.values.get('footer')
    logo_file = request.files.get('logo_file')
    if not model_name or not title or not company or not footer:
        return jsonify(dict(status=False, desc='必选字段不能为空'))
    if len(model_name) > 100:
        return jsonify(dict(status=False, desc='模板名称太长'))
    if len(title) > 100:
        return jsonify(dict(status=False, desc='模板标题太长'))
    if len(company) > 100:
        return jsonify(dict(status=False, desc='单位名称太长'))
    if len(footer) > 200:
        return jsonify(dict(status=False, desc='页脚太长'))
    if len(logo_file.read()) > 2 * 1024 * 1024:
        return jsonify(dict(status=False, desc='Logo文件太大，仅支持2MB以下'))

    # 对异常字符进行HTML编码，防XSS攻击
    model_name = escape(model_name.decode('utf-8'))
    title = escape(title.decode('utf-8'))
    company = escape(company.decode('utf-8'))
    footer = escape(footer.decode('utf-8'))

    try:
        if not logo_file:
            new_filename = ''
            model = ReportModel(model_name=model_name, title=title, company=company,
                                logo_filename=new_filename, footer=footer, user_id=user_id)
            db.session.add(model)
            db.session.commit()
            return jsonify(dict(status=True, desc='提交成功'))
        else:
            filename = secure_filename(logo_file.filename)
            if not re.match('^.{1,50}\.(?:png|jpg)$', filename, re.I):
                return jsonify(dict(status=False, desc='图片文件只支持.jpg或.png格式'))
            time_stamp = time()
            salt = '18f7fc1b0a37c7f023462249c1c1fc36'
            m = md5()
            m.update('%s%s%f' % (salt, filename, time_stamp))
            postfix = filename.rsplit('.', 1)[1].lower()
            if postfix == 'jpg':
                new_filename = m.hexdigest() + '.jpg'
            elif postfix == 'png':
                new_filename = m.hexdigest() + '.png'
            else:
                return jsonify(dict(status=False, desc='图片文件只支持.jpg或.png格式'))
            file_path1 = '%s%s' % (basedir, PDF_LOGO_PATH1)
            file_path2 = '%s%s' % (basedir, PDF_LOGO_PATH2)
            try:
                im = Image.open(logo_file)
                im.save(os.path.join(file_path1, new_filename), quality=99)  # 压缩后质量为原图的99%, 高保真
                if os.path.exists(file_path2):
                    im.save(os.path.join(file_path2, new_filename), quality=99)
                else:
                    logger.debug("路径%s不存在，文件仅保存一份；如果在本地或测试环境，属于正常情况" % file_path2)
            except Exception, e:
                logger.error("文件保存失败, error:%s" % str(e))
                try:  # 文件上传失败，则删除已上传的部分文件
                    if os.path.exists(os.path.join(file_path1, new_filename)):
                        os.remove(os.path.join(file_path1, new_filename))
                    if os.path.exists(os.path.join(file_path2, new_filename)):
                        os.remove(os.path.join(file_path2, new_filename))
                except Exception, e:
                    logger.error("文件删除失败, error:%s" % str(e))
                return jsonify(dict(status=False, desc='提交失败'))

            model = ReportModel(model_name=model_name, title=title, company=company,
                                logo_filename=new_filename, footer=footer, user_id=user_id)
            db.session.add(model)
            db.session.commit()
            return jsonify(dict(status=True, desc='提交成功'))
    except Exception, e:
        logger.error(str(e))
        return jsonify(dict(status=False, desc='提交失败'))


# 进入修改WEB扫描报告PDF模板页面
@web.route('/report/edit_model')
@web.route('/report/edit_model/<int:model_id>', methods=['GET', 'POST'])
@login_required
@permission_required('report_audit')
def report_model_edit(model_id):
    '''
    供内部工作人员调用，自定义PDF报告模板
    '''
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        model = db.session.query(ReportModel.model_id, ReportModel.model_name, ReportModel.company, ReportModel.title,
                                 ReportModel.footer).filter(ReportModel.model_id == model_id).first()
    else:
        model = db.session.query(ReportModel.model_id, ReportModel.model_name, ReportModel.company, ReportModel.title,
                                 ReportModel.footer).filter(ReportModel.user_id == user_id &
                                                            ReportModel.model_id == model_id).first()
    if model:
        return render_template('report_modify_model.html', model=model)


# 修改WEB扫描报告PDF模板
@web.route('/report/modify_model')
@web.route('/report/modify_model/<int:model_id>', methods=['POST'])
@login_required
@permission_required_inter('report_audit')
def report_model_modify(model_id):
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        model = db.session.query(ReportModel).filter(ReportModel.model_id == model_id).first()
    else:
        model = db.session.query(ReportModel).filter(ReportModel.user_id == user_id & ReportModel.model_id == model_id).first()
    if not model:
        logger.error(model_id)
        abort(403)
    model_name = request.values.get('model_name')
    title = request.values.get('title')
    company = request.values.get('company')
    footer = request.values.get('footer')
    logo_file = request.files.get('logo_file')
    if not model_name or not title or not company or not footer:
        return jsonify(dict(status=False, desc='必选字段不能为空'))
    if len(model_name) > 100:
        return jsonify(dict(status=False, desc='模板名称太长'))
    if len(title) > 100:
        return jsonify(dict(status=False, desc='模板标题太长'))
    if len(company) > 100:
        return jsonify(dict(status=False, desc='单位名称太长'))
    if len(footer) > 200:
        return jsonify(dict(status=False, desc='页脚太长'))
    if len(logo_file.read()) > 2 * 1024 * 1024:
        return jsonify(dict(status=False, desc='Logo文件太大，仅支持2MB以下'))

    # 对异常字符进行HTML编码，防XSS攻击
    new_model_name = escape(model_name.decode('utf-8'))
    new_title = escape(title.decode('utf-8'))
    new_company = escape(company.decode('utf-8'))
    new_footer = escape(footer.decode('utf-8'))
    try:
        model.model_name = new_model_name
        model.title = new_title
        model.company = new_company
        model.footer = new_footer
        if not logo_file:  # 不更新logo
            db.session.commit()
        else:  # 更新logo
            filename = secure_filename(logo_file.filename)
            if not re.match('^.{1,50}\.(?:png|jpg)$', filename, re.I):
                return jsonify(dict(status=False, desc='图片文件只支持.jpg或.png格式'))
            time_stamp = time()
            salt = '18f7fc1b0a37c7f023462249c1c1fc36'
            m = md5()
            m.update('%s%s%f' % (salt, filename, time_stamp))
            postfix = filename.rsplit('.', 1)[1].lower()
            if postfix == 'jpg':
                new_filename = m.hexdigest() + '.jpg'
            elif postfix == 'png':
                new_filename = m.hexdigest() + '.png'
            else:
                return jsonify(dict(status=False, desc='图片文件只支持.jpg或.png格式'))
            file_path1 = '%s%s' % (basedir, PDF_LOGO_PATH1)
            file_path2 = '%s%s' % (basedir, PDF_LOGO_PATH2)
            try:
                im = Image.open(logo_file)
                im.save(os.path.join(file_path1, new_filename), quality=99)  # 压缩后质量为原图的99%, 高保真
                if os.path.exists(file_path2):
                    im.save(os.path.join(file_path2, new_filename), quality=99)
                else:
                    logger.debug("路径%s不存在，文件仅保存一份；如果在本地或测试环境，属于正常情况" % file_path2)
            except Exception, e:
                logger.error("文件保存失败, error:%s" % str(e))
                return jsonify(dict(status=False, desc='提交失败'))
            old_filename = model.logo_filename
            model.logo_filename = new_filename
            db.session.commit()
            # 移除旧文件
            try:
                if os.path.exists(os.path.join(file_path1, old_filename)):
                    os.remove(os.path.join(file_path1, old_filename))
                if os.path.exists(os.path.join(file_path2, old_filename)):
                    os.remove(os.path.join(file_path2, old_filename))
            except Exception, e:
                logger.error("文件删除失败, error:%s" % str(e))
                return jsonify(dict(status=True, desc='新logo提交成功，旧logo删除失败'))
        return jsonify(dict(status=True, desc='修改成功'))
    except Exception, e:
        logger.error(str(e))
        return jsonify(dict(status=False, desc='修改失败'))


# 删除WEB扫描报告PDF模板
@web.route('/report/delete_model', methods=['GET', 'POST'])
@login_required
@permission_required_inter('report_audit')
def report_model_delete():
    model_id = request.values.get('model_id')
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        model = db.session.query(ReportModel).filter(ReportModel.model_id == model_id).first()
    else:
        model = db.session.query(ReportModel).filter(ReportModel.user_id == user_id & ReportModel.model_id == model_id).first()
    if not model:
        logger.error(model_id)
        abort(403)
    old_filename = model.logo_filename
    file_path1 = '%s%s' % (basedir, PDF_LOGO_PATH1)
    file_path2 = '%s%s' % (basedir, PDF_LOGO_PATH2)
    try:
        if os.path.exists(os.path.join(file_path1, old_filename)):
            os.remove(os.path.join(file_path1, old_filename))
        if os.path.exists(os.path.join(file_path2, old_filename)):
            os.remove(os.path.join(file_path2, old_filename))
    except Exception, e:
        return jsonify(dict(status=False, desc='logo文件删除失败' + str(e)))
    try:
        db.session.query(ReportModel).filter(ReportModel.model_id == model_id).delete()
        db.session.commit()
    except Exception, e:
        return jsonify(dict(status=False, desc='logo数据删除失败' + str(e)))
    return jsonify(dict(status=True, desc='删除成功'))

# @web.route('/report2/preview/<string:job_id>')
# def report2_preview(job_id=None):
#    report = Report()
#    mReport  = db.session.query(ModelReport.id, ModelReport.task_id, ModelReport.job_id, ModelReport.domain, ModelReport.json_raw).filter(ModelReport.job_id == job_id).first()
#    result = report.jsonRaw2Report2(json.loads(mReport.json_raw), True)
#    return render_template('report2_preview.html', job_id=job_id, jsondata=json.dumps(result))

# @web.route('/report2/preview/pdf/<string:job_id>')
# def report2_preview_pdf(job_id=None):
#    report = Report()
#    mReport  = db.session.query(ModelReport.id, ModelReport.task_id, ModelReport.job_id, ModelReport.domain, ModelReport.json_raw).filter(ModelReport.job_id == job_id).first()
#    result = report.jsonRaw2Report2(json.loads(mReport.json_raw), True)
#    return render_template('report2_pdf.html', job_id=job_id, jsondata=json.dumps(result))

# @web.route('/report2/pdf/cover/<string:date>')
# def report2_pdf_cover(date=None):
#    return render_template('cover.html', create_date=date)

# @web.route('/report2/pdf/<string:job_id>')
# def report2_pdf(job_id=None):
#    report = Report()
#    mReport  = db.session.query(ModelReport.id, ModelReport.pdf).filter(ModelReport.job_id == job_id).first()
#    if not mReport:
#        return render_template('pdf_404.html')
#    pdfFile = PDF_ROOT + mReport.pdf
#    if os.path.exists(pdfFile):
#        return send_file(pdfFile, mimetype="application/pdf")
#    else:
#        return render_template('pdf_404.html')
