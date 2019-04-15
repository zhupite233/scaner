# --*-- coding: utf-8 --*--
from flask import render_template, request, abort
from flask_login import current_user, login_required
from sqlalchemy import func, or_

from web import web, db, logger
from web.models.web_policy_db import WebVulPolicy, WebVulList, WebVulPolicyRef, WebVulFamily
from web.models.cron import ApSchedulerJobs, ApJobsTaskRef
from web.models.task import Task, TaskWebScheme, Sites, TaskRepModelRef
from web.models.user import User, Group
from web.models.webResult import WebResult
from web.models.report import ReportModel
from web.models.rule import RuleFamily, TaskRuleFamilyRef, Rule
from web.utils.decorater import verify_scan_key, permission_required_inter


@web.route('/add_task')
@web.route('/add_task/<task_id>')
@login_required
def add_task_html(task_id=None):
    try:
        web_policys = db.session.query(WebVulPolicy)
        web_schemes = db.session.query(TaskWebScheme)
        rule_types = db.session.query(WebVulFamily).filter(WebVulFamily.parent_id != 0)
        rep_models = db.session.query(ReportModel.model_id, ReportModel.model_name)
        if task_id:
            rule_family_ids = db.session.query(func.group_concat(TaskRuleFamilyRef.rule_family_id)).\
                filter(TaskRuleFamilyRef.task_id == task_id).first()
            # print rule_family_ids[0]
            task = db.session.query(Task).filter(Task.id == task_id).first()
            task_rep_model = db.session.query(TaskRepModelRef).filter(TaskRepModelRef.task_id==task_id).first()
            if task_rep_model:
                task_rep_model_id = task_rep_model.rep_model_id
            else:
                task_rep_model_id = db.session.query(ReportModel).filter(or_(ReportModel.company == '上海云盾信息技术有限公司',
                                                                    ReportModel.model_name == '盾眼默认模板')).first().model_id
            return render_template('web_task_edit.html', task=task, policys=web_policys, schemes=web_schemes,
                                   rep_models=rep_models, task_rep_model_id=task_rep_model_id,
                                   rule_family_ids=rule_family_ids[0], level_one='task', level_two='add_task')

        return render_template('web_task_add.html', policys=web_policys, schemes=web_schemes, rule_types=rule_types,
                               rep_models=rep_models, level_one='task', level_two='add_task')
    except Exception as e:
        logger.error(e)
        abort(404)


@web.route('/tasks')
@login_required
@permission_required_inter('list_task')
def tasks_list():
    scan_key = request.values.get('scan_key')
    if scan_key:
        user_id = verify_scan_key(scan_key).id
    else:
        user_id = current_user.id
    user = db.session.query(User).filter(User.id == user_id).first()
    admin_id = db.session.query(Group).filter(Group.name == 'ADMIN').first().id
    if str(admin_id) in user.groups.split(','):
        task_jobs = db.session.query(Task).filter(Task.state != 3)
        # task_jobs = db.session.query(ApJobsTaskRef, Task).join(Task, ApJobsTaskRef.task_id == Task.id).\
        # filter(ApJobsTaskRef.job_status != 3, ApJobsTaskRef.parent_id == None)
    else:
        # task_jobs = db.session.query(ApJobsTaskRef, Task).join(Task, ApJobsTaskRef.task_id == Task.id).\
        #     filter(ApJobsTaskRef.job_status != 3, ApJobsTaskRef.parent_id == None, Task.user_id == user_id)
        task_jobs = db.session.query(Task).filter(Task.state != 3, Task.user_id == user_id)

    return render_template('tasks_list.html', task_jobs=task_jobs, level_one='task', level_two='list_task')


@web.route('/tasks/process')
@web.route('/tasks/process/<int:task_id>')
@login_required
@permission_required_inter('list_task')
def task_process_html(task_id):
    task = db.session.query(Task).filter(Task.id == task_id).first()
    sites = db.session.query(Sites).filter(Sites.task_id == task_id).all()
    vul_list = db.session.query(WebVulList.vul_id, WebVulList.vul_name, WebVulList.script, WebVulList.level, WebVulList.desc)\
        .join(WebVulPolicyRef, WebVulPolicyRef.vul_id == WebVulList.vul_id).\
        filter(WebVulPolicyRef.policy_id == task.web_scan_policy, WebVulList.enable==1).all()
    site_vul_list = []

    for site in sites:
        dict_sites = {}
        dict_sites['site_id'] = site.id
        dict_sites['task_id'] = site.task_id
        dict_sites['domain'] = site.domain
        scan_vul = []
        not_scan_vul = []
        site_progress = site.progress.split('|')
        for vul in vul_list:
            if str(vul.vul_id) in site_progress:
                count = task_process_detail_count(site.id, vul.vul_id)
                vul_dict = {'count': count, 'vul': vul}
                scan_vul.append(vul_dict)
            else:
                not_scan_vul.append(vul)
        dict_sites['scan_vul'] = scan_vul
        dict_sites['not_scan_vul'] = not_scan_vul
        site_vul_list.append(dict_sites)

    return render_template('task_process.html', site_vul_list=site_vul_list)


@web.route('/tasks/process/detail')
@web.route('/tasks/process/detail/<int:site_id>/<int:vul_id>')
@login_required
@permission_required_inter('list_task')
def task_process_detail(site_id, vul_id):

    process_details = db.session.query(WebResult).filter(WebResult.site_id == site_id, WebResult.vul_id == vul_id).all()
    return render_template('task_process_detail.html', process_details=process_details)


def task_process_detail_count(site_id, vul_id):
    if vul_id == 7719:
        count = db.session.query(WebResult).join(Rule, WebResult.vul_id == Rule.vul_id)\
            .filter(WebResult.site_id == site_id, Rule.run_mode == 'url').count()
    elif vul_id == 7720:
        count = db.session.query(WebResult).join(Rule, WebResult.vul_id == Rule.vul_id)\
            .filter(WebResult.site_id == site_id, Rule.run_mode == 'domain').count()

    else:
        count = db.session.query(WebResult).filter(WebResult.site_id == site_id, WebResult.vul_id == vul_id).count()
    return count

