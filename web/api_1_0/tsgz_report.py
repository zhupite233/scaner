# --*-- coding: utf-8 --*--
import json
from flask import jsonify, request

from web.api_1_0 import api
from web.models.cron import ApJobsTaskRef
from web.utils.decorater import permission_required_inter
from web.models.report import PatchReport, PatchTask
from web import db
from web.utils.logger import mylogger as logger


@api.route('/tsgz/loophole_count', methods=['POST'])
@permission_required_inter('report_read')
def tsgz_loophole_count():
    try:
        patch_no = request.values.get('patch_no')
        patch_rep = db.session.query(PatchReport.data_rep_json).filter(PatchReport.patch_no == patch_no).first()
        data_rep_json = patch_rep.data_rep_json
        if not data_rep_json:
            raise Exception
        data_rep_dict = json.loads(data_rep_json)
        data_rep_dict['status'] = True
    except Exception, e:
        logger.error(e)
        data_rep_dict = dict(status=False, desc=str(e))
    return jsonify(data_rep_dict)


@api.route('/tsgz/loophole_detail', methods=['POST'])
@permission_required_inter('report_read')
def tsgz_loophole_detail():
    try:
        patch_no = request.values.get('patch_no')
        job_id = request.values.get('job_id')
        job_task = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
        task_id = job_task.task_id
        patch_task = db.session.query(PatchTask.data_rep_json).filter(PatchTask.patch_no == patch_no,
                                                                      PatchTask.task_id == task_id).first()
        data_rep_json = patch_task.data_rep_json
        if not data_rep_json:
            raise Exception
        data_rep_dict = json.loads(data_rep_json)
        data_rep_dict['status'] = True
    except Exception, e:
        logger.error(e)
        data_rep_dict = dict(status=False, desc=str(e))
    return jsonify(data_rep_dict)