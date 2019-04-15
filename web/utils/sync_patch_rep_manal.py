# coding: utf-8
import json

from common.sql_orm import DBSession
from web.api_1_0.patch_report import send_patch_rep, send_over_view_rep
from web.models.report import PatchTask, PatchReport


def sync_patch_rep(patch_no, task_id):
    db_session = DBSession()
    patch_task = db_session.query(PatchTask).filter(PatchTask.task_id == task_id).first()
    task_rep_json = patch_task.task_rep_json
    task_rep_dict = json.loads(task_rep_json)

    patch_rep = db_session.query(PatchReport).filter(PatchReport.patch_no == patch_no).first()
    patch_rep_json = patch_rep.rep_json
    patch_rep_dict = json.loads(patch_rep_json)

    send_over_view_rep(patch_no, task_rep_dict)
    send_patch_rep(patch_no, patch_rep_dict)