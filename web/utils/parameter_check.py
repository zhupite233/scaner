#coding=utf-8
import re
import json
from web import db
from web.models.web_policy_db import WebVulPolicy, WebVulFamily

def web_or_host(par):
    if par == "web" or par == "host_scan":
        return 0  # valid parameter
    else:
        return 1  # invalid parameter

def letter_number(par):
    if re.match(r"^\w{0,100}$",par):
        return 0
    else:
        return 1

def format_json(par):
    try:
        if json.loads(par):
            return 0
    except:
        return 1

def valid_action(par):
    action_list = ['create', 'delete', 'update', 'list', 'info']
    if par in action_list:
        return 0
    else:
        return 1

def valid_list_str(par):
    if re.match(r"^(\w{0,100},)*(\w{0,100})$",par):
        return 0
    else:
        return 1

def base_parameters(engine, policy_name ): #验证基本参数的有效性
    try:
        safe_engine = web_or_host(engine) #engine只允许是 web 或 host_scan
        #safe_action = valid_action(action) #action只允许是create delete update list info
        safe_policy_name = letter_number(policy_name) #policy_name只允许是字母数字下划线，长度不超过100
        safe_code = safe_engine + safe_policy_name
        if safe_code != 0:
            return 1 # invalid
        else:
            return 0 # valid
    except:
        return 1 # invalid

def verify_webpolicyid(policy_id):
    exist = db.session.query(WebVulPolicy).filter(WebVulPolicy.id == policy_id).first()
    return exist

def verify_webfamilyid(family_id):
    exist = db.session.query(WebVulFamily.id).filter(WebVulFamily.id == family_id).first()
    return exist

#测试
if __name__ == "__main__":
    a = web_or_host("""web""")
    b = letter_number("test12sS3_35")
    c = format_json("""{"test":"1","a":"2"}""")
    d = valid_action("list ")
    print d


