#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json

from flask import jsonify
from flask_login import current_user

from web.api_1_0 import api
from web.models.user import User
from web.models.web_policy_db import *
from web.utils.parameter_check import verify_webpolicyid, verify_webfamilyid
from web.utils.decorater import permission_required
from web.utils.logger import loggerFactory

loggerfactory = loggerFactory()
logger = loggerfactory.getLogger(__name__)

########web扫描方案######
"""
#根据policy_name查policy_id
def get_policyid(policy_name):
    policy = db.session.query(WebVulPolicy).filter(WebVulPolicy.name == policy_name).first()
    return policy.id

#根据family_name查family_id
def get_familyid(family_name):
    family = db.session.query(WebVulFamily).filter(WebVulFamily.desc == family_name).first()
    return family.id

#根据vul_name查vul_id
def get_vulid(vul_name):
    vul = db.session.query(WebVulList).filter(WebVulList.vul_name == vul_name).first()
    return vul.vul_id
"""


# web扫描方案列表接口
@api.route('/policy/list')
@permission_required('read_policy')
def web_policy_list():
    policys = db.session.query(WebVulPolicy.id, WebVulPolicy.name).all()
    return json.dumps(policys)  # 返回policys对象的json，包含id，name属性


# 方案详情，方案创建者
def web_policy_user(policy_id):
    # policy_id = get_policyid(policy_name)
    policy = db.session.query(WebVulPolicy.user_id).filter(WebVulPolicy.id == policy_id).first()
    if policy:
        user_id = policy.user_id
    else:
        user_id = -1

    #查询创建该方案的用户
    if user_id == -1:  #user id -1 代表未知用户
        user_name = "未知用户"
    elif user_id == 0:  #申杰提供的初始方案1方案2 用户id都是0
        user_name = "申杰"
    else:
        user = db.session.query(User.name).filter(User.id == user_id).first()
        if user:
            user_name = user.name
        else:
            user_name = "未知用户"
    return user_name


# 创建策略页面，获取所有family和vul字典 屏蔽parent_id=0的大类
def web_family_vul():
    family_all = db.session.query(WebVulFamily.id, WebVulFamily.desc). \
        filter(WebVulFamily.parent_id != 0).all()
    family_dict = {}
    vul_dict2 = {}
    for family in family_all:
        vul_dict1 = {}
        family_dict[family.id] = {"name": family.desc, "state": 0}
        vul_all = db.session.query(WebVulFamilyRef.vul_id, WebVulList.vul_name). \
            filter(WebVulFamilyRef.family == family.id, WebVulFamilyRef.vul_id == WebVulList.vul_id, WebVulList.scan_type != 3). \
            group_by(WebVulFamilyRef.vul_id).all()
        for vul in vul_all:
            vul_dict1[vul.vul_id] = {"name": vul.vul_name, "state": 0}
        vul_dict2[family.id] = vul_dict1
    return family_dict, vul_dict2


# 策略详情，获取family字典
def web_policy_family(policy_id):
    def all_family():
        # key为数据库中所有的family，value全部为初始值0, 屏蔽父类id=0的大类
        family_all = db.session.query(WebVulFamily.id, WebVulFamily.desc). \
            filter(WebVulFamily.parent_id != 0).all()
        dict = {}
        for family in family_all:
            dict[family.id] = {"name": family.desc, "state": 0}
        return dict

    def policy_family(dict):
        # 查询方案中已选的family，将字典中对应的value的state改为1
        policy_family = db.session.query(WebVulFamily.id, WebVulFamily.desc). \
            filter(WebVulPolicyRef.policy_id == policy_id, WebVulPolicyRef.family_id == WebVulFamily.id,
                   WebVulFamily.parent_id != 0). \
            group_by(WebVulFamily.id).all()
        for family in policy_family:
            dict[family.id] = {"name": family.desc, "state": 1}
        return dict

    all_dict = all_family()
    policy_dict = policy_family(all_dict)
    return policy_dict


# 策略详情，获取vul字典
def web_policy_vul(policy_id, family_id):
    policy_exist = verify_webpolicyid(policy_id)
    if not policy_exist:
        return "none"
    family_exist = verify_webfamilyid(family_id)
    if not family_exist:
        return "none"

    # 创建字典，key为数据库中指定family下所有的vul，value全部为初始值0
    vul_all = db.session.query(WebVulFamilyRef.vul_id, WebVulList.vul_name). \
        filter(WebVulFamilyRef.family == family_id, WebVulFamilyRef.vul_id == WebVulList.vul_id, WebVulList.scan_type != 3). \
        group_by(WebVulFamilyRef.vul_id).all()
    dict = {}
    for vul in vul_all:
        dict[vul.vul_id] = {"name": vul.vul_name, "state": 0}
    # 指定方案的指定family下已选的vul,将字典对应的state改为1
    policy_vul = db.session.query(WebVulPolicyRef.vul_id, WebVulList.vul_name). \
        filter(WebVulPolicyRef.policy_id == policy_id, WebVulPolicyRef.family_id == family_id,
               WebVulPolicyRef.vul_id == WebVulList.vul_id). \
        group_by(WebVulPolicyRef.vul_id).all()
    for vul in policy_vul:
        dict[vul.vul_id] = {"name": vul.vul_name, "state": 1}

    return dict


# 创建  传入vul_id列表 逗号分隔
# @api.route('/policy/create', methods=['GET','POST'])
# def api_policy_create():
#     policy_name = request.values.get("policy_name")
#     vul_list = request.values.get("vul_list")
#     return web_policy_create(policy_name, vul_list)
def web_policy_create(policy_name, vul_json):
    vul_array = json.loads(vul_json)
    """
    #判断方案名是否存在
    policy_exist = db.session.query(WebVulPolicy).filter(WebVulPolicy.name == policy_name).first()
    if policy_exist:
        return jsonify(dict(status=False, desc='方案重名'))
    """
    # 获取当前用户id
    try:
        user_id = current_user.id
    except:
        user_id = "-1"  # 未知用户

    # 插入数据库
    try:
        # web_vul_policy表增加记录
        policy = WebVulPolicy(policy_name, user_id)
        db.session.add(policy)
        db.session.flush()
        policy_id = policy.id
        # web_vul_policy_ref表增加记录
        for vul_id in vul_array:
            family_id = db.session.query(WebVulFamilyRef.family).filter(WebVulFamilyRef.vul_id == vul_id).first()
            vul_record = WebVulPolicyRef(policy_id, family_id.family, vul_id)
            db.session.add(vul_record)
        db.session.commit()
        return jsonify(dict(status=True, desc='创建成功'))
    except:
        db.session.rollback()
        return jsonify(dict(status=False, desc='创建失败'))


# 删除
# @api.route('/policy/delete/<policy_id>')
def web_policy_delete(policy_id):
    # 获取接口传来的参数
    policy = db.session.query(WebVulPolicy).filter(WebVulPolicy.id == policy_id).first()
    if not policy:
        return jsonify(dict(status=False, desc='策略不存在'))
    else:
        try:
            db.session.query(WebVulPolicy).filter(WebVulPolicy.id == policy_id).delete()
            db.session.query(WebVulPolicyRef).filter(WebVulPolicyRef.policy_id == policy_id).delete()
            db.session.commit()
            return jsonify(dict(status=True, desc='删除成功'))
            # print "删除成功"
        except Exception as e:
            logger.error(e)
            db.session.rollback()
            return jsonify(dict(status=False, desc='删除失败'))

# 修改策略名称
def web_policy_name_update(policy_id, new_policy_name):
    try:
        policy = db.session.query(WebVulPolicy).filter(WebVulPolicy.id == policy_id).first()
        if policy.name != new_policy_name:
            policy.name = new_policy_name
            db.session.add(policy)
            db.session.commit()
            return dict(status=True, desc='名称修改成功')
    except Exception as e:
        logger.error(e)
        db.session.rollback()
        return dict(status=False, desc='名称修改失败')

# 修改策略内容
def web_policy_update(policy_id, vul_json):
    vul_array = json.loads(vul_json)
    try:
        #删除原策略vul配置
        db.session.query(WebVulPolicyRef).filter(WebVulPolicyRef.policy_id == policy_id).delete()
        #增加新的策略vul配置
        for vul_id in vul_array:   #列表 不信任前端传入的数据，核对需要做频繁的数据库查询 性能差 安全性强
            family_id = db.session.query(WebVulFamilyRef.family).filter(WebVulFamilyRef.vul_id == vul_id).first()
            if family_id:
                db.session.add(WebVulPolicyRef(policy_id, family_id.family, vul_id))
            else:
                return dict(status=False, desc='找不到对应的漏洞类型')
        db.session.commit()
        return jsonify(dict(status=True, desc='修改成功'))
    except Exception as e:
        logger.error(e)
        db.session.rollback()
        return jsonify(dict(status=False, desc='修改失败'))


# 主机扫描方案
# 方案列表
def host_policy_list():
    # 预留host
    # policys = db.session.query(HostVulPolicy.id, HostVulPolicy.name).all()
    # return policys
    pass


# 方案创建
def host_policy_create(policy_name, vul_list):
    # 预留host
    pass


# 方案删除
def host_policy_delete(policy_name):
    # 预留host
    pass


def add_policy_script(vul_name, scan_type, script, level, desc, solu, priority, family_id, effect=None,
                      reference=None, enable=1, vul_id=0, family=None, module=None, soluid=None, tag=None):
    '''
    vul_id,默认0,添加后更新； enable,1是enable，0是disable； family，类型名称；module，family父类命令执行类型；
    scan_type=1,1是run_url,2是run_domain； script，脚本名称如sql_inject_common_get；
    level，漏洞级别 HIGH|MED|LOW  命令执行一般是high, 信息泄露如果涉及配置文件、系统文件是high，只是邮箱、注释或者其他内容就是MED或者LOW)；
    desc，攻击描述或者漏洞描述；solu，解决方法；soluid，暂不支持，默认为0；priority，数值越大优先级越高，参考其他插件；
    tag={"DB":"MySQL"}  #   (tag标签，选填。支持 DB数据库，OS操作系统, Language开发语言，一旦填了，就是互斥的)
    family如下：
    id	parent_id	desc                id	parent_id	desc
    1	194	      SQL注入       			122	196	      目录遍历
    98	196	      信息泄露      			123	194	      系统命令执行
    101	195	      内容电子欺骗  			124	196	      资源位置可预测
    103	197	      外链信息      			125	198	      越权访问
    108	199	      暴力登录      			126	195	      跨站脚本攻击
    121	199	      拒绝服务      			127	199	      逻辑错误
    128	197	      配置不当
    '''
    try:
        family = db.session.query(WebVulFamily).filter(WebVulFamily.id == family_id).first()
        module = db.session.query(WebVulFamily).filter(WebVulFamily.id == family.parent_id).first()
        # insert into web_vul_list
        vul_script = WebVulList(vul_id, vul_name, enable, family.desc, module.desc, scan_type, script, level,
                                desc, solu, soluid, priority, tag, family.id, module.id)
        db.session.add(vul_script)
        db.session.flush()
        id = vul_script.id
        if vul_id == 0:
            vul_id = id

        db.session.commit()
        # save vul_script&family relationship
        ref = WebVulFamilyRef(family.parent_id, family.id, vul_id)
        db.session.add(ref)
        db.session.commit()
        # update vul_script
        vul_script = db.session.query(WebVulList).filter(WebVulList.id == id).first()
        if vul_script.vul_id == 0:
            vul_script.vul_id = vul_id

        vul_script.family_id = family.id
        vul_script.module_id = module.id
        db.session.add(vul_script)
        db.session.commit()
    except Exception, e:
        print e
        return False
    return True



if __name__ == '__main__':
    vul_name = 'Thinkphp框架任意代码执行漏洞',
    scan_type = 2
    script = 'ThinkPHPExecScript_yd'
    level = 'HIGH'
    desc = '''ThinkPHP是一个开源的PHP框架， 是为了简化企业级应用开发和敏捷Web应用开发而诞生的。
            最早诞生于2006年初，原名FCS，2007年元旦正式更名为ThinkPHP，并且遵循Apache2开源协议发布。
            早期的思想架构来源于Struts，后来经过不断改进和完善，同时也借鉴了国外很多优秀的框架和模式，使用面向对象的开发结构和MVC模式，融合了Struts的Action和Dao思想和JSP的TagLib（标签库）、RoR的ORM映射和ActiveRecord模式，封装了CURD和一些常用操作，单一入口模式等，在模版引擎、缓存机制、认证机制和扩展性方面均有独特的表现。

            ThinkPHP框架存在任意代码执行漏洞，其威胁程度非常高，漏洞利用方法如下：
            1. http://www.example.com/index.php/module/aciton/param1/${@print(THINK_VERSION)}
            2. http://www.example.com/index.php/module/aciton/param1/${@function_all()}
            ----[1]. 其中function_all代表任何函数，比如:http://www.example.com/index.php/module/aciton/param1/${@phpinfo()}；
                      获取服务器的系统配置信息等；
            ----[2]. http://www.example.com/index.php/module/action/param1/{${system($_GET['x'])}}?x=ls -al；
                      列出网站文件列表；
            ----[3]. http://www.example.com/index.php/module/action/param1/{${eval($_POST[s])}}；
                      写入一句话木马，站点易受到攻击；'''
    solu = '''1. 用户可下载官方发布的补丁：http://code.google.com/p/thinkphp/source/detail?spec=svn2904&r=2838
            2. 直接修改源码：
                /trunk/ThinkPHP/Lib/Core/Dispatcher.class.php
                $res = preg_replace('@(w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
                修改为
                $res = preg_replace('@(w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2';', implode($depr,$paths));
                将preg_replace第二个参数中的双引号改为单引号，防止其中的PHP变量语法被解析执行。'''
    priority = 20
    family_id = 123
    enable = 1
    vul_id = 0
    family = None
    module = None
    soluid = None
    tag = None
    add_policy_script(vul_name, scan_type, script, level, desc, solu, priority, family_id, enable,
                      vul_id, family, module, soluid, tag)
