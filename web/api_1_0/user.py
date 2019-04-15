# -*- coding: utf-8 -*-
from flask import request, jsonify
from flask_login import login_required
from web.utils.logger import mylogger as logger
from web import web, db
from web.models.user import User, Group, Selector, Role
from web.utils.decorater import permission_required, permission_required_inter


@web.route('/users', methods=['POST'])
@web.route('/users/<int:user_id>', methods=['PUT'])
@permission_required('user_write')
@login_required
def create_user(user_id=None):
    name = request.values.get('name')
    cname = request.values.get('cname')
    email = request.values.get('email')
    mobile = request.values.get('mobile')
    company = request.values.get('company')
    password = request.values.get('password')
    repassword = request.values.get('repassword')
    department = request.values.get('department')
    role_name = request.values.get('user_role')
    status = True if request.values.get('user_status') else False
    groups = request.values.get('groups')

    if request.method == 'POST':
        user = db.session.query(User).filter(User.name == name).first()
        if user:
            return jsonify(dict(status=False, desc='账号已存在'))
        if password != repassword:
            return jsonify(dict(status=False, desc='两次输入密码不一致'))
        try:
            user = User(name, cname, email, mobile, department, company, rid=2, groups=groups)
            db.session.add(user)
            db.session.commit()
            # 设置密码及scan_key
            user.password = user.gen_password_hash(password)
            user.scan_key = user.generate_auth_uuid()
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            logger.error(e)
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功'))
    else:

        user = db.session.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify(dict(status=False, desc='账号不存在'))

        try:
            # user.name = name
            user.cname = cname
            user.email = email
            user.mobile = mobile
            user.company = company
            user.department = department
            role = db.session.query(Role).filter(Role.cname == role_name).first()
            user.rid = role.id
            user.status = status
            user.groups = groups
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            logger.error(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/users/<int:user_id>', methods=['DELETE'])
@permission_required('user_write')
@login_required
def delete_user(user_id):
    try:
        user = db.session.query(User).filter(User.id == user_id).first()
        user.status = False
        db.session.commit()
    except Exception as e:
        logger.error(e)
        return jsonify(dict(status=False, desc='删除失败'))
    else:
        return jsonify(dict(status=True, desc='删除成功'))


# Group
@web.route('/groups')
@login_required
def show_group():
    return jsonify({})


@web.route('/groups', methods=['POST'])
@web.route('/groups/<int:group_id>', methods=['PUT'])
@login_required
@permission_required('group_write')
def create_group(group_id=None):
    name = request.values.get('name')
    cname = request.values.get('cname')
    selectors = request.values.get('selectors')

    if request.method == 'POST':
        try:
            group = Group(name, cname, selectors=selectors)
            db.session.add(group)
            db.session.commit()
        except Exception as e:
            logger.error(e)
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功'))
    else:
        group = db.session.query(Group).filter(Group.id == group_id).first()
        if not group:
            return jsonify(dict(status=False, desc='用户组不存在'))

        try:
            group.name = name
            group.cname = cname
            group.selectors = selectors
            db.session.add(group)
            db.session.commit()
        except Exception as e:
            logger.error(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/groups/<int:group_id>', methods=['DELETE'])
@login_required
@permission_required('group_write')
def delete_group(group_id):
    try:
        db.session.query(Group).filter(Group.id == group_id).delete()
        db.session.commit()
    except Exception as e:
        logger.error(e)
        return jsonify(dict(status=False, desc='删除失败'))
    else:
        return jsonify(dict(status=True, desc='删除成功'))


# Selector
@web.route('/selectors')
@login_required
def show_selector():
    return jsonify({})


@web.route('/selectors', methods=['POST'])
@web.route('/selectors/<int:selector_id>', methods=['PUT'])
@login_required
@permission_required('selector_write')
def create_selector(selector_id=None):
    name = request.values.get('name')
    cname = request.values.get('cname')
    kind = request.values.get('kind')

    if request.method == 'POST':
        try:
            selector = Selector(name, cname, kind=kind)
            db.session.add(selector)
            db.session.commit()

        except Exception as e:
            logger.error(e)
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功'))
    else:
        selector = db.session.query(Selector).filter(Selector.id == selector_id).first()
        if not selector:
            return jsonify(dict(status=False, desc='权限不存在'))

        try:
            selector.name = name
            selector.cname = cname
            selector.kind = kind
            db.session.add(selector)
            db.session.commit()
        except Exception as e:
            logger.error(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/selectors/<int:selector_id>', methods=['DELETE'])
@login_required
@permission_required('selector_write')
def delete_selector(selector_id):
    try:
        db.session.query(Selector).filter(Selector.id == selector_id).delete()
        db.session.commit()
    except Exception as e:
        logger.error(e)
        return jsonify(dict(status=False, desc='删除失败'))
    else:
        return jsonify(dict(status=True, desc='删除成功'))
