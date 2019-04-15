# --*-- coding:utf-8 --*--
import StringIO
from flask_login import login_user, logout_user, current_user, login_required
from flask import redirect, render_template, request, flash, session, url_for
from web.utils.validate_code import create_validate_code
from web.models.user import *
from web import web
from ext import app


@web.route('/')
@web.route('/index/')
def index():
    return redirect(url_for('web.tasks_list'))


@web.route('/users')
@login_required
def user_list():
    users = db.session.query(User)
    groups = db.session.query(Group)
    selectors = db.session.query(Selector)
    roles = db.session.query(Role)
    return render_template('admin_user.html', users=users, groups=groups,
                           selectors=selectors, roles=roles, level_one='admin', level_two='users')


@web.route('/login', methods=['GET', 'POST'])
def do_login():
    next_url = request.values.get('next', '/')
    remember_me = request.values.get('remember_me', True)
    if request.method == 'POST':
        username = request.values.get('username')
        password = request.values.get('password')
        code = request.values.get('auth_code')
        if session.get('yzk').upper() != code.upper():
            flash('验证码错误'.decode('utf-8'), 'error')
            return render_template('login.html')
        user = db.session.query(User).filter(User.name == username, User.status==True).first()
        if not user:
            flash('用户名或密码错误'.decode('utf-8'), 'error')
            return render_template('login.html')
        verify_res = user.check_password_hash(password)
        if not verify_res:
            flash('用户名或密码错误'.decode('utf-8'), 'error')

            return render_template('login.html')
        session['username'] = user.name
        session['company'] = user.company
        role = db.session.query(Role).filter(Role.id == user.rid).first()
        session['role'] = role.name
        selectors = get_selectors(user)
        session['selectors'] = selectors
        login_user(user, remember_me)
        return redirect(next_url)
    else:
        if current_user.is_active:
            return redirect(next_url)

        return render_template('login.html')


@web.route('/logout')
@login_required
def do_logout():
    if current_user.is_active:
        logout_user()
        for key in ['username', 'role', 'selectors']:
            session.pop(key, None)
    return redirect(url_for('web.do_login'))


@web.errorhandler(403)
def error403(error):
    return render_template('error-404.html'), 403


@web.errorhandler(404)
def error404(error):
    return render_template('error-404.html'), 404


@web.errorhandler(413)
def error413(error):
    return render_template('error-413.html'), 413


def get_selectors(user):
    groups = db.session.query(Group).filter(Group.id.in_(user.groups.split(',')))
    selectors = []
    for group in groups:
        if not group.selectors:
            continue
        elif group.selectors == '*':
            _selectors = db.session.query(Selector.name)
        else:
            _selectors = db.session.query(Selector.name).filter(Selector.id.in_(set(group.selectors.split(','))))
        selectors += [_selector.name for _selector in _selectors]
    return selectors


@web.route('/users/code')
# @ login_required
def show_code():
    # 把strs发给前端,或者在后台使用session保存

    code_img, str_code = create_validate_code()
    session['yzk'] = str_code
    buf = StringIO.StringIO()
    code_img.save(buf, 'JPEG', quality=70)
    buf_str = buf.getvalue()
    response = app.make_response(buf_str)
    response.headers['Content-Type'] = 'image/jpeg'
    return response