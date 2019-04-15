# --*-- coding: utf-8 --*--
from flask import current_app, request
from flask_paginate import Pagination


def my_paginate(page, per_page, total, record_name, format_total, format_number):
    pagination = get_pagination(page=page,
                                per_page=per_page,
                                total=total,
                                record_name=record_name,
                                format_total=format_total,
                                format_number=format_number,
                                search=True,
                                )
    return pagination


def get_css_framework():
    return current_app.config.get('CSS_FRAMEWORK', 'bootstrap3')


def get_link_size():
    return current_app.config.get('LINK_SIZE', 'sm')


def show_single_page_or_not():
    return current_app.config.get('SHOW_SINGLE_PAGE', False)


def get_page_items():
    page = int(request.args.get('page', 1))
    per_page = request.args.get('per_page', 10)
    search_msg = request.args.get('search_msg')
    if not per_page:
        per_page = current_app.config.get('PER_PAGE', 10)
    else:
        per_page = int(per_page)

    offset = (page - 1) * per_page
    return page, per_page, offset, search_msg


def get_pagination(**kwargs):
    kwargs.setdefault('record_name', 'records')
    return Pagination(css_framework=get_css_framework(),
                      link_size=get_link_size(),
                      show_single_page=show_single_page_or_not(),
                      **kwargs
                      )
