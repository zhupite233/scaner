# --*-- coding: utf-8 --*--
import chardet


def to_unicode(data, charset=None):
    '''
    将输入的字符串转化为unicode对象
    '''
    unicode_data = ''
    if isinstance(data,str):
        if not charset:
            try:
                charset = chardet.detect(data).get('encoding')
            except Exception,e:
                pass
        if charset:
            unicode_data = data.decode(charset,'ignore')
        else:
            unicode_data = data
    else:
        unicode_data = data
    return unicode_data