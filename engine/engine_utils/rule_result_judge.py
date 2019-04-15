# --*-- coding: utf-8 --*--
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import re
from Levenshtein import distance as str_distance

# def result_judge_bak(normal_res, res, content, **kwargs):
#     result = True
#     for key in kwargs.keys():
#         if 'http_code' == key :
#             if res.get('status') == kwargs[key]:
#                 print type(res.get('status'))
#                 result = (True and result)
#             else:
#                 result = (False and result)
#                 break
#         elif 'keyword' == key:
#             if re.search(kwargs[key], content, re.I):
#                 result = (True and result)
#             else:
#                 result = (False and result)
#                 break
#         elif normal_res and 'content' == key:
#             diff_percent = compare_content(normal_res, res)
#             if diff_percent > kwargs[key]:
#                 result = (True and result)
#             else:
#                 result = (False and result)
#                 break
#         else:  # (normal_res and !content)  or (!normal_res and content)
#             pass
#     return result


# def content_similar(content1, content2, rate):
#     '''
#     用于比较响应内容相似度，插件规则都可以用
#     :param content1: 响应body1  str
#     :param content2: 响应body2  str
#     :param rate:  相似度阈值
#     :return:  True 大于等于阈值， False 小于阈值
#     '''
#     diff_distance = str_distance(content1, content2)
#     if diff_distance == 0:
#         return True
#     diff_rate = str_distance(content1, content2) / float(max(len(content1), len(content2)))
#     similar_rate = 1 - diff_rate
#     result = True if similar_rate >= rate else False
#     return result


def page_similar2(status, content, invaild_page_dict):
    '''
    用于比较页面相似度，插件规则都可以用
    :param status: 响应状态码  str
    :param content: 响应body  str
    :param rate:  相似度阈值
    :return:  True 大于等于阈值，表示与404或waf拦截页面相似度高； False 小于阈值，表示与404或waf拦截页面相似度不高
    '''
    if status == '404':
        return True
    if status == '461':
        return True
    # 404 页面关键字匹配，匹配到返回True
    keyword_404 = r'404.{0,10}not\s{0,5}found|404.{0,10}%s|%s|%s|%s|%s|%s|%s' % (u'错误'.decode('utf-8'),
                                                                                 u'找不到文件或目录'.decode('utf-8'),
                                                                                 u'资源可能已被删除'.decode('utf-8'),
                                                                                 u'页面不存在'.decode('utf-8'),
                                                                                 u'文件或目录未找到'.decode('utf-8'),
                                                                                 u'无法访问'.decode('utf-8'),
                                                                                 u'页面可能已经删除'.decode('utf-8')
                                                                                 )

    if re.search(keyword_404, content.decode('utf-8', 'ignore'), re.I | re.M):
        return True

    keyword_waf = r'\bwaf\b|firewall|%s|%s|%s|%s|%s!|%s' % (u'非法请求'.decode('utf-8'),
                                                         u'拦截'.decode('utf-8'),
                                                         u'防火墙'.decode('utf-8'),
                                                         u'非法参数'.decode('utf-8'),
                                                         u'非法操作'.decode('utf-8'),
                                                         u'访问禁止'.decode('utf-8')
                                                         )
    if re.search(keyword_waf, content.decode('utf-8', 'ignore'), re.I | re.M):
        return True
    status2 = invaild_page_dict.get('status')
    content2 = invaild_page_dict.get('content')
    rate = invaild_page_dict.get('similar_rate')
    # 状态码判断
    if not status2:  # status2为 None 表示waf 拦截页面与404页面一样（也可能没有waf），因此跳过waf页面判断
        return False
    if type(status) != type(status2):
        status = str(status)
        status2 = str(status2)
    if status != status2:
        return False

    len_1 = len(content)
    len_2 = len(content2)
    max_len = max(len_1, len_2)
    # 字符串长度差异度判断, 长度相差太大直接认为页面不相似
    len_similar = min(len(content), len(content2)) / float(max_len)
    if len_similar < rate:
        return False
    if len_similar > 0.95:
        return True
    # 字符串编辑距离判断
    if len_1 > 10000:
        content = content[:5000] + content[-5000:]  # 截取content首尾各1000字符
        max_len = 10000  # 最大长度改为2000
    if len_2 > 10000:
        content2 = content2[:5000] + content2[-5000:]
        max_len = 10000
    diff_distance = str_distance(content, content2)
    if diff_distance == 0:
        return True
    str_diff_rate = str_distance(content, content2) / float(max_len)
    str_similar = 1 - str_diff_rate
    if str_similar >= rate:
        return True
    return False


def page_similar(status, content, invaild_page_dict):
    '''
    用于比较页面相似度，插件规则都可以用
    :param status: 响应状态码  str
    :param content: 响应body  str
    :param rate:  相似度阈值
    :return:  True 大于等于阈值，表示与404或waf拦截页面相似度高； False 小于阈值，表示与404或waf拦截页面相似度不高
    '''
    if status == '404':
        return True
    if status == '461':
        return True

    charset_flag = 'utf-8'  # 默认采用 utf-8 解码
    charset = re.search(r'charset=([\w\-]+)\b', content, re.I|re.M)
    if charset:
        charset_flag = charset.groups()[0]
    if charset_flag.lower() == 'gbk2312':
        charset_flag = 'gb2312'
    # 404 页面关键字匹配，匹配到返回True
    keyword_404 = ur'404.{0,10}not\s{0,5}found|404.{0,10}错误|找不到文件或目录|资源可能已被删除|页面不存在|文件或目录未找到|无法访问|页面可能已经删除'

    if re.search(keyword_404, content.decode(charset_flag, 'ignore'), re.I | re.M):
        return True

    keyword_waf = ur'\bwaf\b|firewall|非法请求|拦截|防火墙|非法参数|非法操作|访问禁止|非法内容'
    if re.search(keyword_waf, content.decode(charset_flag, 'ignore'), re.I | re.M):
        return True
    status2 = invaild_page_dict.get('status')
    content2 = invaild_page_dict.get('content')
    rate = invaild_page_dict.get('similar_rate')
    # 状态码判断
    if not status2:  # status2为 None 表示waf 拦截页面与404页面一样（也可能没有waf），因此跳过waf页面判断
        return False
    if type(status) != type(status2):
        status = str(status)
        status2 = str(status2)
    if status != status2:
        return False

    len_1 = len(content)
    len_2 = len(content2)
    max_len = max(len_1, len_2)
    # 字符串长度差异度判断, 长度相差太大直接认为页面不相似
    len_similar = min(len(content), len(content2)) / float(max_len)
    if len_similar < rate:
        return False

    # 字符串编辑距离判断
    if len_1 > 10000:
        content = content[:5000] + content[-5000:]  # 截取content首尾各1000字符
        max_len = 10000  # 最大长度改为10000
    if len_2 > 10000:
        content2 = content2[:5000] + content2[-5000:]
        max_len = 10000
    diff_distance = str_distance(content, content2)
    if diff_distance == 0:
        return True
    str_diff_rate = str_distance(content, content2) / float(max_len)
    str_similar = 1 - str_diff_rate
    if str_similar >= rate:
        return True
    return False


def result_judge(normal_res, normal_cont, res, res_content, **kwargs):
    """
    :param normal_res: 正常http请求返回头
    :param normal_cont: 正常http请求返回body
    :param res: 注入后请求返回头
    :param content: 注入后请求返回body
    :param kwargs: 判断条件,类型为字典，目前只支持http_code/keyword/similar/content 四种判断条件
                    {"http_code": {"mode": "equal", "value": ["200", "999"]},"keyword":"php\\s+version",
                    "similar": {"mode": "less_than", "value": 0.6}}
    :return: True or False ，与判断条件匹配则为True，否则为False
    """
    result = True
    for key in kwargs.keys():
        if 'http_code' == key:
            if httpCode_judge(res.get("status"), kwargs['http_code']):
                result = (True and result)
            else:
                result = (False and result)
                break
        elif 'keyword' == key:
            if re.search(kwargs[key], res_content, re.I):
                result = (True and result)
            else:
                result = (False and result)
                break
        elif 'content' == key:
            content_res = contentSize_judge(res, res_content, kwargs['content'])
            if content_res:
                result = (True and result)
            else:
                result = (False and result)
                break
        elif 'similar' == key:
            similar_res = similar_judge(normal_res, normal_cont, res, res_content, kwargs['similar'])
            if similar_res:
                result = (True and result)
            else:
                result = (False and result)
                break
        else:  # (normal_res and !content)  or (!normal_res and content)
            pass
    return result



def httpCode_judge(res_code,kwargs):
    '''
    判断http_code 等于、不等于、范围；
    前端范围允许只填下限或者只填上限，下限的缺省值为0，上限的缺省值为999
    本方法不接受空值
    '''
    mode = kwargs['mode']
    value = kwargs['value'] # value是列表，元素是字符串
    if mode == "equal":
        if res_code == value[0]:
            return True
        else:
            return False
    elif mode == "not_equal":
        if res_code != value[0]:
            return True
        else:
            return False
    elif mode == "range":
        if int(res_code) >= int(value[0]) and int(res_code) <= int(value[1]):
            return True
        else:
            return False


def compare_length(mode,length,value):
    '''
    比较长度，仅供本地contenSize_judge调用
    :param mode:
    :param length:
    :param value:
    :return:
    '''
    if mode == "greater_than":
        if length > value:
            return True
        else:
            return False
    elif mode == "less_than":
        if length < value:
            return True
        else:
            return False


def contentSize_judge(res,content,kwargs):
    '''
    # 内容长度比较，供上层方法调用
    :param res: 注入http请求返回头
    :param content: 注入请求返回body
    :param kwargs: 判断条件，类型dict，{"mode": "less_than", "value": '450'}
    :return:
    '''
    mode = kwargs["mode"]
    value = kwargs["value"]
    length = res.get("content-length")
    if length:
        result = compare_length(mode,int(length),int(value))
    else:
        result = compare_length(mode,len(content),int(value))
    return result


def similar_judge(normal_res, normal_cont, res, content, kwargs):
    '''
    内容伪相似度比较
    :param normal_res: 正常http请求返回头
    :param normal_cont: 正常http请求返body
    :param res: 注入http请求返回头
    :param content: 注入http请求返回body
    :param kwargs: 判断条件，类型dict，{"mode": "less_than", "value": 0.6}
    :return:
    '''
    mode = kwargs["mode"]
    value = kwargs["value"]
    if res.get("content-length"):
        length = res.get("content-length")
    else:
        length = len(content)
    if normal_res.get("content-length"):
        normal_len = normal_res.get("content-length")
    else:
        normal_len = len(normal_res)
    diff = abs(int(length)-int(normal_len))
    diff_percent = float(diff)/int(normal_len)
    if mode == "greater_than":
        if 1.0-diff_percent >= value:
            return True
        else:
            return False
    elif mode == "less_than":
        if 1.0-diff_percent <= value:
            return True
        else:
            return False

