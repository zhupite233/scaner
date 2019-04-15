windowEvents = ['onload', 'onunload']
formEvents = ['onchange', 'onsubmit', 'onreset', 'onselect', 'onblur', 'onfocus']
imageEvents = ['onabort']
keyboardEvents = ['onkeydown', 'onkeypress', 'onkeyup']
mouseEvents = ['onclick', 'ondbclick', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup']
fillList = ['input', 'select', 'textarea']
passList = ['!--...--', '!DOCTYPE', 'applet', 'script']

tag_mouse_event_dict = {
    'button': '*',
    'a': 'onclick',
    'input': 'onclick',
    'tr': 'onclick'
}
tag_auto_js_list = [['form', 'button', 'onclick']]
tag_attr_dict = {
    '*': 'href',
    'embed': 'src',
    'frame': 'src',
    'iframe': 'src',
    'object': 'data'
}
fill_form_dict = {
    'text': 'text_value',
    'password': 'pwd_value',
    'checkbox': 'true',
    'submit' : 'submit'
    # ,'file': ,
    # 'hidden': ,
    # 'image':
}
tt = 'http://192.168.5.117:8091/ajax_link.php?method=POST&id=1&t=0.6772734614612363'