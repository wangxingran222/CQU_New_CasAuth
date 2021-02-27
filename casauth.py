from lxml import etree
import requests
import re
from Crypto.Cipher import AES
import random
import base64
import json


def finishcaslogin(username,password,rese):
    '''传入统一认证用户名，密码，和一个新的requests_Session进行登录'''
    initheaders = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        'Content-Type':'application/x-www-form-urlencoded',
        'Connection':'keep-alive'
    }
    rese.headers = initheaders
    response_1 = rese.get("http://my.cqu.edu.cn/authserver/casLogin?redirect_uri=http%3A%2F%2Fmy.cqu.edu.cn%2Fenroll%2Fcas")
    response_1.encoding='utf-8'
    text = response_1.text
    html = etree.HTML(text)
    encryptsalt = re.findall(r'(?<=pwdDefaultEncryptSalt = ").+?(?=";)',text)[0] #抓取网站源代码JS中的加密盐
    lt = html.xpath("//input[@name='lt']/@value")[0]
    dllt = html.xpath("//input[@name='dllt']/@value")[0]
    execution = html.xpath("//input[@name='execution']/@value")[0]
    _eventId = html.xpath("//input[@name='_eventId']/@value")[0]
    rmShown = html.xpath("//input[@name='rmShown']/@value")[0]
    encryptedpassword = encryptpw(password,encryptsalt) #对密码进行加密
    encryptedpassword = encryptedpassword.decode('utf-8')
    data = {
        'username':username,'password':encryptedpassword,'lt':lt,'dllt':dllt,'execution':execution,'_eventId':_eventId,'rmShown':rmShown
    }
    rese.post("http://authserver.cqu.edu.cn/authserver/login?service=http://my.cqu.edu.cn/authserver/authentication/cas",data = data)  #统一认证登录
    result_0 = rese.get("http://my.cqu.edu.cn/authserver/oauth/authorize?client_id=enroll-prod&response_type=code&scope=all&state=&redirect_uri=http%3A%2F%2Fmy.cqu.edu.cn%2Fenroll%2Ftoken-index")
    oauthcode = re.findall(r'(?<=code=).+?(?=&state)',result_0.url)[0]  #获取登录选课系统的oauthcode
    oauthdata = {
        "client_id":"enroll-prod","client_secret":"app-a-1234","code":oauthcode,"redirect_uri":"http://my.cqu.edu.cn/enroll/token-index","grant_type":"authorization_code","":""
    }
    result_1 = rese.post("http://my.cqu.edu.cn/authserver/oauth/token",data = oauthdata)
    authorization = re.findall(r'(?<="access_token":).+?(?=")',result_1.text)[0][1:] #获取返回的Authorization Header
    authorization = "Bearer "+authorization
    authheaders = {
        "Authorization":authorization
    }
    rese.headers.update(authheaders)
    result_0 = rese.get("http://my.cqu.edu.cn/enroll/Home")

def encryptpw(password,encryptsalt):
    '''完成密码的加密操作'''
    BLOCK_SIZE_8 = AES.block_size #新版金智系统采用AES_CBC加密
    preprandomlist = [chr(random.randint(97,122)) for i in range(64)] #金智在明文密码前增加64位随机字符
    randomhead = "".join(preprandomlist)
    preprandomlist = [chr(random.randint(97,122)) for i in range(16)] #金智使用随机16位IV
    randomiv = "".join(preprandomlist)
    password = randomhead + password
    x =BLOCK_SIZE_8 - (len(password) % BLOCK_SIZE_8)
    if x != 0:
        password = password + chr(x)*x #CBC补齐
    encryptsalt = encryptsalt.encode('utf-8')
    randomiv = randomiv.encode('utf-8')
    cipher = AES.new(encryptsalt,AES.MODE_CBC,randomiv)
    returnpw = password.encode('utf-8')
    returnpw = cipher.encrypt(returnpw)
    returnpw = base64.b64encode(returnpw)
    return returnpw