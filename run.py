import re
import os
import json
import html
import execjs
import requests
import hashlib
import traceback 

requests.packages.urllib3.disable_warnings()

def get_jsl_clearance_s(jsl_data):
    chars = len(jsl_data['chars'])
    for i in range(chars):
        for j in range(chars):
            jsl_clearance_s = jsl_data['bts'][0] + jsl_data['chars'][i:(i + 1)] + jsl_data['chars'][j:(j + 1)] + jsl_data['bts'][1]
            if getattr(hashlib,jsl_data['ha'])(jsl_clearance_s.encode('utf-8')).hexdigest() == jsl_data['ct']:
                return jsl_clearance_s
            
def cnvd_jsl(url,params={},proxies={},cookies={}):

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36',}
    r = requests.get(url,params=params, headers=headers,cookies=cookies,proxies=proxies, verify=False)
    if r.status_code == 521:
        if re.findall('document.cookie=(.*?);location.',r.text):
            cookies = r.cookies.get_dict()
            __jsl_clearance_s = execjs.eval(re.findall('document.cookie=(.*?);location.',r.text)[0]).split(';')[0].split('=')[1]
            cookies['__jsl_clearance_s'] = __jsl_clearance_s
            r = requests.get(url,params=params,cookies=cookies,headers=headers,proxies=proxies,verify=False,)
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)',r.text)[0])       
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = requests.get(url,params=params,cookies=cookies,headers=headers,proxies=proxies,verify=False,)
        if re.findall('go\((\{.*?\})\)',r.text):
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)',r.text)[0])       
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = requests.get(url,params=params,cookies=cookies,headers=headers,proxies=proxies,verify=False,)
    return r,cookies

def parse_data(data):
    for k in data:
        text = data[k]
        # 实体编码解码
        text = html.unescape(text)
        if k == '危害级别':
            text = re.search('(高|中|低)',text).group(1) if re.search('(高|中|低)',text) else ''
        if k == '参考链接':
            text = '\n'.join(re.findall('href="(.*?)"',text))
        if k == '厂商补丁':
            text = "https://www.cnvd.org.cn"+ re.search('"(/patchInfo/show/\d+)"',text).group(1) if re.search('"(/patchInfo/show/\d+)"',text) else ''
        if k == 'CVE ID':
            text = re.search('>(CVE-\d+-\d+)\s*<',text).group(1) if re.search('>(CVE-\d+-\d+)\s*<',text) else ''

        # <br/>
        text = text.replace('<br/>','\n')
        # \r\n
        text = re.sub('\r\n','\n',text)
        text = re.sub('\n+','\n',text)
        text = text.strip()
        
        data[k] = text 
    return data

def main():
    cookies = {}
    page = 0
    size = 100
    params = {'flag':True,'numPerPage':size,'offset':page * size,'max':size}
    r1, cookies = cnvd_jsl("https://www.cnvd.org.cn/flaw/list",params=params,proxies={},cookies=cookies)
    if '<table class="tlist">' in r1.text:
        cvnd_ids = re.findall(r'"/flaw/show/(.*?)"', r1.text)
        # print(f'{len(cvnd_ids)=}')
        for cvnd_id in cvnd_ids:
            if os.path.exists(f'CNVD/{cvnd_id}.json'):
                continue
            try:
                r, cookies = cnvd_jsl(f'https://www.cnvd.org.cn/flaw/show/{cvnd_id}',params={},proxies={},cookies=cookies)
                if re.findall('<td class="alignRight">(CNVD-ID|公开日期|危害级别|影响产品|CVE ID|漏洞描述|漏洞类型|参考链接|漏洞解决方案|厂商补丁|验证信息|报送时间|收录时间|更新时间|漏洞附件)</td>',r.text):
                    item = {}
                    item['漏洞标题'] = re.findall('<h1 >(.*?)</h1>',r.text)[0]
                    for k, v in re.findall('<td class="alignRight">(CNVD-ID|公开日期|危害级别|影响产品|CVE ID|漏洞描述|漏洞类型|参考链接|漏洞解决方案|厂商补丁|验证信息|报送时间|收录时间|更新时间|漏洞附件)</td>\s+<td.*?>(.*?)</td>',r.text,re.S):
                        k = k.strip().replace('\t','')
                        v =  v.strip().replace('\t','')
                        item[k] = v
                    os.makedirs('CNVD',exist_ok=True)
                    item = parse_data(item)
                    with open(f"CNVD/{cvnd_id}.json", "w",encoding='utf8') as f:
                        json.dump(item, f, ensure_ascii=False, indent=4)
                    print(f'{cvnd_id}')
                else:
                    # print(f'{cvnd_id=} error')
                    break
            except:
                # traceback.print_exc()
                pass

                # print(f'{cvnd_id=} continue')
    else:
        pass
        # print(f'list error')

if __name__ == '__main__':
    main()