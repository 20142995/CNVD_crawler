import re
import os
import json
import html
import execjs
import requests
import hashlib

requests.packages.urllib3.disable_warnings()


class CNVDSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36'
        })

    def get_jsl_clearance_s(self, jsl_data):
        """根据 jsl_data 计算 __jsl_clearance_s 的值"""
        chars = len(jsl_data['chars'])
        for i in range(chars):
            for j in range(chars):
                jsl_clearance_s = jsl_data['bts'][0] + jsl_data['chars'][i:(
                    i + 1)] + jsl_data['chars'][j:(j + 1)] + jsl_data['bts'][1]
                if getattr(hashlib, jsl_data['ha'])(jsl_clearance_s.encode('utf-8')).hexdigest() == jsl_data['ct']:
                    return jsl_clearance_s

    def handle_521_response(self, response):
        """处理状态码为 521 的响应，返回需要更新的 cookies"""
        cookies = {}
        if re.findall('document.cookie=(.*?);location.', response.text):
            # 第一次 521 响应：运行 JS 得到 __jsl_clearance_s
            __jsl_clearance_s = execjs.eval(re.findall(
                'document.cookie=(.*?);location.', response.text)[0]).split(';')[0].split('=')[1]
            cookies['__jsl_clearance_s'] = __jsl_clearance_s
        elif re.findall('go\((\{.*?\})\)', response.text):
            # 第二次 521 响应：解析 JS 数据并计算新的 cookie
            jsl_data = json.loads(re.findall(
                'go\((\{.*?\})\)', response.text)[0])
            cookies[jsl_data['tn']] = self.get_jsl_clearance_s(jsl_data)
        return cookies

    def get(self, url, **kwargs):
        """发送 GET 请求，自动处理 521 状态码"""
        response = self.session.get(url, **kwargs)
        if response.status_code == 521:
            # 处理 521 响应并更新 cookies
            cookies = self.handle_521_response(response)
            if cookies:
                self.session.cookies.update(cookies)
                # 带上更新后的 cookies 再次请求
                response = self.session.get(url, **kwargs)
                if response.status_code == 521:
                    # 处理第二次 521 响应
                    cookies = self.handle_521_response(response)
                    if cookies:
                        self.session.cookies.update(cookies)
                        # 带上更新后的 cookies 再次请求
                        response = self.session.get(url, **kwargs)
        return response


def parse_data(data):
    for k in data:
        text = data[k]
        # 实体编码解码
        text = html.unescape(text)
        if k == '危害级别':
            text = re.search('(高|中|低)', text).group(
                1) if re.search('(高|中|低)', text) else ''
        if k == '参考链接':
            text = '\n'.join(re.findall('href="(.*?)"', text))
        if k == '厂商补丁':
            text = "https://www.cnvd.org.cn" + re.search('"(/patchInfo/show/\d+)"', text).group(
                1) if re.search('"(/patchInfo/show/\d+)"', text) else ''
        if k == 'CVE ID':
            text = re.search(
                '>(CVE-\d+-\d+)\s*<', text).group(1) if re.search('>(CVE-\d+-\d+)\s*<', text) else ''

        # <br/>
        text = text.replace('<br/>', '\n')
        # \r\n
        text = re.sub('\r\n', '\n', text)
        text = re.sub('\n+', '\n', text)
        text = text.strip()

        data[k] = text
    return data


def main():
    session = CNVDSession()
    page = 0
    size = 100
    params = {'flag': True, 'numPerPage': size,
              'offset': page * size, 'max': size}
    r1 = session.get("https://www.cnvd.org.cn/flaw/list",
                     params=params, verify=False)
    if '<table class="tlist">' in r1.text:
        cvnd_ids = re.findall(r'"/flaw/show/(.*?)"', r1.text)
        # print(f'{len(cvnd_ids)=}')
        for cvnd_id in cvnd_ids:
            if os.path.exists(f'CNVD/{cvnd_id}.json'):
                continue
            try:
                r2 = session.get(
                    f'https://www.cnvd.org.cn/flaw/show/{cvnd_id}', verify=False)
                if re.findall('<td class="alignRight">(CNVD-ID|公开日期|危害级别|影响产品|CVE ID|漏洞描述|漏洞类型|参考链接|漏洞解决方案|厂商补丁|验证信息|报送时间|收录时间|更新时间|漏洞附件)</td>', r2.text):
                    item = {}
                    item['漏洞标题'] = re.findall('<h1 >(.*?)</h1>', r2.text)[0]
                    for k, v in re.findall('<td class="alignRight">(CNVD-ID|公开日期|危害级别|影响产品|CVE ID|漏洞描述|漏洞类型|参考链接|漏洞解决方案|厂商补丁|验证信息|报送时间|收录时间|更新时间|漏洞附件)</td>\s+<td.*?>(.*?)</td>', r2.text, re.S):
                        k = k.strip().replace('\t', '')
                        v = v.strip().replace('\t', '')
                        item[k] = v
                    os.makedirs('CNVD', exist_ok=True)
                    item = parse_data(item)
                    with open(f"CNVD/{cvnd_id}.json", "w", encoding='utf8') as f:
                        json.dump(item, f, ensure_ascii=False, indent=4)
                    print(f'{cvnd_id}')
                else:
                    break
            except:
                pass
    else:
        pass


if __name__ == '__main__':
    main()
