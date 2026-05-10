"""DVWA - 查看原始登录页 HTML"""
import requests

s = requests.Session()
s.get('http://192.168.18.131/dvwa/setup.php', timeout=5)
r = s.get('http://192.168.18.131/dvwa/login.php', timeout=5)
print(r.text[:3000])
