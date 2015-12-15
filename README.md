cookiescanner
=========

Tool for check the cookie flag in multiple sites.


Intro
-----

Tool created to do more easy the process of check the cookie flag when we are analyzing multiple web servers.

If you want to know for why could be useful this tools?

https://www.owasp.org/index.php/SecureFlag <br>
https://www.owasp.org/index.php/HttpOnly <br>
https://www.owasp.org/index.php/Testing_for_cookies_attributes_%28OTG-SESS-002%29 <br>


Usage
-----


```
Usage: cookiescanner.py [options] 
Example: ./cookiescanner.py -i ips.txt

Options:
  -h, --help            show this help message and exit
  -i INPUT, --input=INPUT
                        File input with the list of webservers
  -I, --info            More info
  -u URL, --url=URL     URL
  -f FORMAT, --format=FORMAT
                        Output format (json, xml, csv, normal, grepable)
  --nocolor             Disable color (for the normal format output)
  -g GOOGLE, --google=GOOGLE
                        Search in google by domain
```

Requirements
------

```
requests >= 2.8.1
BeautifulSoup >= 4.2.1
```

Install requirements
------
```
pip3 install --upgrade -r requirements.txt
```

TODO
------

Add intel to recognize the kind of value in the cookie.

Author
------

Manuel Mancera (sinkmanu@gmail.com/[@sinkmanu](https://twitter.com/sinkmanu))<br />


