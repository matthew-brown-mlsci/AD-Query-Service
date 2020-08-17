# AD-Query-Service
Python Windows service that provides various AD query data via a flask-powered API

- Used as some glue to expose various AD query data / functions to web browsers via JSONP requests.  

***

- To compile python -> service .exe
```
set PYTHONHOME=C:\python37\python-3.7.1.amd64\
set PYTHONPATH=C:\python37\python-3.7.1.amd64\Lib\
pip install pyinstaller
pyinstaller -F --hidden-import=win32timezone "AD query service.py"
mkdir "c:\scripts"
mkdir "c:\scripts\AD query service"
copy "dist\AD query service.exe" "c:\scripts\AD query service\AD query service.exe"
copy "domains.conf" "c:\scripts\AD query service\domains.conf"
c:
cd "c:\scripts\AD query service"
"AD query service.exe" install
```

- Edit domains.conf, specify your AD specific DCs and fqdn(s) for any domain controllers you want to query
- Make sure the service is running and port 9994 is open and accepting connections

- testing:
```
curl -s "http://localhost:9994/ListKnownDomains"
```

+ List available domains in the domains.conf file, several endpoints require specifying which domain to use (thus specifying ldap server)
*curl -s "http://localhost:9994/GroupUsers?domain-EXAMPLE&group=TestGroup"
+ requires 'domain' and 'group' GET request args - returns AD group DN, ldap_server queried, and member user DN's + samAccountNames
*curl -s "http://localhost:9994/UserInGroup?domain-EXAMPLE&group=TestGroup&samAccountName=testuser"
+ requires 'domain' and 'group' and 'samAccountName' GET request args - verifies if samAccountName is in group or not
*curl -s "http://localhost:9994/UserInfo?domain=EXAMPLE&samAccountName=testuser"
+ requires 'domain' and 'samAccountName' GET request args - Lists a bunch of information about the user account.

- There are also a few other misc endpoints (run a command, list routes, etc) 




