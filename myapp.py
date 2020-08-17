"""

Flask AD query service implementation
    - includes a bunch of endpoints to facilitate AD tasks
    - supports jsonp
    - Service should be run as LocalSystem user, uses computer's AD acct for query auth

"""

from flask import Flask
import sys
import os
import time
import datetime
from flask import jsonify
import subprocess
import socket
import json
from functools import wraps
from flask import redirect, request, current_app, app
import win32api, win32ts, win32net, win32security, ntsecuritycon
import psutil
from subprocess import PIPE
import tempfile
import re
import pyad.adquery
import pyad.pyad
import pyad.pyadutils
import pythoncom

logfile = "C:\\scripts\\AD query service\\AD query service log.txt"
domain_config_file = "C:\\scripts\\AD query service\\domains.conf"
port = 9994

hostname = socket.gethostname()
app = Flask(__name__)


# Wrapper functions to support JSONP requests should we want to access this API from a browser in the future
def jsonp(func):
    """Wraps JSONified output for JSONP requests."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        callback = request.args.get('callback', False)
        if callback:
            resp = func(*args, **kwargs)
            resp.set_data('{}({})'.format(
                str(callback),
                resp.get_data(as_text=True)
            ))
            resp.mimetype = 'application/javascript'
            return resp
        else:
            return func(*args, **kwargs)
    return decorated_function

# Add a log entry + datetime
def log_entry(log_message):
	with open(logfile, 'a') as f:
		f.write(str(datetime.datetime.now()) + " : ")
		f.write(log_message + '\n')

class domain_obj(object):
    def __init__(self,
                domain,
                base_dn,
                ldap_servers
                ):
        self.domain = domain
        self.base_dn = base_dn
        self.ldap_servers = ldap_servers

    def serialize(self):
        return {
            'domain': self.domain,
            'base_dn': self.base_dn,
            'ldap_servers': [e for e in self.ldap_servers]
        }

@app.route("/ListKnownDomains", methods=['GET'])
@jsonp
def ListKnownDomains():
    domain_objs = []
    try:
        with open(domain_config_file, 'r') as f:
            line = f.readline()
            while line:
                line_domain = line.split('|')[1]
                line_base_dn = line.split('|')[3].strip()
                line_ldap_servers = line.split('|')[5].strip().split(';')
                d = domain_obj(domain=line_domain,base_dn=line_base_dn,ldap_servers=line_ldap_servers[:])
                domain_objs.append(d)
                line = f.readline()
    except Exception as e:
        return jsonify(success=False,
                  error=("Error loading domain_config_file: " + domain_config_file),
                  exception=str(e))

    return jsonify(success=True,
                   domains=[e.serialize() for e in domain_objs])

@app.route("/GroupUsers", methods=['GET'])
@jsonp
def GroupUsers():
    domain = request.args.get('domain')
    group = request.args.get('group')
    last_exception = None

    if domain and group:
        try:
            domain_objs = []
            with open(domain_config_file, 'r') as f:
                line = f.readline()
                while line:
                    line_domain = line.split('|')[1]
                    line_base_dn = line.split('|')[3].strip()
                    line_ldap_servers = line.split('|')[5].strip().split(';')
                    d = domain_obj(domain=line_domain,base_dn=line_base_dn,ldap_servers=line_ldap_servers[:])
                    domain_objs.append(d)
                    line = f.readline()
            domain_set = [e.serialize() for e in domain_objs]
            domain_check = next((item for item in domain_set if item["domain"] == domain), None)
            if not domain_check:
                return jsonify(success=False,
                               error=("'domain' parameter '" + domain + "' not present in domain_config_file"))
            base_dn = domain_check['base_dn']
            ldap_servers = domain_check['ldap_servers']
            
        except Exception as e:
            return jsonify(success=False,
                    error=("Error loading domain_config_file: " + domain_config_file),
                    exception=str(e))

        # Now try the AD query
        ldap_server_query_success = 0
        for ldap_server in ldap_servers:
            pyad.pyad_setdefaults(ldap_server=ldap_server)
            if ldap_server_query_success == 0:
                try:
                    query_results = []
                    pythoncom.CoInitialize()

                    q = pyad.adquery.ADQuery()
                    q.execute_query(
                        attributes=["distinguishedName"],
                        where_clause="objectClass = 'group' AND cn = '{}'".format(group),
                        base_dn=base_dn
                    )
                    
                    if q.get_row_count() == 0:
                        return jsonify(success=False,
                                domain=domain,
                                group=group,
                                ldap_server=ldap_server,
                                error='No rows returned from adsi query')

                    group_dn = ''
                    for row in q.get_results():
                        group_dn = row['distinguishedName']
                    ldap_server_query_success = 1

                except Exception as e:
                    last_exception = e

            if last_exception:
                pythoncom.CoUninitialize()
                return jsonify(success=False,
                               error=("Error querying domain controller"),
                               ldap_server=ldap_server,
                               domain=domain,
                               group=group,
                               exception=str(last_exception))
            
            if group_dn == '':
                pythoncom.CoUninitialize()
                return jsonify(success=False,
                        error=("Error group cn specified invalid"),
                        domain=domain,
                        group=group
                        )

            if ldap_server_query_success == 1:
                try:
                    q = pyad.adquery.ADQuery()
                    q.execute_query(
                                    attributes=["distinguishedName", "sAMAccountName"],
                                    where_clause="memberOf = '{}'".format(group_dn),
                                    base_dn=base_dn
                                )

                    # parse the user dn/samaccountname results
                    users = []
                    for row in q.get_results():
                        users.append({"distinguishedName": row['distinguishedName'],
                                    "sAMAccountName": row['sAMAccountName'] })
                    pythoncom.CoUninitialize()
                    return jsonify(success=True,
                                domain=domain,
                                group=group,
                                ldap_server=ldap_server,
                                group_dn=group_dn,
                                users=[e for e in users])


                except Exception as e:
                    return jsonify(success=False,
                                    error=("Error querying domain controller for memberOf information"),
                                    domain=domain,
                                    group=group,
                                    ldap_server=ldap_server,
                                    exception=str(e))

    else:
        return jsonify(success=False,
                       error="/GroupUsers requires parameter 'domain', and 'group'")

@app.route("/UserInGroup", methods=['GET'])
@jsonp
def UserInGroup():
    last_exception = None
    user_in_group = False
    samAccountName = request.args.get('samAccountName')
    domain = request.args.get('domain')
    group = request.args.get('group')

    if samAccountName and domain and group:
        try:
            domain_objs = []
            with open(domain_config_file, 'r') as f:
                line = f.readline()
                while line:
                    line_domain = line.split('|')[1]
                    line_base_dn = line.split('|')[3].strip()
                    line_ldap_servers = line.split('|')[5].strip().split(';')
                    d = domain_obj(domain=line_domain,base_dn=line_base_dn,ldap_servers=line_ldap_servers[:])
                    domain_objs.append(d)
                    line = f.readline()
            domain_set = [e.serialize() for e in domain_objs]
            domain_check = next((item for item in domain_set if item["domain"] == domain), None)
            if not domain_check:
                return jsonify(success=False,
                               error=("'domain' parameter '" + domain + "' not present in domain_config_file"))
            base_dn = domain_check['base_dn']
            ldap_servers = domain_check['ldap_servers']
            
        except Exception as e:
            return jsonify(success=False,
                    error=("Error loading domain_config_file: " + domain_config_file),
                    exception=str(e))

        # Now try the AD query
        ldap_server_query_success = 0
        for ldap_server in ldap_servers:
            pyad.pyad_setdefaults(ldap_server=ldap_server)
            if ldap_server_query_success == 0:
                try:
                    query_results = []
                    pythoncom.CoInitialize()

                    q = pyad.adquery.ADQuery()
                    q.execute_query(
                        attributes=["distinguishedName"],
                        where_clause="objectClass = 'group' AND cn = '{}'".format(group),
                        base_dn=base_dn
                    )
                    
                    if q.get_row_count() == 0:
                        return jsonify(success=False,
                                domain=domain,
                                group=group,
                                ldap_server=ldap_server,
                                error='Group CN does not exist, No rows returned from adsi query')

                    group_dn = ''
                    for row in q.get_results():
                        group_dn = row['distinguishedName']
                    

                    ldap_server_query_success = 1

                except Exception as e:
                    last_exception = e


            if last_exception:
                pythoncom.CoUninitialize()
                return jsonify(success=False,
                               error=("Error querying domain controller"),
                               ldap_server=ldap_server,
                               domain=domain,
                               group=group,
                               exception=str(last_exception))
            
            if group_dn == '':
                pythoncom.CoUninitialize()
                return jsonify(success=False,
                        error=("Error group cn specified invalid"),
                        domain=domain,
                        group=group
                        )

            print('found group_dn: ' + str((group_dn)))
            if ldap_server_query_success == 1:
                try:
                    query_results = []

                    q = pyad.adquery.ADQuery()
                    q.execute_query(
                                    attributes=["sAMAccountName", "memberOf"],
                                    where_clause="samAccountName = '{}' AND memberOf='{}'".format(samAccountName, group_dn),
                                    base_dn=base_dn
                                )
                    
                    print('q.get_row_count(): ' + str(q.get_row_count()))
                    if q.get_row_count() == 0:

                        pythoncom.CoUninitialize()
                        return jsonify(success=True,
                                samAccountName=samAccountName,
                                domain=domain,
                                ldap_server=ldap_server,
                                group=group,
                                user_in_group=False,
                                )
                    else:
                        pythoncom.CoUninitialize()
                        return jsonify(success=True,
                                samAccountName=samAccountName,
                                domain=domain,
                                ldap_server=ldap_server,
                                group=group,
                                user_in_group=True,
                                )

                except Exception as e:
                    return jsonify(success=False,
                                samAccountName=samAccountName,
                                domain=domain,
                                ldap_server=ldap_server,
                                group=group,
                                error=("Error querying domain controller"),
                                exception=str(e))

    else:
        return jsonify(success=False,
                       error="/UserInGroup requires parameter 'samAccountName', 'domain', and 'group'")


@app.route("/UserInfo", methods=['GET'])
@jsonp
def UserInfo():
    samAccountName = request.args.get('samAccountName')
    domain = request.args.get('domain')
    last_exception = None

    if samAccountName and domain:
        try:
            domain_objs = []
            with open(domain_config_file, 'r') as f:
                line = f.readline()
                while line:
                    line_domain = line.split('|')[1]
                    line_base_dn = line.split('|')[3].strip()
                    line_ldap_servers = line.split('|')[5].strip().split(';')
                    d = domain_obj(domain=line_domain,base_dn=line_base_dn,ldap_servers=line_ldap_servers[:])
                    domain_objs.append(d)
                    line = f.readline()
            domain_set = [e.serialize() for e in domain_objs]
            domain_check = next((item for item in domain_set if item["domain"] == domain), None)
            if not domain_check:
                return jsonify(success=False,
                               error=("'domain' parameter '" + domain + "' not present in domain_config_file"))
            base_dn = domain_check['base_dn']
            ldap_servers = domain_check['ldap_servers']
            
        except Exception as e:
            return jsonify(success=False,
                    error=("Error loading domain_config_file: " + domain_config_file),
                    exception=str(e))

        # Now try the AD query
        ldap_server_query_success = 0
        for ldap_server in ldap_servers:
            pyad.pyad_setdefaults(ldap_server=ldap_server)
            if ldap_server_query_success == 0:
                try:
                    query_results = []
                    pythoncom.CoInitialize()

                    q = pyad.adquery.ADQuery()
                    q.execute_query(
                                    attributes=["sAMAccountName",
                                                "memberOf",
                                                "cn",
                                                "sn",
                                                "l",
                                                "st",
                                                "title",
                                                "description",
                                                "postalCode",
                                                "physicalDeliveryOfficeName",
                                                "telephoneNumber",
                                                "givenName",
                                                "initials",
                                                "distinguishedName",
                                                "displayName",
                                                "memberOf",
                                                "department",
                                                "company",
                                                "streetAddress",
                                                "targetAddress",
                                                "employeeNumber",
                                                "employeeType",
                                                "name",
                                                "homeDirectory",
                                                "lastLogon",
                                                "pwdLastSet",
                                                "objectSid",
                                                "userPrincipalName",
                                                "lastLogonTimestamp",
                                                "mail",
                                                "departmentNumber",
                                                "ADsPath"],
                                    where_clause="samAccountName = '{}'".format(samAccountName),
                                    base_dn=base_dn
                                )
                    
                    if q.get_row_count() == 0:
                        ldap_server_query_success = 1
                        return jsonify(success=False,
                                samAccountName=samAccountName,
                                domain=domain,
                                ldap_server=ldap_server,
                                error='No rows returned from adsi query')
                    
                    cn = None
                    group_count = 0
                    groups = []
                    for row in q.get_results():
                        for attr in row:
                            if attr == 'cn':
                                cn = str(row[attr])
                            if attr == 'sn':
                                sn = str(row[attr])
                            if attr == 'l':
                                l = str(row[attr])
                            if attr == 'st':
                                st = str(row[attr])
                            if attr == 'title':
                                title = str(row[attr])
                            if attr == 'description':
                                description = str(row[attr])
                            if attr == 'postalCode':
                                postalCode = str(row[attr])
                            if attr == 'physicalDeliveryOfficeName':
                                physicalDeliveryOfficeName = str(row[attr])
                            if attr == 'telephoneNumber':
                                telephoneNumber = str(row[attr])
                            if attr == 'givenName':
                                givenName = str(row[attr])
                            if attr == 'initials':
                                initials = str(row[attr])
                            if attr == 'distinguishedName':
                                distinguishedName = str(row[attr])
                            if attr == 'displayName':
                                displayName = str(row[attr])
                            if attr == 'department':
                                department = str(row[attr])
                            if attr == 'company':
                                company = str(row[attr])
                            if attr == 'streetAddress':
                                streetAddress = str(row[attr])
                            if attr == 'targetAddress':
                                targetAddress = str(row[attr])
                            if attr == 'employeeNumber':
                                employeeNumber = str(row[attr])
                            if attr == 'employeeType':
                                employeeType = str(row[attr])
                            if attr == 'name':
                                name = str(row[attr])
                            if attr == 'homeDirectory':
                                homeDirectory = str(row[attr])
                            if attr == 'lastLogon':
                                lastLogon = pyad.pyadutils.convert_datetime(row[attr])
                            if attr == 'pwdLastSet':
                                pwdLastSet = pyad.pyadutils.convert_datetime(row[attr])
                            if attr == 'objectSid':
                                objectSid = str(row[attr].tobytes())
                            if attr == 'userPrincipalName':
                                userPrincipalName = str(row[attr])
                            if attr == 'lastLogonTimestamp':
                                lastLogonTimestamp = pyad.pyadutils.convert_datetime(row[attr])
                            if attr == 'mail':
                                mail = str(row[attr])
                            if attr == 'departmentNumber':
                                departmentNumber = str(row[attr])
                            if attr == 'ADsPath':
                                ADsPath = str(row[attr])
                            if attr == 'memberOf':
                                for member in row[attr]:
                                    full_cn = member
                                    member_of_group = member.split(',')[0].split('=')[1]
                                    groups.append({
                                                    "group":member_of_group,
                                                    "full_cn":full_cn
                                    })
                                    group_count = group_count + 1

                    if not cn:
                        ldap_server_query_success = 1
                        pythoncom.CoUninitialize()
                        return jsonify(success=False,
                                    error="samAccountName not found",
                                    samAccountName=samAccountName,
                                    domain=domain,
                                    ldap_server=ldap_server,
                                    )

                    pythoncom.CoUninitialize()
                    ldap_server_query_success = 1
                    return jsonify(success=True,
                                sAMAccountName=samAccountName,
                                domain=domain,
                                memberOf=[e for e in groups],
                                cn=cn,
                                sn=sn,
                                l=l,
                                st=st,
                                title=title,
                                description=description,
                                postalCode=postalCode,
                                physicalDeliveryOfficeName=physicalDeliveryOfficeName,
                                telephoneNumber=telephoneNumber,
                                givenName=givenName,
                                initials=initials,
                                distinguishedName=distinguishedName,
                                displayName=displayName,
                                department=department,
                                company=company,
                                streetAddress=streetAddress,
                                targetAddress=targetAddress,
                                employeeNumber=employeeNumber,
                                employeeType=employeeType,
                                name=name,
                                homeDirectory=homeDirectory,
                                lastLogon=lastLogon,
                                pwdLastSet=pwdLastSet,
                                objectSid=objectSid,
                                userPrincipalName=userPrincipalName,
                                lastLogonTimestamp=lastLogonTimestamp,
                                mail=mail,
                                departmentNumber=departmentNumber,
                                ADsPath=ADsPath,
                                ldap_server=ldap_server,
                                )

                except Exception as e:
                    last_exception = e
                    
            if ldap_server_query_success == 0:
                return jsonify(success=False,
                                samAccountName=samAccountName,
                                domain=domain,
                                ldap_server=ldap_server,
                                error=("Error querying domain controller"),
                                exception=str(last_exception))

    else:
        return jsonify(success=False,
                  error="/UserFullName requires parameter 'samAccountName' and 'domain'")


@app.route("/UserFullName", methods=['GET'])
@jsonp
def UserFullName():
    samAccountName = request.args.get('samAccountName')
    domain = request.args.get('domain')
    
    if samAccountName and domain:
        try:
            domain_objs = []
            with open(domain_config_file, 'r') as f:
                line = f.readline()
                while line:
                    line_domain = line.split('|')[1]
                    line_base_dn = line.split('|')[3].strip()
                    line_ldap_servers = line.split('|')[5].strip().split(';')
                    d = domain_obj(domain=line_domain,base_dn=line_base_dn,ldap_servers=line_ldap_servers[:])
                    domain_objs.append(d)
                    line = f.readline()
            domain_set = [e.serialize() for e in domain_objs]
            domain_check = next((item for item in domain_set if item["domain"] == domain), None)
            if not domain_check:
                return jsonify(success=False,
                               error=("'domain' parameter '" + domain + "' not present in domain_config_file"))
            base_dn = domain_check['base_dn']
            ldap_servers = domain_check['ldap_servers']
            
        except Exception as e:
            return jsonify(success=False,
                    error=("Error loading domain_config_file: " + domain_config_file),
                    exception=str(e))
        
        # Now try the AD query
        ldap_server_query_success = 0
        for ldap_server in ldap_servers:
            pyad.pyad_setdefaults(ldap_server=ldap_server)
            try:
                query_results = []
                pythoncom.CoInitialize()

                q = pyad.adquery.ADQuery()
                q.execute_query(
                                attributes=["sAMAccountName", "displayName"],
                                where_clause="samAccountName = '{}'".format(samAccountName),
                                base_dn=base_dn
                            )
                
                if q.get_row_count() == 0:
                    return jsonify(success=False,
                            samAccountName=samAccountName,
                            domain=domain,
                            ldap_server=ldap_server,
                            error='No rows returned from adsi query')

                last_row = ''
                for row in q.get_results():
                    last_row = row
                FullName = last_row['displayName']


                pythoncom.CoUninitialize()
                ldap_server_query_success = 1
                return jsonify(success=True,
                            displayName=FullName,
                            samAccountName=samAccountName,
                            domain=domain,
                            FullName=FullName,
                            ldap_server=ldap_server)

            except Exception as e:
                last_exception = e

        if ldap_server_query_success == 0:
            return jsonify(success=False,
                    error=("No data returned from querying domain controllers: " + str(ldap_servers)))

    else:
        return jsonify(success=False,
                  error="/UserFullName requires parameter 'samAccountName' and 'domain'")


@app.route("/RunCmd", methods=['GET'])
@jsonp
def RunCmd():
    cmd = request.args.get('cmd')
    
    if cmd:
        try:
            #sys.stderr.write(str(cmd_args))
            proc = subprocess.run(("C:\\Windows\\System32\\cmd.exe /c " + cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            proc_stdout = proc.stdout.decode('ascii')
            proc_stderr = proc.stderr.decode('ascii')
            #print(cmd)

            return jsonify(success=True,
                           cmd=cmd,
                           stdout=proc_stdout,
                           stderr=proc_stderr)

        except Exception as e:
            return jsonify(success=False,
                    error=("Error RunCmd()"),
                    exception=str(e))
    
    else:
        return jsonify(success=False,
                    error=("Error: 'cmd' argument must be provided with each request to RunCmd"),
                    exception="")

@app.route("/ListRoutes", methods=['GET'])
@jsonp
def ListRoutes():
    routes = []

    for rule in app.url_map.iter_rules():
        routes.append('%s' % rule)

    return jsonify(success=True,
                   routes=[e for e in routes])

@app.route("/", methods=['GET'])
@jsonp
def DefaultPath():
    return jsonify(success=True,
                   message='This is the AD query service API, please contact Matthew.Brown.mls@gmail.com with any questions.')

if __name__ == "__main__":
    #app.run(ssl_context='adhoc', debug=True, host='0.0.0.0', port=9990)
    #pythoncom.CoInitialize()
    app.run(debug=True, host='0.0.0.0', port=port)
    #pythoncom.CoUninitialize()