#!/usr/bin/python
# -*- coding: utf-8 -*-

#######################################################
# autotransfer (domain,path,ssl,php) script for whm/cpanel(cloudlinux)
#
# Written by : maksim sasov (maksim.sasov@hoster.by)
# Created date: Nov 06, 2019
# Tested with : Python 2.7.15
# Script Revision: v2.0 (beta)
#######################################################

from urllib2 import urlopen
from xml.dom import minidom
from collections import Counter
from collections import defaultdict
import os, re, sys, time
import subprocess
from subprocess import PIPE, Popen
import pipes
import simplejson as json
import socket
import ssl

global search_account, domain, command_output, list_raw, list_account, cloud_ip, cloud_pass

userdata = '/etc/userdatadomains.json'
file_read = open(userdata).read()
list_raw = json.loads(file_read)
list_account=list_raw.keys()
key_pub = '/root/.ssh/id_rsa.pub'
key_priv ='/root/.ssh/id_rsa'
getkey = 'cat /root/.ssh/id_rsa.pub'
getauth = 'cat /root/.ssh/authorized_keys'


def Check_authorized_keys(cmd, cloud_ip):
    cmd = '''ssh-copy-id root@%s '''%(cloud_ip)
    with open(os.devnull, "w") as fnull:
        subprocess.call(cmd.split(), stdout = fnull, stderr = fnull)
    print '\033[92m Installed authorized key to server\033[0m \033[93m %s \033[0m\n' %(cloud_ip)


def Local(cmd, key_pub, key_priv):
    global checker
    if (os.path.exists(key_pub) == False) and (os.path.exists(key_priv) == True):
        checker=1
        print("\033[91m Not found id_rsa.pub on this server\033[0m")
        cmd_keygen = ("ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub")
        subprocess.call(cmd_keygen, shell=True)
        print("\033[92m Created id_rsa.pub for this server\033[0m")
        lines = subprocess.check_output(cmd.split())
        return '\n'.join(lines)
    elif (os.path.exists(key_pub) == False) and (os.path.exists(key_priv) == False):
        print ("\033[91m Public and Private Key not found on this server! Need to generate a SSH keys\033[0m")
        sys.exit()
    else:
        checker=0
        lines = subprocess.check_output(cmd.split())
        return '\n'.join(lines)

sourcekey = Local(getkey, key_pub, key_priv).replace('\n','').strip()
keycmd='''echo "%s" >>/root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys '''%(sourcekey)


def sync(user_domains,cloud_domains,keycmd,cloud_ip):
    global key_pub
    Check_authorized_keys(keycmd, cloud_ip)
    del user_domains['parked']
    LISTPARAMETR = " --no-perms --no-owner --no-group --size-only " # first sycn for all cms
    #LISTPARAMETR = " --no-perms --no-owner --no-group --size-only --delete --exclude file1.txt" # last sync exclude 'file'
    #LISTPARAMETR = " --no-links --no-perms --no-owner --no-group --size-only --delete"  # for last sync bitrix
    #LISTPARAMETR = "--no-perms --no-owner --no-group --size-only --delete --exclude=cache/ --exclude=managed_cache/"  # first sync for bitrix
    for domain, atr in user_domains.items():
        print '\033[96m Sync %s => %s \033[0m' %(atr[1], cloud_domains[domain][0])
        cmd = ("rsync -azP --stats %s %s root@%s:%s" %(LISTPARAMETR, atr[1], cloud_ip, cloud_domains[domain][0]))
        proc = Popen(cmd.split(),stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        res = proc.communicate()
        if proc.returncode != 0:
            print '\033[91m %s\n Error \033[0m\n' %(''.join(res))
        else:
            print '\033[92m Success! \033[0m\n'
    if os.path.isfile(key_pub) and checker==1:
        os.remove(key_pub)
        print("\033[92m Deleted id_rsa.pub for this server\033[0m")
    report(user_domains)


def add_to_isp(user_domains, search_account, cloud_ip, cloud_pass):
    php = ''.join(re.findall(r'^\d\.\d',os.popen('/usr/bin/selectorctl --user-current --user=%s' %(search_account)).read()))
    php = re.sub(r'\.','',php)
    if (not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None)):
        ssl._create_default_https_context = ssl._create_unverified_context
    cloud_domains = defaultdict(list)
    for domain, path_type in user_domains.items():
        cloud_domains[domain].append('/var/www/www-root/data/www/%s' %(domain))
        if user_domains[domain][0] == "main":
            mysql_backup_path = path_type[1] + 'mysql_bakups'
            parked = ('%20'.join(user_domains['parked']))
            out = urlopen('https://{3}:1500/ispmgr?authinfo=root:{4}&func=webdomain.edit&name={0}&aliases=www.{0}%20{1}&owner=www-root&home=www/{0}&php_mode=php_mode_fcgi_apache&php_cgi_version=isp-php{2}&email=webmaster@{0}&srv_gzip=on&gzip_level=5&srv_cache=on&expire_times=expire_times_d&expire_period=30&out=xml&sok=ok'.format(domain, parked, php, cloud_ip, cloud_pass))
        else:
            out = urlopen('https://{2}:1500/ispmgr?authinfo=root:{3}&func=webdomain.edit&name={0}&owner=www-root&home=www/{0}&php_mode=php_mode_fcgi_apache&php_cgi_version=isp-php{1}&email=webmaster@{0}&srv_gzip=on&gzip_level=5&srv_cache=on&expire_times=expire_times_d&expire_period=30&out=xml&sok=ok'.format(domain, php, cloud_ip, cloud_pass))
    try:
       os.stat(mysql_backup_path)
    except:
       os.mkdir(mysql_backup_path)
    listdbs = os.popen('/usr/bin/cpapi2 --user=%s MysqlFE listdbs'%(search_account)).read()
    result = re.findall(r'(db:\s\w+\b\n\s+user:\s\w+\b)',listdbs)
    mysql_list = {}
    for i in result:
        i = re.sub(r'\n',',',i)
        i = re.sub(r'\s','',i)
        i = re.sub(r'(db:|user:)','',i)
        mysql_list.update([[x[:] for x in i.split(',')], ])
    for db, user_db in mysql_list.items():
        try:
            out = urlopen('https://{0}:1500/ispmgr?authinfo=root:{1}&func=db.edit&name={2}&username={3}&password=QwerTy12w23e21&confirm=q12wQ!@W&out=xjson&sok=ok'.format(cloud_ip, cloud_pass, db, user_db))
        except:
            print('База', db, 'не создана')
        print '\033[92mCreating backup database: \033[0m',db
        dumpcmd = "mysqldump " + db + " > " + mysql_backup_path + "/" + db + ".sql"
        os.system(dumpcmd)
        print '\033[92m Success! \033[0m\n'
    sync(user_domains,cloud_domains,keycmd,cloud_ip)


def check_info(search_account):
    user_domains = defaultdict(list)
    for acc in list_account:
        if ((list_raw[acc][0]) == search_account):
            if (list_raw[acc][2] == 'sub') and ((acc == ''.join(re.findall(acc,list_raw[acc][4]))) or re.findall(r'public_html',list_raw[acc][4])):
                 user_domains[acc].append('sub')
                 user_domains[acc].append(list_raw[acc][4]+'/')
            elif list_raw[acc][2] == 'main':
                 user_domains[acc].append('main')
                 main_domain = acc
                 user_domains[acc].append(list_raw[acc][4]+'/')
            elif list_raw[acc][2] == 'addon':
                 user_domains[acc].append('addon')
                 user_domains[acc].append(list_raw[acc][4]+'/')
            elif list_raw[acc][2] == 'parked':
                 user_domains['parked'].append(acc)

    add_to_isp(user_domains, search_account, cloud_ip, cloud_pass)


def report(user_domains):
    for domain, atr in user_domains.items():
        if os.path.exists("/var/cpanel/ssl/apache_tls/%s/combined" %(domain)):
            print '\033[93m SSL certificate for %s \033[0m\n'%(domain)
            with open(r"/var/cpanel/ssl/apache_tls/%s/combined"%(domain), "r+") as f:
                d = f.readlines()
                f.seek(0)
                ssl= ''
                for line in d:
                    ssl += line
            print ssl,'\n'


def start():
    global cloud_ip, cloud_pass
    while True:
        domain = raw_input('Enter domain name: ')
        #domain = 'iknow.of.by'
        domain = ' '.join(domain.split())
        domain = domain.strip()
        search_account = os.popen('/usr/local/cpanel/scripts/whoowns %s' %(domain)).read()
        search_account = search_account.strip('\n')
        if len(search_account)==0:
           print '\033[91mDomain \033[0m',domain,' \033[91mnot found on this server!\033[0m'
        else:
           break
    cloud_ip = raw_input('Enter IP adress cloud server: ')
    cloud_pass = raw_input('Enter pass(root): ')
    cloud_ip = ' '.join(cloud_ip.split())
    cloud_ip = cloud_ip.strip()
    cloud_pass = ' '.join(cloud_pass.split())
    cloud_pass = cloud_pass.strip()
    #cloud_ip = '178.172.137.151'
    #cloud_pass = 'PkKzKX7HxO2f'
    check_info(search_account)

if __name__ == '__main__':
    start()
