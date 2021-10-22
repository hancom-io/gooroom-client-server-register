#!/usr/bin/python3
import configparser
import sys
import subprocess
import os
import argparse
gcsr_auto_conf_file = '/etc/gooroom/gooroom-client-server-register/gcsr_auto.conf'
gcsr_conf_file = '/etc/gooroom/gooroom-client-server-register/gcsr.conf'
def config_read():
    config = configparser.ConfigParser()
    config.read(gcsr_auto_conf_file, encoding='utf-8')
    try:
        autoreg = config['autoreg']
        gkm_server = autoreg['gkm_server']
        reg_key = autoreg['reg_key']
    except Exception as error:
        sys.exit("Not exist gcsr_auto.conf : %s" % error)
    gkm_ip = ''
    try:
        gkm_ip = autoreg['gkm_ip']
    except Exception as error:
        with open('/etc/hosts', 'r') as f:
            lines = f.readlines()
        for line in lines:
            host = line.split()
            if len(host) < 2:
                continue
            if host[1].lower() == gkm_server.lower():
                gkm_ip = host[0]
                break
    if gkm_server and gkm_ip and reg_key :
        return gkm_server, gkm_ip, reg_key
    else:
        sys.exit("gkm_ip is not entered")
def check_registered():
    try:
        config = configparser.ConfigParser()
        re = config.read(gcsr_conf_file, encoding='utf-8')
        if not re:
            return
        certificate = config['certificate']
        if len(certificate['client_name']) > 0:
            remove_auto_conf()
            sys.exit("Already registered")
        else:
            return
    except Exception as error:
        print('before registered :', error)
        return
def remove_auto_conf():
    os.remove(gcsr_auto_conf_file)
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--option', '-o', help='Actiave gooroom-agent after registering', dest='option')
    option_list = parser.parse_args().option
    return option_list
if __name__ == '__main__':
    '''
    main
    '''
    option_list = get_arguments()
    gkm_server, gkm_ip, reg_key = config_read()
    check_registered()
    cmd = 'gooroom-client-server-register noninteractive-regkey -d %s -I %s -k %s' %(gkm_server, gkm_ip, reg_key)
    subprocess.run(cmd, shell=True)
    remove_auto_conf()
    if option_list != 'DONOTTOUCH_AGENT':
        cmd = 'systemctl enable gooroom-agent'
        subprocess.run(cmd, shell=True)
        cmd = 'systemctl start gooroom-agent'
        subprocess.run(cmd, shell=True)
