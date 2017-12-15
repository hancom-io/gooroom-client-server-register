"""OpenSSL related object required to obtaion a certificate from the gooroom managerment server.
Written by python3
Make RSA 2048 client key pair and save key pair.
Make csr and singing from client private key and save csr.`
"""
import configparser
import gettext
import grp
import hashlib
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime

import OpenSSL
import requests

gettext.install('gooroom-client-server-register', '/usr/share/gooroom/locale')

class Certification():

    def __init__(self):
        self.result = {'err':None, 'log':[]}
        self.config_dir = '/etc/gooroom/gooroom-client-server-register'
        self.config_file = os.path.join(self.config_dir, 'gcsr.conf')

    def check_data(self):
        "Checking the input data is correct"
        raise NotImplementedError('Implement check data method.')

    def certificate(self):
        "do certificate"
        raise NotImplementedError("Implement certificate method.")

    @staticmethod
    def remove_file(path):
        "remove file if existss"
        if os.path.exists(path):
            os.remove(path)

    def response(self, res):
        """data is response from server
        response type is json type, if not raise error.
        convert to dictionay, then return data"""
        if res.status_code == 200:
            data = res.json()
        else:
            raise ResponseError('Status Code:[{0}], {1}'.format(res.status_code, res.text))

        if data['status']['result'] == 'success':
            return data
        else:
            # fail to get data
            raise ResponseError('Result code:[{0}], {1}'.format(data['status']['resultCode'], data['status']['message']))

    def _save_config(self, section, section_data):
        "Save config file. Section is config section name, section_data is dictionary of section."
        if not os.path.isdir(self.config_dir):
            os.makedirs(self.config_dir)

        config = configparser.ConfigParser()
        config.read(self.config_file)

        config[section] = section_data
        with open(self.config_file, 'w') as conf_file:
            config.write(conf_file)


class ServerCertification(Certification):

    def __init__(self):
        Certification.__init__(self)
        self.root_crt_path = '/usr/local/share/ca-certificates/gooroom_root.crt'
        self.err_msg = _('Fail to register Gooroom Platform Management Server complete.')

    def certificate(self, data):
        try:
            self.result['log'] = [(_('Getting certificate of gooroom root CA...'))]
            self.remove_file(self.root_crt_path)
            self.get_root_certificate(data)
            self.result['log'].append(_('Server registration completed.'))
        except (ConnectionRefusedError, socket.gaierror) as error:
            self.result['err'] = '102'
            self.result['log'].append((type(error), error))
        except Exception as error:
            self.result['err'] = '110'
            self.result['log'].append((type(error), error))
            self.result['log'].append(_('Unknown Error Occurred.'))

        if self.result['err']:
            self.result['log'].append(self.err_msg)

        yield self.result

        try:
            self.result['log'] = [(_('Getting list of Gooroom platform management server...'))]
            self._add_hosts(data['domain'])
            self.result['log'].append(_('List of Gooroom platform management server registration completed.'))
        except (OSError, requests.exceptions.ConnectionError, socket.timeout) as error:
            self.result['err'] = '102'
            self.result['log'].append((type(error), error))
        except ResponseError as error:
            self.result['err'] = '104'
            self.result['log'].append((type(error), error))
        except Exception as error:
            self.result['err'] = '105'
            self.result['log'].append(_('Server response type is wrong. Contact your server administrator.'))
            self.result['log'].append((type(error), error))

        if self.result['err']:
            self.result['log'].append(self.err_msg)

        yield self.result

    def check_data(self, data):
        if data['path']:
            if not os.path.exists(data['path']):
                # Error
                self.result['err'] = '101'
                self.result['log'].append(_('Certificate path of gooroom root CA is not exists.'))
                return

        self.result['log'].append(_('Start server registering.'))

    def get_root_certificate(self, data):
        """data['path'] distinguish how to get the root certificate.
         True: get root certificate from local.
        False : get root certificate from server certificate chain."""
        domain = data['domain']
        local_crt_path = data['path']
        if local_crt_path:
            # get root certificate from local path
            # TODO: need to verify certificate
            shutil.copy(local_crt_path, self.root_crt_path)
        else:
            # get root certificate from gooroom key server certificate chain
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((domain, 443))

            ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            ssl_conn = OpenSSL.SSL.Connection(ssl_context, s)
            ssl_conn.set_connect_state()
            ssl_conn.set_tlsext_host_name(bytes(domain.encode('utf-8')))
            tries = 0
            while True:
                try:
                    ssl_conn.do_handshake()
                    break
                except OpenSSL.SSL.WantReadError:
                    tries += 1
                    if tries >= 5:
                        raise
                    time.sleep(0.1)

            certs = ssl_conn.get_peer_cert_chain()
            server_crt = ssl_conn.get_peer_certificate()
            server_crt = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, server_crt)

            # TODO: register all key chain
            root_crt = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certs[-1])

            with open(self.root_crt_path, 'wb') as f:
                f.write(root_crt)

            self._update_ca_certificate()

    def _update_ca_certificate(self):
        """address is (domain or IP) or certificate path
        seperated by server_crt_flag
        """
        update = ['update-ca-certificates', '--fresh']
        subprocess.check_output(update, shell=False)

    def _add_hosts(self, domain):
        """Get server list and /etc/hosts file from server.
        write /etc/hosts
        write config"""
        url = 'https://%s/gkm/v1/gpms' % domain
        res = requests.get(url, timeout=5)

        response_data = self.response(res)
        gpms = response_data['data'][0]

        modify_date = int(gpms['modifyDate']) / 1000
        modify_date = datetime.strftime(datetime.utcfromtimestamp(modify_date),
            ' %Y-%m-%d %H:%M:%S')

        with open('/etc/hosts', 'r') as f:
            lines = f.readlines()

        hosts = ''
        parsing = True
        for line in lines:
            if line == '### Auto Generated by gcsr\n':
                parsing = False
            elif line.endswith('End gcsr\n'):
                parsing = True
                continue

            if parsing:
                hosts += line

        domain_datas = {}
        hosts += '### Auto Generated by gcsr\n'
        server_urls = [x for x in gpms if x.endswith('Url')]
        for server_url in server_urls:
            server_name = server_url.replace('Url', '')
            server_ip = server_name + 'Ip'
            hosts += '{0}\t{1}\n'.format(gpms[server_ip], gpms[server_url])
            domain_datas[server_name] = gpms[server_url]

        hosts += '### Modify {} End gcsr\n'.format(modify_date)

        with open('/etc/hosts', 'w') as f:
            f.write(hosts)

        self._save_config(section='domain', section_data=domain_datas)


class ClientCertification(Certification):

    def __init__(self, domain):
        Certification.__init__(self)
        self.domain = domain
        self.client_crt = '/etc/ssl/certs/gooroom_client.crt'
        self.client_key = '/etc/ssl/private/gooroom_client.key'

    def check_data(self, data):
        self.result['log'].append(_('Requesting client certificate.'))

        if not data['cn']:
            self.result['err'] = '101'
            self.result['log'].append(_('Check the client name.'))
        elif not data['ou']:
            self.result['err'] = '101'
            self.result['log'].append(_('Check the organizational unit.'))
        elif not data['user_id']:
            self.result['err'] = '101'
            self.result['log'].append(_('Check the gooroom admin ID.'))
        elif not data['user_pw']:
            self.result['err'] = '101'
            self.result['log'].append(_('Check the password.'))
        elif data['valid_date']:
            try:
                datetime.strptime(data['valid_date'], '%Y-%m-%d')
            except ValueError:
                self.result['err'] = '101'
                self.result['log'].append(_('Incorrect date format, should be YYYY-MM-DD'))

    def hash_password(self, **kargs):
        """
        Password hash algorithms are required depending on the settings of gpms.
        Argument: kargs(password, salt, etc...)

        Return: hashed password(str)
        """
        hash_tmp = hashlib.sha256(kargs['password'].encode()).hexdigest()

        return hashlib.sha256((kargs['id']+hash_tmp).encode()).hexdigest()

    def certificate(self, data):
        self.check_data(data)
        yield self.result

        self.remove_file(self.client_key)
        csr, private_key = self.generate_csr(data['cn'], data['ou'])
        data['csr'] = csr
        url = 'https://%s/gkm/v1/client/register' % self.domain

        self.result['log'] = []

        data['user_pw'] = self.hash_password(id=data['user_id'],
                                             password=data['user_pw'])

        try:
            res = requests.post(url, data=data, timeout=30)
            response_data = self.response(res)
            # save crt
            with open(self.client_crt, 'w') as f:
                f.write(response_data['data'][0]['certInfo'])
                del response_data['data'][0]['certInfo']

            self.__save_key(private_key)
            del private_key

            self.result['log'].append(response_data['status']['message'])
            self.result['log'].append(response_data['data'][0])
        except ResponseError as error:
            self.result['err'] = '104'
            self.result['log'].append(_('Client certificate issue failed.'))
            self.result['log'].append((type(error), error))
        except Exception as error:
            self.result['err'] = '105'
            self.result['log'].append(_('Server response type is wrong. Contact your server administrator.'))
            self.result['log'].append((type(error), error))
        else:
            self._save_config('certificate', self.get_certificate_data(data['cn'], data['ou'], data['password_system_type']))
            self.result['log'].append(_('Client registration completed.'))

        yield self.result

    def __generate_key(self):
        """Generate key using gooroom client rsa/2048 key pair"""
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        private_key = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key)
        self.__save_key(private_key)

        return key, private_key

    def __save_key(self, private_key):
        """save key and change owner.
        Return ssl privite path
        """
        ssl_cert_gid = grp.getgrnam('ssl-cert').gr_gid

        with open(self.client_key, 'wb') as key_file:
            key_file.write(private_key)

        shutil.chown(self.client_key, group=ssl_cert_gid)
        os.chmod(self.client_key, 0o640)

    def generate_csr(self, common_name, organizational_unit):
        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = common_name
        req.get_subject().OU = organizational_unit

        key, private_key = self.__generate_key()
        req.set_pubkey(key)
        req.sign(key, 'sha256')
        del key

        csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
        # Do not save csr
        return csr, private_key

    def get_certificate_data(self, client_name, organizational_unit, password_system_type):
        "Return certificate section data of gcsr.config"
        sc = ServerCertification()
        certificate_data = {'organizational_unit':organizational_unit,
            'password_system_type':password_system_type.lower(),
            'client_crt':self.client_crt,
            'client_name':client_name,
            'server_crt':sc.root_crt_path}

        return certificate_data

class ResponseError(Exception):
    pass
