#!/usr/bin/python3
import gettext
import os
import getpass
import pprint
import threading
import time
import copy
import hashlib
import codecs

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gdk, Gtk

import certification
import subprocess

from pwd import getpwnam

gettext.install("gooroom-client-server-register", "/usr/share/gooroom/locale")

class RegisterThread(threading.Thread):
    def __init__(self, datas, application):
        threading.Thread.__init__(self)
        self.datas = datas
        self.application = application

    def result_format(self, result):
        "Return result log pretty"
        result_text = ''
        for text in result:
            result_text += pprint.pformat(text) + '\n'

        return result_text

    def run(self):
        try:
            textbuffer = self.application.builder.get_object('textbuffer_result')
            client_data = next(self.datas)
            server_certification = self.application.server_certification
            sc = server_certification.certificate(client_data)
            for server_result in sc:
                result_text = self.result_format(server_result['log'])
                current_text = textbuffer.get_text(textbuffer.get_start_iter(),
                    textbuffer.get_end_iter(),
                    True)

                Gdk.threads_enter()
                textbuffer.set_text('{0}\n{1}'.format(current_text, result_text))
                Gdk.threads_leave()

                if server_result['err']:
                    raise Exception

            server_data = next(self.datas)
            client_certification = certification.ClientCertification(client_data['domain'])
            cc = client_certification.certificate(server_data)
            for client_result in cc:
                result_text = self.result_format(client_result['log'])
                current_text = textbuffer.get_text(textbuffer.get_start_iter(),
                    textbuffer.get_end_iter(),
                    True)

                Gdk.threads_enter()
                textbuffer.set_text('{0}\n{1}'.format(current_text, result_text))
                Gdk.threads_leave()
                if client_result['err']:
                    raise Exception
        except Exception as e:
            Gdk.threads_enter()
            self.application.builder.get_object('button_prev2').set_sensitive(True)
            Gdk.threads_leave()
            print(type(e), e)
        finally:
            Gdk.threads_enter()
            self.application.builder.get_object('button_ok').set_sensitive(True)
            Gdk.threads_leave()

class Registering():
    "Registering parent class"
    def __init__(self):
        self.WORK_DIR = '/usr/lib/gooroom/gooroomClientServerRegister'

    def result_format(self, result):
        "Return result log pretty"
        # TODO: formatting more pretty
        result_text = ''
        for text in result:
            result_text += pprint.pformat(text) + '\n'

        return result_text

    def make_hash_cn(self):
        cmd = subprocess.run(['/usr/sbin/dmidecode', '-s', 'system-serial-number'], stdout=subprocess.PIPE, universal_newlines=True)
        result = cmd.stdout.rstrip() + '/'
        cmd = subprocess.run(['/usr/sbin/dmidecode', '-s', 'system-uuid'], stdout=subprocess.PIPE, universal_newlines=True)
        result += cmd.stdout.rstrip() + '/'
        cmd = subprocess.run(['/usr/sbin/dmidecode', '-s', 'baseboard-serial-number'], stdout=subprocess.PIPE, universal_newlines=True)
        result += cmd.stdout.rstrip()
        hash_result = hashlib.md5(result.encode()).hexdigest()
        base64_result = codecs.encode(codecs.decode(hash_result, 'hex'), 'base64').decode().rstrip()
        return base64_result

    def make_mac(self):
        """
        make cn with sn + mac
        """

        ENP_PATH = '/sys/class/net/enp0s3/address'
        if os.path.exists(ENP_PATH):
            with open(ENP_PATH) as f:
                cn = f.read().strip('\n').replace(':', '')
                print('enp0s3={}'.format(cn))
                return cn
        else:
            import glob
            ifaces = [i for i in glob.glob('/sys/class/net/*')]
            ifaces.sort()
            for iface in ifaces:
                if iface == '/sys/class/net/lo':
                    continue
                with open(iface+'/address') as f2:
                    cn = f2.read().strip('\n').replace(':', '')
                    print('iface={}'.format(cn))
                    return cn
            return 'CN-NOT-FOUND-ERROR'

    def make_cn(self):

        CN_PATH = '/etc/gooroom/gooroom-client-server-register/gcsr.conf'
        if os.path.exists(CN_PATH):
            try:
                import configparser
                parser = configparser.RawConfigParser()
                parser.optionxform = str
                parser.read(CN_PATH)
                cn = parser.get('certificate', 'client_name').strip().strip('\n')
                print('gcsr.conf={}'.format(cn))
                return cn
            except:
                pass

        cn = self.make_mac()
        return cn + self.make_hash_cn()

    def make_ipname(self):
        """
        make name with IP
        """
        return os.popen('hostname --all-ip-addresses').read().split(' ')[0]

    def make_ipv6name(self):
        """
        make name with IPv6
        """
        return os.popen('/sbin/ip -6 addr | grep inet6 | awk -F \'[ \t]+|/\' \'{print $3}\' | grep -v ^::1').read().split('\n')[0]

class GUIRegistering(Registering):
    def __init__(self):
        Registering.__init__(self)
        Gdk.threads_init()
        glade_file = "%s/gooroomClientServerRegister.glade" % self.WORK_DIR
        self.builder = Gtk.Builder()
        self.builder.add_from_file(glade_file)

        self.window = self.builder.get_object('window1')
        self.window.set_default_size(600, 380)
        self.window.set_title(_('Gooroom Client Server Register'))
        self.window.set_icon_name('gooroom-client-server-register')
        self.window.set_position(Gtk.WindowPosition.CENTER)

        self.builder.get_object('label_subtitle1').set_text(_("Register Gooroom Root CA in the client.\nAnd, add gooroom platform management servers from the server."))
        self.builder.get_object('label_cert_type').set_text(_('How to regist certificate'))
        self.builder.get_object('radiobutton_create').set_label(_('Create'))
        self.builder.get_object('radiobutton_update').set_label(_('Update'))
        self.builder.get_object('radiobutton_create_or_update').set_label(_('Create or Update'))
        self.builder.get_object('checkbutton_hosts').set_label(_('Record in /etc/hosts'))
        self.builder.get_object('label_address').set_text(_('GKM'))
        self.builder.get_object('label_path').set_text(_('(Option)Select the certificate path of gooroom root CA'))
        self.builder.get_object('entry_address').set_placeholder_text(_('Enter the domain name'))
        self.builder.get_object('entry_file').set_text('')
        self.builder.get_object('button_browse').set_label(_('browse...'))
        self.builder.get_object('button_register').set_label(_('Register'))
        self.builder.get_object('label_subtitle2').set_text(_('Generate a certificate signing request(CSR) based on the input value\nto receive a certificate from the server.'))
        self.builder.get_object('label_cn').set_text(_('Client ID'))
        self.builder.get_object('label_name').set_text(_('Client name'))
        self.builder.get_object('entry_name').set_placeholder_text(self.make_ipname())
        self.builder.get_object('entry_name').set_text(self.make_ipname())
        self.builder.get_object('label_classify').set_text(_('Client organizational unit'))
        self.builder.get_object('label_date').set_text(_('(Option)Certificate expiration date'))

        self.builder.get_object('label_id').set_text(_('Gooroom admin ID'))
        self.builder.get_object('label_password').set_text(_('Password'))
        self.builder.get_object('label_comment').set_text(_('(Option)Comment'))
        self.builder.get_object('label_detail').set_text(_('Send the request to the gooroom platform management server.'))
        self.builder.get_object('label_result').set_text(_('Result data'))

        self.builder.get_object('button_next').connect('clicked', self.next_page)
        self.builder.get_object('button_prev1').connect('clicked', self.prev_page)
        self.builder.get_object('button_prev2').connect('clicked', self.prev_page)
        self.builder.get_object('button_browse').connect('clicked', self.file_browse)
        self.builder.get_object('button_register').connect('clicked', self.register)
        self.builder.get_object('button_ok').connect('clicked', Gtk.main_quit)
        self.builder.get_object('button_close1').connect('clicked', Gtk.main_quit)
        self.builder.get_object('button_close2').connect('clicked', Gtk.main_quit)

        self.builder.get_object('checkbutton_hosts').connect('toggled', self.on_checkbutton_hosts_toggled)

        self.builder.get_object('radiobutton_idpw').set_label(_('ID/PW'))
        self.builder.get_object('radiobutton_idpw').connect('toggled', self.on_radiobutton_idpw_clicked)
        self.builder.get_object('radiobutton_regkey').set_label(_('REGKEY'))
        self.builder.get_object('radiobutton_regkey').connect('toggled', self.on_radiobutton_regkey_clicked)
        self.builder.get_object('label_regkey').set_text(_('REGKEY'))

        self.builder.get_object('entry_cn').set_text(self.make_cn())
        self.builder.get_object('entry_cn').set_sensitive(False)

        self.builder.get_object('radiobutton_create_or_update').set_sensitive(False)

        #save widget for inserting or removing grid rows when switching idpw and regkey
        self.label_id = self.builder.get_object('label_id')
        self.entry_id = self.builder.get_object('entry_id')
        self.label_password = self.builder.get_object('label_password')
        self.entry_password = self.builder.get_object('entry_password')
        self.label_regkey = self.builder.get_object('label_regkey')
        self.entry_regkey = self.builder.get_object('entry_regkey')
        self.label_date = self.builder.get_object('label_date')
        self.entry_date = self.builder.get_object('entry_date')
        self.builder.get_object('grid2').remove_row(10)

        #save widget for inserting or removing grid rows when switching cert-reg-type
        self.label_classify = self.builder.get_object('label_classify')
        self.entry_classify = self.builder.get_object('entry_classify')
        self.label_name = self.builder.get_object('label_name')
        self.entry_name = self.builder.get_object('entry_name')

        self.server_certification = certification.ServerCertification()

        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show_all()
        Gdk.threads_enter()
        Gtk.main()
        Gdk.threads_leave()

    def on_radiobutton_idpw_clicked(self, obj):
        """
        """

        if not obj.get_active():
            return

        grid = self.builder.get_object('grid2')
        grid.remove_row(7)
        grid.remove_row(7)
        grid.remove_row(7)
        grid.insert_row(7)
        grid.insert_row(8)
        grid.insert_row(9)
        grid.attach(self.label_id, 0, 7, 1, 1)
        grid.attach(self.entry_id, 1, 7, 1, 1)
        grid.attach(self.label_password, 0, 8, 1, 1)
        grid.attach(self.entry_password, 1, 8, 1, 1)
        grid.attach(self.label_date, 0, 9, 1, 1)
        grid.attach(self.entry_date, 1, 9, 1, 1)
        self.window.show_all()

    def on_radiobutton_regkey_clicked(self, obj):
        """
        """

        if not obj.get_active():
            return

        grid = self.builder.get_object('grid2')
        grid.remove_row(7)
        grid.remove_row(7)
        grid.remove_row(7)
        grid.insert_row(7)
        grid.insert_row(8)
        grid.insert_row(9)
        grid.attach(self.label_regkey, 0, 7, 1, 1)
        grid.attach(self.entry_regkey, 1, 7, 1, 1)
        lbl0 = Gtk.Label()
        lbl1 = Gtk.Label()
        lbl2 = Gtk.Label()
        lbl3 = Gtk.Label()
        grid.attach(lbl0, 0, 8, 1, 1)
        grid.attach(lbl1, 1, 8, 1, 1)
        grid.attach(lbl2, 0, 9, 1, 1)
        grid.attach(lbl3, 1, 9, 1, 1)
        self.window.show_all()

    def on_checkbutton_hosts_toggled(self, obj):
        """
        toggle hosts checkbutton
        """

        grid = self.builder.get_object('grid_serverinfo')
        if obj.get_active():
            gkm_ip = Gtk.Entry()
            gkm_ip.set_placeholder_text(_('Enter ip address'))

            glm_domain = Gtk.Label()
            glm_domain.set_text(_('This domain is set on the GPMS'))
            glm_ip = Gtk.Entry()
            glm_ip.set_placeholder_text(_('Enter ip address'))
            glm_label = Gtk.Label()
            glm_label.set_text(_('GLM'))

            grm_domain = Gtk.Label()
            grm_domain.set_text(_('This domain is set on the GPMS'))
            grm_ip = Gtk.Entry()
            grm_ip.set_placeholder_text(_('Enter ip address'))
            grm_label = Gtk.Label()
            grm_label.set_text(_('GRM'))

            gpms_domain = Gtk.Label()
            gpms_domain.set_text(_('This domain is set on the GPMS'))
            gpms_ip = Gtk.Entry()
            gpms_ip.set_placeholder_text(_('Enter ip address'))
            gpms_label = Gtk.Label()
            gpms_label.set_text(_('GPMS'))

            grid.attach(gkm_ip, 2, 1, 1 ,1)
            grid.attach(glm_label, 0, 2, 1 ,1)
            grid.attach(glm_domain, 1, 2, 1 ,1)
            grid.attach(glm_ip, 2, 2, 1 ,1)
            grid.attach(grm_label, 0, 3, 1 ,1)
            grid.attach(grm_domain, 1, 3, 1 ,1)
            grid.attach(grm_ip, 2, 3, 1 ,1)
            grid.attach(gpms_label, 0, 4, 1 ,1)
            grid.attach(gpms_domain, 1, 4, 1 ,1)
            grid.attach(gpms_ip, 2, 4, 1 ,1)
            self.window.show_all()
        else:
            grid.remove_row(4)
            grid.remove_row(3)
            grid.remove_row(2)
            grid.remove_column(2)
            self.window.resize(600, 380)
            self.window.show_all()

    def next_page(self, button):
        "After check empty information, do next page."
        current_page = self.builder.get_object('notebook').get_current_page()
        if current_page == 0:
            if not self.builder.get_object('entry_address').get_text():
                self.show_info_dialog(_('Please enter the domain'))
                return
            checkbutton_hosts = self.builder.get_object('checkbutton_hosts')
            if checkbutton_hosts.get_active():
                grid_serverinfo = self.builder.get_object('grid_serverinfo')
                gkm_ip = grid_serverinfo.get_child_at(2, 1).get_text()
                if not gkm_ip:
                    self.show_info_dialog(_('GKM ip adress must be present'))
                    return

            domain = self.builder.get_object('entry_address').get_text()
            path = self.builder.get_object('entry_file').get_text()
            serverinfo = self.get_serverinfo()
            server_certification = self.server_certification
            server_certification.add_hosts_gkm(serverinfo)
            try:
                for ip_type in server_certification.get_root_certificate({'domain':domain, 'path':path}):
                    self.ip_type=ip_type
            except:
                self.show_info_dialog(_('Authentication server connection failed.\n'\
                                        'Check the connection information and network status.'))
                raise

            grid = self.builder.get_object('grid2')
            if self.builder.get_object('radiobutton_update').get_active():
                grid.remove_row(3)
                grid.remove_row(3)
                grid.insert_row(3)
                grid.insert_row(4)
                lbl0 = Gtk.Label()
                lbl1 = Gtk.Label()
                grid.attach(self.label_name, 0, 3, 1, 1)
                grid.attach(lbl0, 1, 3, 1, 1)
                grid.attach(self.label_classify, 0, 4, 1, 1)
                grid.attach(lbl1, 1, 4, 1, 1)
                self.window.show_all()
            else:
                grid.remove_row(3)
                grid.remove_row(3)
                grid.insert_row(3)
                grid.insert_row(4)
                grid.attach(self.label_name, 0, 3, 1, 1)
                grid.attach(self.entry_name, 1, 3, 1, 1)
                grid.attach(self.label_classify, 0, 4, 1, 1)
                grid.attach(self.entry_classify, 1, 4, 1, 1)
                self.window.show_all()

        elif current_page ==1:
            pass

        self.builder.get_object('notebook').next_page()

    def prev_page(self, button):
        self.builder.get_object('notebook').prev_page()

    def catch_user_id(self):
        """
        get session login id
        (-) not login
        (+user) local user
        (user) remote user
        """

        pp = subprocess.Popen(
            ['loginctl', 'list-sessions'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        pp_out, pp_err = pp.communicate()
        pp_out = pp_out.decode('utf8').split('\n')

        for l in pp_out:
            l = l.split()
            if len(l) < 3:
                continue
            try:
                sn = l[0].strip()
                if not sn.isdigit():
                    continue
                uid = l[1].strip()
                if not uid.isdigit():
                    continue
                user = l[2].strip()
                pp2 = subprocess.Popen(
                    ['loginctl', 'show-session', sn],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

                pp2_out, pp2_err = pp2.communicate()
                pp2_out = pp2_out.decode('utf8').split('\n')
                service_lightdm = False
                state_active = False
                active_yes = False
                for l2 in pp2_out:
                    l2 = l2.split('=')
                    if len(l2) != 2:
                        continue
                    k, v = l2
                    k = k.strip()
                    v = v.strip()
                    if k == 'Id'and v != sn:
                        break
                    elif k == 'User'and v != uid:
                        break
                    elif k == 'Name' and v != user:
                        break
                    elif k == 'Service':
                        if v == 'lightdm':
                            service_lightdm = True
                        else:
                            break
                    elif k == 'State':
                        if v == 'active':
                            state_active = True
                        else:
                            break
                    elif k == 'Active':
                        if v == 'yes':
                            active_yes = True

                    if service_lightdm and state_active and active_yes:
                        gecos = getpwnam(user).pw_gecos.split(',')
                        if len(gecos) >= 5 and gecos[4] == 'gooroom-account':
                            return user
                        else:
                            return '+{}'.format(user)
            except:
                AgentLog.get_logger().debug(agent_format_exc())

        return '-'

    def file_browse(self, button):
        '''
        dialog = Gtk.FileChooserDialog(_('Select a certificate'), self.builder.get_object('window1'),
            Gtk.FileChooserAction.OPEN,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        self.add_filters(dialog)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self.builder.get_object('entry_file').set_text(dialog.get_filename())

        dialog.destroy()
        '''

        login_id = self.catch_user_id()
        if login_id[0] == '+':
            login_id = login_id[1:]
        fp = subprocess.check_output(
            ['sudo', 
            '-u', 
            login_id, 
            '/usr/lib/gooroom/gooroomClientServerRegister/file-chooser.py'])
        fp = fp.decode('utf8').strip()
        if fp and fp.startswith('path='):
            self.builder.get_object('entry_file').set_text(fp[5:])

    def add_filters(self, dialog):
        filter_text = Gtk.FileFilter()
        filter_text.set_name(_("Certificate files"))
        filter_text.add_mime_type("application/x-x509-ca-cert")
        dialog.add_filter(filter_text)

        filter_any = Gtk.FileFilter()
        filter_any.set_name(_("Any files"))
        filter_any.add_pattern("*")
        dialog.add_filter(filter_any)

    def register(self, button):
        textbuffer = self.builder.get_object('textbuffer_result')
        textbuffer.set_text('')
        self.builder.get_object('button_ok').set_sensitive(False)
        self.builder.get_object('button_prev2').set_sensitive(False)

        datas = self.get_datas()
        self.next_page(button)
        register_thread = RegisterThread(datas, self)
        register_thread.start()

    def get_serverinfo(self):
        """
        get domain/ip of gkm/glm/grm/gpms for writing to /etc/hosts
        """

        hosts_data = {}

        checkbutton_hosts = self.builder.get_object('checkbutton_hosts')
        if checkbutton_hosts.get_active():
            gkm_domain = self.builder.get_object('entry_address').get_text()
            grid_serverinfo = self.builder.get_object('grid_serverinfo')
            gkm_ip = grid_serverinfo.get_child_at(2, 1).get_text()

            glm_domain = grid_serverinfo.get_child_at(1, 2).get_text()
            glm_ip = grid_serverinfo.get_child_at(2, 2).get_text()

            grm_domain = grid_serverinfo.get_child_at(1, 3).get_text()
            grm_ip = grid_serverinfo.get_child_at(2, 3).get_text()

            gpms_domain = grid_serverinfo.get_child_at(1, 4).get_text()
            gpms_ip = grid_serverinfo.get_child_at(2, 4).get_text()

            hosts_data['gkm'] = (gkm_domain,gkm_ip)
            hosts_data['glm'] = (glm_domain,glm_ip)
            hosts_data['grm'] = (grm_domain,grm_ip)
            hosts_data['gpms'] = (gpms_domain,gpms_ip)

        return hosts_data

    def get_datas(self):
        "Return input information. notebook page 0 and 1"
        server_data = {}
        server_data['domain'] = self.builder.get_object('entry_address').get_text()
        server_data['path'] = self.builder.get_object('entry_file').get_text()
        server_data['serverinfo'] = self.get_serverinfo()
        yield server_data

        client_data = {}
        client_data['cn'] = self.builder.get_object('entry_cn').get_text()
        client_data['name'] = self.builder.get_object('entry_name').get_text()
        client_data['ou'] = self.builder.get_object('entry_classify').get_text()
        client_data['password_system_type'] = "sha256"
        client_data['user_id'] = self.builder.get_object('entry_id').get_text()
        client_data['user_pw'] = self.builder.get_object('entry_password').get_text()
        client_data['valid_date'] = self.builder.get_object('entry_date').get_text()
        client_data['comment'] = self.builder.get_object('entry_comment').get_text()

        client_data['regkey'] = self.builder.get_object('entry_regkey').get_text()
        if self.builder.get_object('radiobutton_idpw').get_active():
            api_type = 'id/pw'
        else:
            api_type = 'regkey'
        client_data['api_type'] = api_type
        client_data['regkey'] = self.builder.get_object('entry_regkey').get_text()

        if self.builder.get_object('radiobutton_create').get_active():
            cert_reg_type = '0'
        elif self.builder.get_object('radiobutton_update').get_active():
            cert_reg_type = '1'
        else:
            cert_reg_type = '2'
        client_data['cert_reg_type'] = cert_reg_type
        if self.ip_type == 'ipv4':
            client_data['ipv4'] = self.make_ipname()
            client_data['ipv6'] = ''
        else:
            client_data['ipv4'] = ''
            client_data['ipv6'] = self.make_ipv6name()
        yield client_data

    def show_info_dialog(self, message, error=None):
        dialog = Gtk.MessageDialog(self.builder.get_object('window1'), 0,
            Gtk.MessageType.INFO, Gtk.ButtonsType.OK, 'info dialog')
        dialog.set_title(_('Gooroom Management Server Registration'))
        dialog.format_secondary_text(message)
        dialog.set_icon_name('gooroom-client-server-register')
        dialog.props.text = error
        response = dialog.run()
        if response == Gtk.ResponseType.OK or response == Gtk.ResponseType.CLOSE:
            dialog.destroy()


class ShellRegistering(Registering):

    def __init__(self):
        Registering.__init__(self)

    def input_surely(self, prompt):
        user_input = ''
        while not user_input:
            user_input = input(prompt)

        return user_input

    def cli(self):
        'Get request info from keyboard using cli'

        #SARABAL VERSION REQUEST
        client_data = {}
        while True:
            cert_reg_type = self.input_surely(_('Enter certificate registration type[0:create 1:update 2: create or update]: '))
            if cert_reg_type != '0' and cert_reg_type != '1' and cert_reg_type != '2':
                continue
            break
        client_data['cert_reg_type'] = cert_reg_type

        #client_data['cn'] = self.input_surely(_('Enter the Client ID: '))
        client_data['cn'] = self.make_cn()

        if cert_reg_type == '1':
            client_data['name'] = ''
            client_data['ou'] = ''
        else:
            client_ip = self.make_ipname()
            client_data['name'] = \
                input(_('Enter the client name')+'[{}]: '.format(client_ip)) or client_ip
            client_data['ou'] = input(_('Enter the organizational unit: '))

        while True:
            api_type = self.input_surely(_('Enter the authentication type[0:id/password 1:regkey]: '))
            if api_type != '0' and api_type != '1':
                continue
            break

        if api_type == '0':
            api_type = 'id/pw'
            client_data['user_id'] = self.input_surely(_('Enter the gooroom admin ID: '))
            client_data['user_pw'] = getpass.getpass(_('Enter the password: '))
        else:
            api_type = 'regkey'
            client_data['regkey'] = self.input_surely(_('Enter the registration key: '))
        client_data['api_type'] = api_type

        client_data['password_system_type'] = "sha256"
        client_data['valid_date'] = input(_('(Option)Enter the valid date(YYYY-MM-DD): '))
        client_data['comment'] = input(_('(Option)Enter the comment: '))
        if self.ip_type == 'ipv4':
            client_data['ipv4'] = self.make_ipname()
            client_data['ipv6'] = ''
        else:
            client_data['ipv4'] = ''
            client_data['ipv6'] = self.make_ipv6name()
        return client_data

    def run(self, args):
        if args.cmd == 'cli':
            print(_('Gooroom Client Server Register.\n'))
            server_data = {}
            server_data['domain'] = self.input_surely(_('Enter the domain name: '))
            server_data['path'] = input(_('(Option)Enter the certificate path of gooroom root CA: '))

        elif args.cmd == 'noninteractive':
            server_data = {'domain':args.domain, 'path':args.CAfile}

        elif args.cmd == 'noninteractive-regkey':
            server_data = {'domain':args.domain, 'path':args.CAfile}

        server_certification = certification.ServerCertification()
        for ip_type in server_certification.get_root_certificate(server_data):
            self.ip_type=ip_type

        self.do_certificate(args, server_certification, server_data)

    def do_certificate(self, args, server_certification, server_data):
        """
        certificate
        """

        sc = server_certification.certificate(server_data)
        for result in sc:
            result_text = self.result_format(result['log'])
            if result['err']:
                print("###########ERROR(%s)###########" % result['err'])
                print(result_text)
                exit(result['err'])

            print(result_text)

        if args.cmd == 'cli':
            client_data = self.cli()
        elif args.cmd == 'noninteractive':
            client_data = {}
            client_data['cn'] = self.make_cn()
            client_data['name'] = args.name
            if args.unit:
                client_data['ou'] = args.unit
            else:
                client_data['ou'] = ''
            client_data['password_system_type'] = "sha256"
            client_data['user_id'] = args.id
            client_data['user_pw'] = args.password
            client_data['valid_date'] = args.expiration_date
            client_data['comment'] = args.comment
            client_data['api_type'] = 'id/pw'
            client_data['cert_reg_type'] = args.cert_reg_type
            if self.ip_type == 'ipv4':
                client_data['ipv4'] = self.make_ipname()
                client_data['ipv6'] = ''
            else:
                client_data['ipv4'] = ''
                client_data['ipv6'] = self.make_ipv6name()
        elif args.cmd == 'noninteractive-regkey':
            client_data = {}
            client_data['cn'] = self.make_cn()
            client_data['name'] = args.name
            if args.unit:
                client_data['ou'] = args.unit
            else:
                client_data['ou'] = ''
            client_data['password_system_type'] = "sha256"
            client_data['valid_date'] = args.expiration_date
            client_data['comment'] = args.comment
            client_data['regkey'] = args.regkey
            client_data['api_type'] = 'regkey'
            client_data['cert_reg_type'] = args.cert_reg_type
            if self.ip_type == 'ipv4':
                client_data['ipv4'] = self.make_ipname()
                client_data['ipv6'] = ''
            else:
                client_data['ipv4'] = ''
                client_data['ipv6'] = self.make_ipv6name()
        else:
            print('can not support mode({})'.format(args.cmd))
            return

        client_certification = certification.ClientCertification(server_data['domain'])
        cc = client_certification.certificate(client_data)
        for result in cc:
            result_text = self.result_format(result['log'])
            if result['err']:
                print("###########ERROR(%s)###########" % result['err'])
                print(result_text)
                exit(1)

            print(result_text)

    def make_name(self):
        """
        make name with hostname@ip
        """

        import socket
        return socket.gethostname()
