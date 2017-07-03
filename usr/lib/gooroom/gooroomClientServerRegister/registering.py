#!/usr/bin/python3
import gettext
import os
import getpass
import pprint
import threading
import time
import copy

import gi
from gi.repository import Gdk, Gtk

import certification

gi.require_version('Gtk', '3.0')


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
        textbuffer = self.application.builder.get_object('textbuffer_result')
        client_data = next(self.datas)
        server_certification = certification.ServerCertification()
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
                return

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
                return


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
        self.window.set_icon_from_file('%s/icon/main-icon.png' % self.WORK_DIR)

        self.builder.get_object('label_subtitle1').set_text(_("Register certificate of gooroom root CA & gooroom platform management server"))
        self.builder.get_object('label_address').set_text(_('Domain'))
        self.builder.get_object('label_path').set_text(_('(Option)Select the certificate path of gooroom root CA'))
        self.builder.get_object('entry_address').set_placeholder_text(_('Enter the domain name'))
        self.builder.get_object('label_file').set_text('')
        self.builder.get_object('button_browse').set_label(_('browse...'))
        self.builder.get_object('button_register').set_label(_('Register'))
        self.builder.get_object('label_subtitle2').set_text(_('Register certificate of Gooroom root CA on the client'))
        self.builder.get_object('label_name').set_text(_('Client name'))
        self.builder.get_object('label_classify').set_text(_('Client organizational unit'))
        self.builder.get_object('label_date').set_text(_('(Option)Certificate expiration date'))

        self.builder.get_object('label_id').set_text(_('Gooroom admin ID'))
        self.builder.get_object('label_password').set_text(_('Password'))
        self.builder.get_object('label_detail').set_text(_('Send the request to the gooroom platform management server.'))
        self.builder.get_object('label_comment').set_text(_('(Option)Comment'))
        self.builder.get_object('label_result').set_text(_('Result data'))

        self.builder.get_object('button_next').connect('clicked', self.next_page)
        self.builder.get_object('button_prev1').connect('clicked', self.prev_page)
        self.builder.get_object('button_prev2').connect('clicked', self.prev_page)
        self.builder.get_object('button_browse').connect('clicked', self.file_browse)
        self.builder.get_object('button_register').connect('clicked', self.register)
        self.builder.get_object('button_ok').connect('clicked', Gtk.main_quit)
        self.builder.get_object('button_close1').connect('clicked', Gtk.main_quit)
        self.builder.get_object('button_close2').connect('clicked', Gtk.main_quit)

        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show_all()
        Gdk.threads_enter()
        Gtk.main()
        Gdk.threads_leave()

    def next_page(self, button):
        "After check empty information, do next page."
        current_page = self.builder.get_object('notebook').get_current_page()
        if current_page == 0:
            if not self.builder.get_object('entry_address').get_text():
                self.show_info_dialog(_('Please enter the domain'))
                return

        elif current_page ==1:
            pass

        self.builder.get_object('notebook').next_page()

    def prev_page(self, button):
        self.builder.get_object('notebook').prev_page()

    def file_browse(self, button):
        dialog = Gtk.FileChooserDialog(_('Select a certificate'), self.builder.get_object('window1'),
            Gtk.FileChooserAction.OPEN,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        self.add_filters(dialog)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self.builder.get_object('label_file').set_text(dialog.get_filename())

        dialog.destroy()

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
        datas = self.get_datas()
        self.next_page(button)
        register_thread = RegisterThread(datas, self)
        register_thread.start()

    def get_datas(self):
        "Return input information. notebook page 0 and 1"
        server_data = {}
        server_data['domain'] = self.builder.get_object('entry_address').get_text()
        server_data['path'] = self.builder.get_object('label_file').get_text()
        yield server_data

        client_data = {}
        client_data['cn'] = self.builder.get_object('entry_name').get_text()
        client_data['ou'] = self.builder.get_object('entry_classify').get_text()
        client_data['user_id'] = self.builder.get_object('entry_id').get_text()
        client_data['user_pw'] = self.builder.get_object('entry_password').get_text()
        client_data['valid_date'] = self.builder.get_object('entry_date').get_text()
        client_data['comment'] = self.builder.get_object('entry_comment').get_text()
        yield client_data

    def show_info_dialog(self, message, error=None):
        #parameter erros is error name using dialog title. message is details of error or real message
        dialog = Gtk.MessageDialog(self.builder.get_object('window1'), 0,
            Gtk.MessageType.INFO, Gtk.ButtonsType.OK, 'info dialog')
        dialog.set_title(_('Gooroom Management Server Registration'))
        dialog.format_secondary_text(message)
        dialog.set_icon_from_file("%s/icon/main-icon.png" % self.WORK_DIR)
        dialog.props.text = error
        response = dialog.run()
        if response == Gtk.ResponseType.OK or response == Gtk.ResponseType.CLOSE:
            dialog.destroy()


class ShellRegistering(Registering):

    def __init__(self):
        Registering.__init__(self)

    def cli(self):
        'Get request info from keyboard using cli'
        print(_('Gooroom Client Server Register.\n'))
        server_data = {}
        server_data['domain'] = input(_('Enter the domain name: '))
        server_data['path'] = input(_('(Option)Enter the certificate path of gooroom root CA: '))
        yield server_data

        client_data = {}
        client_data['cn'] = input(_('Enter the client name: '))
        client_data['ou'] = input(_('Enter the organizational unit: '))
        client_data['user_id'] = input(_('Enter the gooroom admin ID: '))
        client_data['user_pw'] = getpass.getpass(_('Enter the password: '))
        client_data['valid_date'] = input(_('(Option)Enter the valid date(YYYY-MM-DD): '))
        client_data['comment'] = input(_('(Option)Enter the comment: '))
        yield client_data

    def run(self, args):
        if args.cmd == 'cli':
            datas = self.cli()
            server_data = next(datas)

        elif args.cmd == 'noninteractive':
            server_data = {'domain':args.domain, 'path':args.path}

        server_certification = certification.ServerCertification()
        sc = server_certification.certificate(server_data)
        for result in sc:
            result_text = self.result_format(result['log'])
            if result['err']:
                # ERROR. print result and exit
                print("###########ERROR###########")
                print(result['err'])
                print(result_text)
                exit(1)

            print(result_text)

        if args.cmd == 'cli':
            client_data = next(datas)
        elif args.cmd == 'noninteractive':
            del args.cmd
            del args.domain
            del args.path
            client_data = vars(args)

        client_certification = certification.ClientCertification(server_data['domain'])
        cc = client_certification.certificate(client_data)
        for result in cc:
            result_text = self.result_format(result['log'])
            if result['err']:
                print(result['err'])
                print(result_text)
                exit(1)

            print(result_text)
