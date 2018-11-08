#!/usr/bin/python3
import os
import sys
import argparse
import gettext
import registering

from gcsr_define import *

gettext.install('gooroom-client-server-register', '/usr/share/gooroom/locale')

example_v1 = """v1.0)gooroom-client-server-register noninteractive -d gkm.gooroom.kr
                                                 [-C /usr/local/share/ca-certificates/server.crt]
                                                  -n client003 -u gooroom
                                                  -u gooroom
                                                 [-t Default]
                                                  -i admin_id
                                                  -p admin_password
                                                 [-e 2020-01-01]
                                                 [-c 2F ooo]"""

example = """>v1.0)gooroom-client-server-register noninteractive -d gkm.gooroom.kr
                                            [-C /usr/local/share/ca-certificates/server.crt]
                                            [ -r 2] #0:create 1:update 2:create or update
                                            [ -m ipaddress]
                                             -u gooroom
                                            [-t Default]
                                             -i admin_id
                                             -p admin_password
                                            [-e 2020-01-01]
                                            [-c 2F ooo]"""

example_regkey = """>v1.0)gooroom-client-server-register noninteractive-regkey -d gkm.gooroom.kr
                                            [-C /usr/local/share/ca-certificates/server.crt]
                                            [ -r 2] #0:create 1:update 2:create or update
                                            [ -m ipaddress]
                                             -u gooroom
                                            [-t Default]
                                             -k registration key
                                            [-e 2020-01-01]
                                            [-c 2F ooo]"""

autoregisteration_help ="""To automatically register your client to Gooroom Platform Management Server(GPMS) on boot,
                           configure “/etc/gooroom/gooroom-client-server-register/gcsr_auto.conf” accordingly."""

def usage():
    print('ex)gooroom-client-server-register gui\n')
    print('ex)gooroom-client-server-register cli\n')
    print(example_v1)
    print('\n')
    print(example)
    print('\n')
    print(example_regkey)
    print('\n')
    print(autoregisteration_help)

def argument_parser():
    clientip = os.popen('hostname --all-ip-addresses').read().split(' ')[0]
    parser = argparse.ArgumentParser(description=_('Register certificate of gooroom root CA & gooroom platform management server'))
    #parser.add_argument('-h', '--help', help=_('show this help message and exit'))
    #parser.add_argument('--help noninteractive', help=_('Show help on the noninteractive command'))
    parser.add_argument('--version', action='version', version=_('Gooroom Client Server Register 0.9'))

    subparsers = parser.add_subparsers(dest='cmd', help=_('commands'))
    subparsers.required = True
    gui_parser = subparsers.add_parser('gui', help=_('Run as gtk graphical user interface'))
    cli_parser = subparsers.add_parser('cli', help=_('Run as command line interface'))
    ni_parser = subparsers.add_parser('noninteractive', description=example,
                                      help=_('Run as Noninteractive with shell.'),
                                      formatter_class=argparse.RawTextHelpFormatter)
    ni_help = subparsers.add_parser('noninteractive --help', help=_('Print help on the noninteractive command'))
    ni_parser.add_argument('-d', '--domain', required=True, help=_('Key management server hostname'))
    ni_parser.add_argument('-C', '--CAfile', help=_('(Option)PEM format file of gooroom root CA certificate'), nargs='?')
    ni_parser.add_argument('-n', '--cn', help=_('Unique CN to use for the client certificate'))
    ni_parser.add_argument('-m', '--name', help=_('(Option)Client name to distinguish from others:default=ip'), default=clientip)
    ni_parser.add_argument('-u', '--unit', required=True, help=_('Client organizational unit to use for the client certificate'))
    ni_parser.add_argument('-t', '--password-system-type', help=_('Password system type to use for the password hashing.'), default='Default', nargs='?')
    ni_parser.add_argument('-i', '--id', help=_('GPMS admin ID'))
    ni_parser.add_argument('-p', '--password', help=_('GPMS admin password'))
    ni_parser.add_argument('-e', '--expiration-date', help=_('(Option)Certificates expiration date(format:YYYY-MM-DD)'), default='', nargs='?')
    ni_parser.add_argument('-c', '--comment', help=_('(Option)Description of the certificate'), nargs='?')
    ni_parser.add_argument('-r', '--cert-reg-type', help=_('(Option)Certificate Registration Type(0:create 1:update 2:create or update) default=create or update'), default='2', nargs='?')

    ni_regkey_parser = subparsers.add_parser('noninteractive-regkey', description=example_regkey,
                                      help=_('Run as NoninteractiveRegKey with shell using regstration key but id/pwd.'),
                                      formatter_class=argparse.RawTextHelpFormatter)
    ni_regkey_help = subparsers.add_parser('noninteractive-regkey --help', help=_('Print help on the noninteractive-regkey command'))
    ni_regkey_parser.add_argument('-d', '--domain', required=True, help=_('Key management server hostname'))
    ni_regkey_parser.add_argument('-C', '--CAfile', help=_('(Option)PEM format file of gooroom root CA certificate'), nargs='?')
    ni_regkey_parser.add_argument('-m', '--name', help=_('Option)Client name to distinguish from others:default=ip'), default=clientip)
    ni_regkey_parser.add_argument('-u', '--unit', required=True, help=_('Client organizational unit to use for the client certificate'))
    ni_regkey_parser.add_argument('-t', '--password-system-type', help=_('Password system type to use for the password hashing.'), default='Default', nargs='?')
    ni_regkey_parser.add_argument('-e', '--expiration-date', help=_('(Option)Certificates expiration date(format:YYYY-MM-DD)'), default='', nargs='?')
    ni_regkey_parser.add_argument('-c', '--comment', help=_('(Option)Description of the certificate'), nargs='?')
    ni_regkey_parser.add_argument('-k', '--regkey', required=True, help=_('GPMS registration key'))
    ni_regkey_parser.add_argument('-r', '--cert-reg-type', help=_('(Option)Certificate Registration Type(0:create 1:update 2:create or update) default=create or update'), default='2', nargs='?')

    arguments = parser.parse_args()
    return arguments


if __name__ == '__main__':
    if len(sys.argv) == 1:
        usage()
        exit(1)
        
    args = argument_parser()
    if os.getuid():
        print(_("Permission denied."))
        exit(1)

    if args.cmd == 'gui':
        registering.GUIRegistering()
    else:
        shell_register = registering.ShellRegistering()
        shell_register.run(args)
