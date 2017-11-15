#!/usr/bin/python3
import os
import argparse
import gettext
import registering

gettext.install('gooroom-client-server-register', '/usr/share/gooroom/locale')

def argument_parser():
    parser = argparse.ArgumentParser(description=_('Register certificate of gooroom root CA & gooroom platform management server'))
    #parser.add_argument('-h', '--help', help=_('show this help message and exit'))
    #parser.add_argument('--help noninteractive', help=_('Show help on the noninteractive command'))
    parser.add_argument('--version', action='version', version=_('Gooroom Client Server Register 0.9'))

    subparsers = parser.add_subparsers(dest='cmd', help=_('commands'))
    subparsers.required = True
    gui_parser = subparsers.add_parser('gui', help=_('Run as gtk graphical user interface'))
    cli_parser = subparsers.add_parser('cli', help=_('Run as command line interface'))
    example = """ex)gooroom-client-server-register noninteractive -d gkm.gooroom.kr
                                                [-C /usr/local/share/ca-certificates/server.crt]
                                                 -n client003
                                                 -u gooroom
                                                [-o Default]
                                                 -i admin_id
                                                 -p admin_password
                                                [-e 2020-01-01]
                                                [-c 2F ooo]"""
    ni_parser = subparsers.add_parser('noninteractive', description=example,
                                      help=_('Run as Noninteractive with shell.'),
                                      formatter_class=argparse.RawTextHelpFormatter)
    ni_help = subparsers.add_parser('noninteractive --help', help=_('Print help on the noninteractive command'))

    ni_parser.add_argument('-d', '--domain', required=True, help=_('Key management server hostname'))
    ni_parser.add_argument('-C', '--CAfile', help=_('(Option)PEM format file of gooroom root CA certificate'), nargs='?')
    ni_parser.add_argument('-n', '--name', required=True, help=_('Unique client common name to use for the client certificate'))
    ni_parser.add_argument('-u', '--unit', required=True, help=_('Client organizational unit to use for the client certificate'))
    ni_parser.add_argument('-o', '--organization', help=_('Client organization to use for the password hashing.'), default='Default', nargs='?')
    ni_parser.add_argument('-i', '--id', required=True, help=_('GPMS admin ID'))
    ni_parser.add_argument('-p', '--password', required=True, help=_('GPMS admin password'))
    ni_parser.add_argument('-e', '--expiration-date', help=_('(Option)Certificates expiration date(format:YYYY-MM-DD)'), default='', nargs='?')
    ni_parser.add_argument('-c', '--comment', help=_('(Option)Description of the certificate'), nargs='?')

    arguments = parser.parse_args()
    return arguments


if __name__ == '__main__':
    args = argument_parser()
    if os.getuid():
        print(_("Permission denied."))
        exit(1)

    if args.cmd == 'gui':
        registering.GUIRegistering()
    else:
        shell_register = registering.ShellRegistering()
        shell_register.run(args)
