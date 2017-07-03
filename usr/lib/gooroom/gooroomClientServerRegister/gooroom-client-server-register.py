#!/usr/bin/python3
import os
import argparse
import gettext
import registering

gettext.install('gooroom-client-server-register', '/usr/share/gooroom/locale')

def argument_parser():
    parser = argparse.ArgumentParser(description=_('Register certificate of gooroom root CA & gooroom platform management server'))

    subparsers = parser.add_subparsers(dest='cmd', help=_('commands'))
    subparsers.required = True
    gui_parser = subparsers.add_parser('gui', help=_('Run as gtk graphical user interface'))
    cli_parser = subparsers.add_parser('cli', help=_('Run as command line interface'))
    ni_parser = subparsers.add_parser('noninteractive', help=_('Run as Noninteractive with shell.'))
    ni_help = subparsers.add_parser('noninteractive --help', help=_('Print help on the noninteractive command'))

    group = ni_parser.add_argument_group('request information', description=_('Information for registering client certificate'))
    group.add_argument('--domain', help=_('Domain name'), required=True)
    group.add_argument('--path', nargs='?', help=_('Certificate path of gooroom root CA'))
    group.add_argument('cn', help=_('Client name'))
    group.add_argument('ou', help=_('Client organizational unit'))
    group.add_argument('user_id', help=_('Gooroom admin ID'))
    group.add_argument('user_pw', help=_('Password'))
    group.add_argument('valid_date', help=_('(Option)Expiration date(YYYY-MM-DD)'), nargs='?', default='')
    group.add_argument('comment', help=_('(Option)Comment of client'), nargs='?')
    parser.add_argument('--version', action='version', version=_('Gooroom Client Server Register 0.9'))

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
