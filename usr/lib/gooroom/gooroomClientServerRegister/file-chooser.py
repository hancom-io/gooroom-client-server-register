#!/usr/bin/python3

import gettext
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gdk, Gtk

gettext.install("gooroom-client-server-register", "/usr/share/gooroom/locale")

def file_chooser():
    dialog = Gtk.FileChooserDialog(_('Select a certificate'), None,
        Gtk.FileChooserAction.OPEN,
        (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
         Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

    filter_text = Gtk.FileFilter()
    filter_text.set_name(_("Certificate files"))
    filter_text.add_mime_type("application/x-x509-ca-cert")
    dialog.add_filter(filter_text)

    filter_any = Gtk.FileFilter()
    filter_any.set_name(_("Any files"))
    filter_any.add_pattern("*")
    dialog.add_filter(filter_any)

    response = dialog.run()

    result = ''
    if response == Gtk.ResponseType.OK:
        result = dialog.get_filename()
    dialog.destroy()
    print('path={}'.format(result))

if __name__ == '__main__':
    file_chooser()
