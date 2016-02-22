#!/usr/bin/env python

"""
    Manipulate the macwatch database
"""

import re
from arpobj import MacWatch
from argparse import ArgumentParser

def convert_mac_to_proper(mac):
    """
        Converts any mac address to a flat format
        and then formatted back to the correct format
    """
    mac = mac.replace('-', '')
    mac = mac.replace('.', '')
    mac = mac.replace(':', '')
    mac = mac.lower()
    if not len(mac) == 12:
        return ''
    


def main():

    parser = ArgumentParser(description='Manipulate the macwatch database.')
    mutually_exclusive_group = parser.add_mutually_exclusive_group(required=True)
    mutually_exclusive_group.add_argument('-a', '--add', action="store", dest="add", metavar="ma:ca:dd:re:ss:00", help="Add MAC Address to macwatch database")
    mutually_exclusive_group.add_argument('-d', '--del', action="store", dest="delete", metavar="ma:ca:dd:re:ss:00", help="Deletes MAC Address from macwatch database")
    mutually_exclusive_group.add_argument('-s', '--show', action="store_true", dest="show", help="Dump macwatch database", default=False)
    parser.add_argument('-p', '--make-persistent', action="store_true", dest="persistent", help="When adding a MAC, delete after found or keep alerting?", default=False)

    options=parser.parse_args()

    db = MacWatch()

    if options.add:
        db.add_mac(options.add, options.persistent)
        print "Done {Add: [%s], make_persistent: [%s]}" % (options.add, options.persistent)
    elif options.delete:
        db.del_mac(options.delete)
        print "Done {Del: [%s]}" % options.delete
    elif options.show:
        print "Showing MacWatch Database:"
        if db.maclist():
            for row in db.maclist():
                print row
        else:
            print "MacWatch database is empty."

    else:
        parser.print_help()
        

if __name__ == '__main__':
    main()
