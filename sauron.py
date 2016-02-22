#!/usr/local/bin/python

"""
    I AM THE ALL SEEING EYE OF FEDELE.LOCAL
"""

import re
from subprocess import Popen, PIPE
from arpobj import CouchCoop

def get_macs(arp_binary):
    """
        Scans the network using arp-scan and returns a python object
        with the mac address.

        Parms: arp_binary -- location of arp-scan binary
        Returns: Dict: (key: mac, value: ip address)
    """
    retval = list()
    # Run the command to scan the network
    process = Popen([arp_binary, "--localnet"], stdout=PIPE)
    (output, err) = process.communicate()
    output = output.split('\n')

    # Compile the regex to look for IP addresses
    ip_regex = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})')

    # Loop through the list looking for valid entries
    for line in output:
        if ip_regex.match(line):
            # This is a line with valid data in it, and we can extrapolate stuff to add to the DB
            # Note that the split function splits on whitespace when no seperator is given, but
            # I only want it to split it into a triple! The second parameter specifies how many
            # splits I can perform. Forcing an explicit "None"-type to split on whitespace but
            # only twice
            (ip_address, mac_address, OUI) = line.split(None, 2)
            retval.append(dict(ip=ip_address, mac=mac_address, oui=OUI))

    # At this point, we should have everything we need.
    return retval

def main():
    # Hello World!
    macs = CouchCoop()
    
    # Run the full scan of the network and report
    report = get_macs('/usr/local/bin/arp-scan')

    # Now update the datbase and report
    macs.read_scan_data(report)

    # That's it.

if __name__ == "__main__":
    main()
