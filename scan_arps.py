#!/usr/local/bin/python

"""
    This will scan the network for mac data and write to a couchdb.
    It will then alert on new devices on the network.
"""

import re
import couchdb
import datetime
import smtplib
from email.mime.text import MIMEText
from subprocess import Popen, PIPE

class CouchCoop:
    def __init__(self, server='localhost', port=5984, database_name='sauron'):
        """
            Initializes server connection to couchDB
        """
        self.server = server
        self.port = port
        self.database_name = database_name
        self.server = couchdb.Server(url="http://%s:%d" % (self.server, self.port))
        try:
            # create if database doesn't exist
            self.server.create(database_name)
        except couchdb.PreconditionFailed:
            # Database already exists
            pass
        finally:
            self.db = self.server[database_name]

    def add_doc(self, identifier, attributes):
        """
            Adds doc to database as-is
            Identifier is the key, attributes is the kwargs to add with it
        """
        self.db[identifier] = attributes

    def does_mac_exist(self, mac):
        """
            Checks if we have a record of this mac in the database
        """
        if mac in self.db:
            return True
        else:
            return False

    def date_from_database(self, identifier, field):
        """
            With the supplied identifier, take the database string
            of a date and work it into a date object that we can
            manipulate in the python way. Field is the datetime object
        """
        return datetime.datetime.strptime(self.db[identifier][field], '%x %X')

    def date_to_database(self, datetime_obj):
        """
            Just a wrapper for the strftime function, the return of this
            would get stored in couchdb
        """
        return datetime_obj.strftime('%x %X')

    def get_doc(self, identifier):
        """
            Returns the doc from couchdb as a document object. Note that
            this returns "None" if the object does not exist.
        """
        if self.does_mac_exist(identifier):
            return self.db[identifier]
        else:
            return None

    def read_scan_data(self, scan_data):
        """
            Reads the scan data from the below function
            and adds to the database as necessary. This
            is the "mean and potatoes" function.
        """
        rightnow = datetime.datetime.now()
        # Let's try 30 for now
        delta = datetime.timedelta(days=1)
        comparedate = rightnow - delta

        # List of docs to update in one swath
        update_doc_list = []

        # What new entries should we alert on?
        alert_doc_list = []

        for entry in scan_data:
            if self.does_mac_exist(entry['mac']):
                # We know about this already. Check the date.
                # Pull the doc.
                doc = self.get_doc(entry['mac'])
                working_date = datetime.datetime.strptime(doc['lastSeen'], '%x %X')
                if working_date < comparedate:
                    # This is a really old mac that we haven't seen in a while.
                    pass
                else:
                    # This is a fairly new mac that we've seen before.
                    pass

                # Now update the doc
                doc['lastSeen'] = rightnow.strftime('%x %X')
                doc['ip'] = entry['ip']
                update_doc_list.append(doc)

            else:
                # This is a new mac on the network. Should we alert?
                self.db[entry['mac']] = {'ip': entry['ip'], 'lastSeen': rightnow.strftime('%x %X'),
                                         'firstSeen': rightnow.strftime('%x %X'), 'oui': entry['oui']}

                doc = self.get_doc(entry['mac'])
                alert_doc_list.append(doc)


        # Now let's update all the entries as necessary
        self.db.update(update_doc_list)

        # And finally, formulate an alert with new mac addresses we find
        body = "I discovered one or more devices using our network.\n"
        body += "Just thought you should know.\n"
        body += "\n"
        for entry in alert_doc_list:
            body += "Mac Address: %s\n" % entry.id
            body += "IP Address: %s\n" % entry['ip']
            body += "OUI: %s\n" % entry['oui']
            body += "\n"

        if len(alert_doc_list):
            mail_exec(body, "New Device(s) found on network", "sauron@example.com", "dan@example.com")


def mail_exec(body, subj, m_from, m_to):
    """Does all the gruntwork for emailing data. Just
        send the proper data and it will send everything
        for you. Returns T/F based on whether it was able
        to send email.

        body   = body of the email.
        subj   = Subject of the email.
        m_from = Email address it will be sent from.
        m_to   = most likely this will be csirt@bnl.gov."""
    if len(body) < 1:
        return False
    if len(subj) < 1:
        return False
    msg = MIMEText(body)
    msg['Subject'] = subj
    msg['From'] = m_from
    msg['To'] = m_to
    s = smtplib.SMTP('localhost')
    s.sendmail(m_from, m_to, msg.as_string())
    s.quit()
    return True


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
    """ Main Function """
    # Hello World!
    macs = CouchCoop()

    # Run the full scan of the network and report
    report = get_macs('/usr/local/bin/arp-scan')

    # Now update the database
    macs.read_scan_data(report)

    # That's about it.

if __name__ == '__main__':
    main()
