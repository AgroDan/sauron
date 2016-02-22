#!/usr/local/env python

"""
Object utilized for accessing the couchdb objects
"""

import couchdb
import smtplib
import datetime
import re
from email.mime.text import MIMEText

# TODO: find a way to delete an entry from macwatch if the persistent
#       flag is set to false

class MacWatch:
    def __init__(self, server='localhost', port=5984, database_name='all_seeing_eye'):
        """
            Initializes server connection to couchDB. This does all the ususal
            shit that couchcoop does but in a more limited sense, being more
            specific towards the macwatch database.
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

    def add_mac(self, mac, persistent=False):
        """
            Adds a mac to the macwatch database.

            Parms:
                mac = mac address. serves as the key to the database
                persistent = if we find this mac, should we keep
                    alerting on it?

            NOTE: If you add a mac, you are responsible for the
                  PROPER formatting! I am expecting the following
                  IEEE format: aa:bb:cc:11:22:33
        """
        if mac in self.db:
            # If this exists already, update it -- overwrite
            doc = self.db[mac]
            doc['persistent'] = persistent
            self.db.update([doc])
        
        self.db[mac] = {'persistent': persistent}

    def del_mac(self, mac):
        """
            Removes the entry from the database altogether
        """
        # First, let's pull the doc from the database
        if mac in self.db:
            # This entry exists, so let's do this
            doc = self.db[mac]
            self.db.delete(doc)
            return True
        else:
            return False

    def does_mac_exist(self, mac):
        """
            Returns T/F to determine if mac exists or not
        """
        if mac in self.db:
            return True
        else:
            return False

    def maclist(self):
        """
            Returns list of macs listed in macwatch.
            Returns empty list if db is empty.
        """
        retlist = []
        for entry in self.db:
            retlist.append(entry)

        return retlist

    def act_on_mac(self, mac):
        """
            This will return whether or not a mac address
            is in the macwatch database. If it is not, it will
            return false. If it is, it will check if it is marked
            as persistent. If it is, it will do nothing. If it
            is not, it will remove it.
        """
        if mac in self.db:
            doc = self.db[mac]
            if doc['persistent']:
                return True
            else:
                self.db.delete(doc)
                return True
        else:
            return False


class CouchCoop:
    def __init__(self, server='localhost', port=5984, database_name='sauron', ageout=30,
                 mail_to='dan@einados.com', mail_from='root@stewie.einados.com'):
        """
            Initializes server connection to couchDB
        """
        self.server = server
        self.port = port
        self.mail_to = mail_to
        self.mail_from = mail_from
        self.ageout = ageout
        # Macwatch is a list of mac addresses we care about if we see them again
        self.database_name = database_name
        self.server = couchdb.Server(url="http://%s:%d" % (self.server, self.port))
        self.macwatch = MacWatch()
        try:
            # create if database doesn't exist
            self.server.create(database_name)
        except couchdb.PreconditionFailed:
            # Database already exists
            pass
        finally:
            self.db = self.server[database_name]

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

    def alert(self, alert_list, message, subject):
        """
            Raises an alert with a customized message
            based on pre-defined criteria.
            Parms: alert_list -- list of docs from couchdb
                   message -- customized message header
                   subject -- customized subject line
        """
        body = "An alert has been triggered for the following event:\n"
        body += message
        for entry in alert_list:
            body += "MAC Address: %s\n" % entry['_id']
            body += "IP Address: %s\n" % entry['ip']
            body += "OUI: %s\n" % entry['oui']
            body += "\n"

        mail_exec(body, subject, self.mail_from, self.mail_to)


    def read_scan_data(self, scan_data):
        """
            Reads the scan data from the below function
            and adds to the database as necessary. This
            is the "meat and potatoes" function.
        """
        rightnow = datetime.datetime.now()
        delta = datetime.timedelta(days=self.ageout)
        comparedate = rightnow - delta

        # List of docs to update in one swath
        update_doc_list = []

        # What new entries should we alert on?
        new_devices_doc_list = []

        # Create a list for macwatch entries
        macwatch_found_list = []

        # Create a list for aged-out entries
        old_devices_found_doc_list = []

        for entry in scan_data:
            if self.does_mac_exist(entry['mac']):
                # We know about this already. Check the date.
                # Pull the doc.
                doc = self.get_doc(entry['mac'])
                working_date = datetime.datetime.strptime(doc['lastSeen'], '%x %X')
                if working_date < comparedate:
                    # This is a really old mac that we haven't seen in a while.
                    old_devices_found_doc_list.append(doc)
                else:
                    # This is a fairly new mac that we've seen before.
                    pass

                # Now update the doc
                doc['lastSeen'] = rightnow.strftime('%x %X')
                doc['ip'] = entry['ip']

                # Is this device on macwatch?
                if self.macwatch.act_on_mac(doc['_id']):
                    macwatch_found_list.append(doc)

                update_doc_list.append(doc)

            else:
                # This is a new mac on the network. Should we alert?
                self.db[entry['mac']] = {'ip': entry['ip'], 'lastSeen': rightnow.strftime('%x %X'),
                                         'firstSeen': rightnow.strftime('%x %X'), 'oui': entry['oui']}

                doc = self.get_doc(entry['mac'])

                # Log to macwatch if this is what we were looking for
                if entry['mac'] in self.macwatch:
                    macwatch_found_list.append(doc)

                # Append to new devices list
                new_devices_doc_list.append(doc)


        # Update all the timestamps. Basically if we found you and know about
        # you already, we're just going to update the last seen timestamp and
        # move on with our lives.
        self.db.update(update_doc_list)

        # Old device found? Form the alert.
        message = "A device that we haven't seen for at least %d days just showed up\n"
        message += "on your network! Just thought you should know.\n"
        message += "\n"
        if len(old_devices_found_doc_list):
            self.alert(old_devices_found_doc_list, message, "Long-lost Device Discovered!")

        # Cater to macwatch now.
        message = "A device which was manually placed in macwatch was just found\n"
        message += "on your network! This message will repeat A LOT until you disable it\n"
        message += "manually! Unless you chose to not make this persistent, in which case\n"
        message += "this will most likely be the last message you see about this.\n"
        message += "\n"
        if len(macwatch_found_list):
            self.alert(macwatch_found_list, message, "MACWATCH: Found Device!")

        # And finally, formulate an alert with new mac addresses we find
        message = "I discovered one or more devices using our network.\n"
        message += "Just thought you should know.\n"
        message += "\n"

        if len(new_devices_doc_list):
            self.alert(alert_doc_list, message, "New Device(s) found on network")


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
