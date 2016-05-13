#!/usr/bin/python
# --- HTTP Security Headers Analyzer ---
# This script can be used to verify the presence of HTTP security headers
#
# Note that it merely checks the presence of these headers but does not make
# any judgement on the effectiveness or correctness of the configurations or
# rules (e.g., CSP rules, pins of HSTS or X-XSS-Protection set to 0).
#
# This code was used to perform the survey published on Wildfire Labs blog.
#
# by Julio Cesar Fort // Wildfire Labs @ Blaze Information Security

import requests
import sys
import sqlite3
import socket
import Queue
import threading

# --- global constants ---
VERBOSE = True
DB_NAME = 'securityheaders.db'
DEFAULT_TIMEOUT = 7
MAX_THREADS = 1

# --- global variables ---
queue = Queue.Queue()
security_headers = {}
lock = threading.Lock()
db = ''

# --- global declarations ---
socket.setdefaulttimeout(DEFAULT_TIMEOUT)


def create_database(dbname):
    global db
    
    try:
        db = sqlite3.connect(dbname, check_same_thread=False)
    except Exception as err:
        print "[!] Error creating database: " + str(err)
        sys.exit(0)

    cursor = db.cursor()
    if VERBOSE:
        print "[+] Flushing all database tables"
    try:
        cursor.execute('''SELECT * FROM secheaders''')
    except sqlite3.OperationalError as err:
        if VERBOSE:
            print "[+] Table 'secheaders' not found. Does the database even exist?"
    #finally:
    #    cursor.execute('''DROP TABLE secheaders''')

    if VERBOSE:
        print "[+] Creating 'secheaders' table"
    try:
        cursor.execute('''CREATE TABLE secheaders(id INTEGER PRIMARY KEY, url TEXT unique, xss_protection TEXT, csp TEXT, xframe_options TEXT, no_sniff TEXT, hsts TEXT, hpkp TEXT, final_score INTEGER)''')
    except sqlite3.OperationalError as err:
        if VERBOSE:
            print "[+] Table 'secheaders' already exists. Skipping."
        pass
    
    db.commit()
    return


def insert_into_database(url):
    global db
    final_score = 0

    try:
        cursor = db.cursor()
    except Exception as err:
        print "Error acquiring a cursor to the database: " + str(err)
        sys.exit(0)

    # --- defining variables and assigning final_scores for the database ---
    xss_protection = security_headers['XSS_PROTECTION']
    csp = security_headers['CSP']
    xframe_options = security_headers['XFRAME_OPTIONS']
    no_sniff = security_headers['NO_SNIFF']
    hsts = security_headers['HSTS']
    hpkp = security_headers['HPKP']

    if xss_protection == 'True':
        final_score += 1
    if csp == 'True':
        final_score += 1
    if xframe_options == 'True':
        final_score += 1
    if no_sniff == 'True':
        final_score += 1
    if hsts == 'True':
        final_score += 1
    if hpkp == 'True':
        final_score += 1

    try:
        cursor.execute('''INSERT INTO secheaders(url, xss_protection, csp, xframe_options, no_sniff, hsts, hpkp, final_score) VALUES(?,?,?,?,?,?,?,?)''', (url, xss_protection, csp, xframe_options, no_sniff, hsts, hpkp, final_score))
    except sqlite3.IntegrityError as err:
        if VERBOSE:
            print "[+] The URL %s has already been inserted into the database and analyzed. Skipping." % url
        pass

    db.commit()
    return


def initialize_headers():
    global security_headers
    
    security_headers['XSS_PROTECTION'] = 'False'
    security_headers['CSP'] = 'False'
    security_headers['XFRAME_OPTIONS'] = 'False'
    security_headers['NO_SNIFF'] = 'False'
    security_headers['HSTS'] = 'False'
    security_headers['HPKP'] = 'False'


def parse_headers(url):
    global security_headers
    
    try:
	print "Connecting to %s" % url
	# we deliberately ignore SSL certificate errors
        req = requests.get(url, verify=False)
        
        for header in req.headers.items():
            if 'x-xss-protection' in header[0].lower():
                security_headers['XSS_PROTECTION'] = 'True'
            if 'public-key-pins' in header[0].lower():
                security_headers['HPKP'] = 'True'
            if 'x-frame-options' in header[0].lower():
                security_headers['XFRAME_OPTIONS'] = 'True'
            if 'x-content-type-options' in header[0].lower():
                security_headers['NO_SNIFF'] = 'True'
            if 'content-security-policy' in header[0].lower():
                security_headers['CSP'] = 'True'
            if 'strict-transport-security' in header[0].lower():
                security_headers['HSTS'] = 'True'
        return True
    except Exception as err:
        print err
    
    return False


def save_error_url(url):
    err_msg = "[!] Error connecting to %s\n" % url
    if VERBOSE:
        print "[!] %s" % err_msg,
    
    try:
        fd_error = open("error.log", "a+")
        fd_error.write(err_msg)
        fd_error.close()
    except IOError as err:
        print "[!] Error writing into log file 'error.log': %s" % str(err)
        
    return


class ThreadAnalyzer(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
        
    def run(self):
        while True:
            # --- get a lock, fetch from the queue, parse and into db ---
            lock.acquire()
            url = self.queue.get()
            if parse_headers(url):
                insert_into_database(url)
            else:
                save_error_url(url)
            
            # --- end ---
            initialize_headers()
            self.queue.task_done()
            lock.release()
        

def main():
    create_database(DB_NAME)
    initialize_headers()

    # --- initialize the analyzer threads ---
    for i in range(MAX_THREADS):
        worker = ThreadAnalyzer(queue)
        worker.setDaemon(True)
        worker.start()

    try:
        fd = open("list.txt", "r")
        urls = fd.read().splitlines()
        
        for url in urls:
            if not url.startswith("http"):
                #if not "www" in url:
                #    url = "http://www." + url
                #else:
                #    url = "http://" + url
                url = "http://" + url
                queue.put(url)
                
        queue.join()
        
    except IOError as err:
        print err
            

if __name__ == '__main__':
    main()

