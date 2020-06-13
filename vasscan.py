#!/usr/bin/env python3

# Author: KittyTechnoProgrammer (aka: KittyTechno)
# vasscan.py attempts to ease the scanning of targets using openvas via the command line, and can save the reports
# It also gives you addition information such as the Report ID to download into metasploit using the openvas plugin.


# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.



from threading import Semaphore
from functools import partial
from openvas_lib import VulnscanManager, VulnscanException
from sys import stdout
from colored import fg, bg, attr
from progress.bar import ChargingBar
from argparse import ArgumentParser
from time import sleep
from xml.etree import ElementTree
from IPy import IP
import openvas_lib
import os
import base64


lastprog = 0

# function for getting arguments
def get_args():

    args = ArgumentParser()
    args.add_argument("-s", dest="server", help="Specify the ip of the openVAS server")
    args.add_argument("-p", dest="profile", help="Specify profile to scan target(s) with | Needs to be in quotation marks", required = False)
    args.add_argument("-u", dest="username", help="Specify the username to connect with", required = False)
    args.add_argument("--pass", dest="password", help="Specify the password to the username", required = False)
    args.add_argument("-t", dest="target", help="Specify the target(s) to scan", required = False)
    args.add_argument("-oX", dest="save_xml", help="Specify the path of the xml to save the report", required = False)
    args.add_argument("-oH", dest="save_html", help="Specify the path of the html file to save the report", required = False)
    args.add_argument("-oA", dest="save_all", help="Specify the path of the xml and html files to save the report", required = False)

    # return the parsed args
    return args.parse_args()

# function for printing a loading prompt
def print_loading(msg):

    stdout.write("[ {}{}*{} ] {}".format(
        attr(1), fg(12), attr(0),
        msg
    ))

    stdout.flush()


# function for printing an okay prompt
def print_ok(msg):

    stdout.write("[ {}{}+{} ] {}".format(
        attr(1), fg(10), attr(0),
        msg
    ))

    stdout.flush()

# function for printing notifications
def print_notify(msg):

    stdout.write("[ {}{}!{} ] {}".format(
        attr(1), fg(11), attr(0),
        msg
    ))

    stdout.flush()

# function for printing an error prompt
def print_error(msg):

    stdout.write("[ {}{}-{} ] {}".format(
        attr(1), fg(9), attr(0),
        msg
    ))

    stdout.flush()


# function for printing status of the scan
def print_status(msg):

    global pbar
    global lastprog
    p = int("{:.0f}".format(msg), 10)
    pbar.next(p - lastprog)
    # print("P : {} | lastprog : {}".format(p, lastprog))

    if lastprog < p:

        lastprog = p

    # stdout.write("\033[K")
    # print_loading("Scan Progress : {:.0f}%\r".format(msg))
    # # stdout.write("\033[K")
    # stdout.flush()


# function for printing profiles of scans
def print_profiles():

    print("1). empty")
    print("2). Host Discovery")
    print("3). Full and fast ultimate")
    print("4). Full and very deep")
    print("5). Full and very deep ultimate")
    print("6). Discovery")
    print("7). System Discovery")
    print("8). Full and fast")


# function for launching the scan
def launch_scanner(server, username, password, target, profile, args):

    global pbar

    try:

        sem =  Semaphore(0)
        
        # configure the scan
        print_loading("Connecting to openVAS\r")
        manager = VulnscanManager(server, username, password)
        stdout.write("\033[K")
        print_ok("Connected to openVAS\n")
        # print_loading("Launching Scan\r")
        stdout.flush()

        pbar = ChargingBar("Scanning", max=100, suffix='%(percent)d%%')
        pbar.next(n=0)
        # pbar.next()
        scan_id, target_id = manager.launch_scan(target, 
            profile = profile,
            callback_end = partial(lambda x: x.release(), sem), 
            callback_progress=print_status)
        
        # wait
        sem.acquire()
        sleep(2)
        pbar.finish()
        stdout.write("\033[A")
        stdout.write("\033[K")
        stdout.flush()
        # print()
        # stdout.write("\033[K")
        # stdout.flush()
        print_ok("Finished Scan\n")
        # print_loading("Getting Report ID")
        report_id = manager.get_report_id(scan_id)

        # check if it has been specified to save the file as an xml
        if args.save_xml or args.save_all:

            print_loading("Getting XML Report ")
            report = manager.get_report_xml(report_id)
            # print(report)
            
            stdout.write("\r\033[K")
            stdout.flush()
            print_ok("Loaded XML Report\n")
            
            name = args.save_xml
            if not name.lower().endswith(".xml"):
                name += ".xml"

            print_loading("Attempting to save XML Report ")
            with open(name, "wb") as f:
                f.write(ElementTree.tostring(report, encoding="utf-8", method="xml"))

            stdout.write("\r\033[K")
            stdout.flush()
            print_ok("Saved XML Report as : {}\n".format(name))

        # check if it has been specified to save the file as an html
        if args.save_html or args.save_all:

            print_loading("Getting HTML Report ")
            report = manager.get_report_html(report_id)
            
            html_text = report.find("report").text
            if not html_text: 
                html_text = report.find("report").find("report_format").tail

            stdout.write("\r\033[K")
            stdout.flush()
            print_ok("Loaded HTML Report\n")
            
            name = args.save_html
            if not name.lower().endswith(".html"):
                name += ".html"

            print_loading("Attempting to save HTML Report ")
            with open(name, "wb") as f:
                f.write(base64.b64decode(html_text))

            stdout.write("\r\033[K")
            stdout.flush()
            print_ok("Saved HTML Report as : {}\n".format(name))


        print_ok("Scan ID : {}\n".format(scan_id))
        print_ok("Target ID : {}\n".format(target_id))
        print_ok("Report ID : {}\n".format(report_id))

        # finished scan
        print_ok("Finished\n")

    except Exception as e:
        print_error(e)
        os._exit(-1)

def choose_profile():
    
    print_profiles()
    
    while True:

        str_choice = input("(p: to print profiles) > ")

        if str_choice.lower() == "p":
            print_profiles()
            continue

        choice = int(str_choice, 10)

        if choice >= 9 or choice <= 0:

            print_error("Need a valid choice")
            continue
            
        if choice == 1:

            return "empty"

        elif choice == 2:

            return "Host Discover"

        elif choice == 3:

            return "Full and fast ultimate"

        elif choice == 4:

            return "Full and very deep"

        elif choice == 5:

            return "Full and very deep ultimate"

        elif choice == 6:

            return "Discovery"

        elif choice == 7:

            return "System Discovery"

        elif choice == 8:

            return "Full and fast"

        else:
            print_error("Need a valid choice")
            continue

# function for getting a username to connect to openvas with
def get_username():

    while True:

        user = input("openVAS username > ")
        if user == "":
            continue
        else:
            return user

# function for getting a server ip of openvas
def get_server():

    while True:

        try:

            ip = input("openVAS server IP > ")
            if ip.lower() == "localhost":
                ip = "127.0.0.1"

            IP(ip)

            return ip

        except ValueError:

            print_error("Need valid server IP\n")

def get_target():

    while True:

        try:
            
            ip = input("openVAS server IP > ")
            if ip == "localhost":
                ip = "127.0.0.1"

            IP(ip)

            return ip 

        except ValueError:

            print_error("Need valid server IP\n")
        
# function for getting a password to use for the username
# def get_password():

#     while True:

#         password = input("password > ")
#         # if password == "":

def main():

    # get command line arguments
    args = get_args()

    if args.server:
        server = args.server
    else:
        server = get_server()
        print()

    # check if username is given. If not then get it
    if args.username:
        username = args.username
    else: 
        # print_notify("No user from command line. Please specify username\n")
        username = get_username()
        print()

    if args.password:
        password = args.password
    else: 
        # print_notify("No password specified from command line. Please specify password\n")
        password = input("password > ")
        print()

    # check if targets and profile are given. If not then get them
    if args.target:
        target = args.target
    else:
        # print_notify("No target(s) specified from command line. Please specify target(s)\n")
        target = input("Target(s) > ")
        print()

    # check if a profile has been choosen to scan with
    if args.profile:
        profile = args.profile
    else:
        # print_notify("No profile specified from command line. Please specify profile\n")
        profile = choose_profile()
        print()

    # launch the scan
    launch_scanner(server, username, password, target, profile, args)

if __name__ == "__main__":
    main()