#!/usr/bin/python3


#----------------Imports----------------#
import sys
import argparse
import os
import os.path
import subprocess
import socket
import concurrent.futures
import ftplib
import time
import json



#----------------Colors-----------------#
from termcolor import colored, cprint



#---------------Constants---------------#
testssl_location    = "/opt/testssl.sh/testssl.sh"
ssh_audit_location  = "/opt/ssh-audit/ssh-audit.py"
httpmethods         = "/opt/httpmethods/httpmethods.py"
webanalyze_path     = "/usr/bin/webanalyze"
gau_path            = "/usr/bin/gau"
dns_server          = "8.8.8.8"



#------------Error functions------------#
def usage():
    print(
'''
usage: recon.py [-h] [-e] [-n] [-s] -d DIRECTORY (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...])

options:
  -h, --help            show this help message and exit
  -e, --extended        Run extended tests (includes SSH, FTP and HTTP tests)
  -n, --nuclei          Use Nuclei scanner to scan assets
  -s, --screenshot      Use Gowitness to take screenshots of web assets

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results

mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of domains to scan
'''
        )

def exit_abnormal():
    usage()
    sys.exit()



#---Create / Check if exists Directory--#
def dir_create_check(dir_path, tab):
    if not(tab):
        try:
            os.mkdir(dir_path)
            cprint("Creation of " + dir_path + " directory\n", 'blue')
        except FileExistsError:
            cprint("Directory " + dir_path + " already exists\n", 'blue')
        except:
            raise
    else:
        try:
            os.mkdir(dir_path)
            cprint("\tCreation of " + dir_path + " directory\n", 'blue')
        except FileExistsError:
            cprint("\tDirectory " + dir_path + " already exists\n", 'blue')
        except:
            raise



#----------Nmap Recon Function----------#
def nmap_f(directory, domain):
    ## Directory creation
    dir_create_check(directory + "/01.Nmap/01.Ping", False)
    dir_create_check(directory + "/01.Nmap/02.Nmap", False)
    dir_create_check(directory + "/01.Nmap/01.Ping/" + domain, True)
    dir_create_check(directory + "/01.Nmap/02.Nmap/" + domain, True)

    ## Ping scan
    ### Print to console
    cprint("\tPing scan of " + domain + "\n",'blue')

    ### Ping command execution
    bashCommand = "ping -c 1 " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ### Check if Ping failed
    ping_failed = False
    for line in output.decode('ascii').splitlines():
        if "100% packet loss" in line:
            ping_failed = True
    
    ### Write output of ping command to file
    with open(directory + "/01.Nmap/01.Ping/" + domain + "/ping.txt","w") as fp:
        fp.write(output.decode('ascii'))
    
    ## Nmap scan
    ### Print to console
    cprint("\tNmap scan of " + domain + "\n",'blue')

    ## Nmap Command execution
    output_location = directory + "/01.Nmap/02.Nmap/" + domain + "/" + domain + " "
    if ping_failed:
        #bashCommand = "nmap -A -p- -Pn -oA " + output_location + domain
        bashCommand = "nmap -A -p 22,80,443,445,1099,1433,3000,3306,3389,5000,5900,7001,7002,8000,8001,8008,8080,8083,8443,8834,8888,10000,28017,9000,623,8090,2301,45000,45001,623,873,1090,1098,1099,4444,11099,47001,47002,10999,6379,7000-7004,8002,8003,9001,9002,9003,9200,9503,7070,7071,1789,1889,11501,1500,5001,81,6338,7199,9010 -oA " + output_location + domain
    else:
        bashCommand = "nmap -A -p- -oA " + output_location + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#-----------DNS Recon Function----------#
def dns_f(directory, domain):
    ## Directory creation
    dir_create_check(directory + "/02.DNS/" + domain, True)

    ## Print to console
    cprint("\tDNS recon of " + domain + "\n",'blue')

    ## DNS command execution
    ### Dig domain
    bashCommand = "dig " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ### Write output of dig command to file
    with open(directory + "/02.DNS/" + domain + "/dig_url.txt","w") as fp:
        fp.write(output.decode('ascii'))

    ### Nslookup domain
    bashCommand = "nslookup " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ### Write output of dig command to file
    with open(directory + "/02.DNS/" + domain + "/nslookup_url.txt","w") as fp:
        fp.write(output.decode('ascii'))

    ### DNS Recon
    bashCommand = "dnsrecon -d " + domain + " -n " + dns_server
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ### Write output of dig command to file
    with open(directory + "/02.DNS/" + domain + "/dnssec.txt","w") as fp:
        fp.write(output.decode('ascii'))

    ### IP resolution
    IPs = []
    try:
        ais = socket.getaddrinfo(domain,0,socket.AF_INET,0,0)
        for result in ais:
            IPs.append(result[-1][0])
        IPs = sorted(set(IPs))
    except socket.gaierror:
        None

    ### Loop through IP adresses of the host
    counter = 0
    for ip in IPs:
        counter += 1

        ### Dig IP
        bashCommand = "dig " + ip
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output of dig command to file
        with open(directory + "/02.DNS/" + domain + "/dig_ip_" + str(counter) + ".txt","w") as fp:
            fp.write(output.decode('ascii'))

        ### Dig -x IP
        bashCommand = "dig -x " + ip
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output of dig command to file
        with open(directory + "/02.DNS/" + domain + "/dig_x_ip_" + str(counter) + ".txt","w") as fp:
            fp.write(output.decode('ascii'))

        ### Nslookup IP
        bashCommand = "nslookup " + ip
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output of dig command to file
        with open(directory + "/02.DNS/" + domain + "/nslookup_ip_" + str(counter) + ".txt","w") as fp:
            fp.write(output.decode('ascii'))

        ### Whois IP
        bashCommand = "whois " + ip
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output of dig command to file
        with open(directory + "/02.DNS/" + domain + "/whois_ip_" + str(counter) + ".txt","w") as fp:
            fp.write(output.decode('ascii'))



#-----------DNS Recon Function----------#
def ssl_f(directory, domain):
    ## Directory creation
    dir_create_check(directory + "/03.SSL/" + domain, True)

    ## Print to console
    cprint("\tSSL recon of " + domain + "\n",'blue')

    ## SSLScan
    bashCommand = "sslscan " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ### Write output of sslscan command to file
    with open(directory + "/03.SSL/" + domain + "/sslscan.txt","w") as fp:
        fp.write(output.decode('ascii'))
    
    ## TestSSL
    bashCommand = testssl_location + " --connect-timeout 10 --openssl-timeout 10 " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ### Write output of sslscan command to file
    with open(directory + "/03.SSL/" + domain + "/testssl.txt","w") as fp:
        fp.write(output.decode('ascii'))

    ## TestSSL json
    output_file = directory + "/03.SSL/" + domain + "/testssl.json"
    bashCommand = testssl_location + " --connect-timeout 10 --openssl-timeout 10 --jsonfile " + output_file + " " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#-Return Directory Counter Function Launch--#
def dir_counter(directory):
    ## Counter of directories
    max_counter = 0

    ## List of subdirectories in directory
    dir_list = next(os.walk(directory))[1]

    ## Analyze subdirectories
    for dir in dir_list:
        counter = int(dir.split("0")[1].split(".")[0])
        if (counter > max_counter):
            max_counter = counter

    max_counter += 1

    return max_counter



#---------Check if HTTP dir exists----------#
def check_dir_index(directory, name):
    ## Counter of directories
    index = 0

    ## List of subdirectories in directory
    dir_list = next(os.walk(directory))[1]

    ## Analyze subdirectories
    for direct in dir_list:
        if name in direct:
            index = int(direct.split("0")[1].split(".")[0])

    return index



#---------Screenshot Function Launch--------#
def screenshot_f(directory, domains):
    ## Print to console
    cprint("Screenshots of found web assets with Gowitness launched!\n",'blue')

    ## Counter
    index = check_dir_index(directory, "HTTP")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create directories
    dir_create_check(directory + "/0" + str(counter) + ".HTTP", False)
    filename_path = directory + "/0" + str(counter) + ".HTTP/"
    
    with open(filename_path + "domain_list.txt.tmp", "w") as fp:
        for i in domains:
            fp.write(i)

    ## Gowitness tool launch
    dir_create_check(filename_path + "Screenshots", True)
    bashCommand = "gowitness file --disable-db --disable-logging -P " + filename_path + "Screenshots/ -f " + filename_path + "domain_list.txt.tmp"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ## Remove temporary file
    bashCommand = "rm -rf " + filename_path + "domain_list.txt.tmp"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#---------Nuclei Function Launch--------#
def nuclei_f(directory, domains):
    ## Print to console
    cprint("Nuclei scan launched!\n",'blue')

    ## Counter
    index = check_dir_index(directory, "Nuclei")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create Nuclei output directory
    dir_path = directory + "/0" + str(counter) + ".Nuclei"
    dir_create_check(dir_path, False)

    with open(dir_path + "/domain_list.txt.tmp", "w") as fp:
        for i in domains:
            fp.write(i)
    
    ## Nuclei scan launch
    bashCommand = "nuclei -t cves/ -l " + dir_path + "/domain_list.txt.tmp -o " + dir_path + "/nuclei_all_findings.txt"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ## Extract interresting findings
    with open(dir_path + "/nuclei_all_findings.txt", "r") as f_read:
        with open(dir_path + "/nuclei_important_findings.txt", "w") as f_write:
            to_remove = "[dns]"
            for line in f_read.readlines():
                if (to_remove not in line):
                    f_write.write(line)

    ## Remove temporary file
    bashCommand = "rm -rf " + dir_path + "/domain_list.txt.tmp"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#---Determine Technologies Function Launch--#
def determine_technologies(directory, domain):
    ## Variable initialization
    technologies    = {}
    ssh_ports       = []
    http_ports      = []
    https_ports     = []
    ftp_ports       = []
    telnet_ports    = []

    ## Parse Nmap scan output file to list technologies
    with open(directory + "/01.Nmap/02.Nmap/" + domain + "/" + domain + ".nmap", "r") as fp:
        for line in fp.read().splitlines():
            if "ssh " in line:
                ssh_ports.append(line.split("/tcp")[0])
            if line.endswith("ssh"):
                ssh_ports.append(line.split("/tcp")[0])
            elif "ftp " in line:
                ftp_ports.append(line.split("/tcp")[0])
            elif line.endswith("ftp"):
                ftp_ports.append(line.split("/tcp")[0])
            elif "http " in line:
                http_ports.append(line.split("/tcp")[0])
            elif line.endswith("http"):
                http_ports.append(line.split("/tcp")[0])
            elif "https " in line:
                https_ports.append(line.split("/tcp")[0])
            elif "https?" in line:
                https_ports.append(line.split("/tcp")[0])
            elif line.endswith("https"):
                https_ports.append(line.split("/tcp")[0])
            elif "telnet " in line:
                telnet_ports.append(line.split("/tcp")[0])
            elif line.endswith("telnet"):
                telnet_ports.append(line.split("/tcp")[0])

    technologies["ssh"]     = ssh_ports.copy()
    technologies["ftp"]     = ftp_ports.copy()
    technologies["http"]    = http_ports.copy()
    technologies["https"]   = https_ports.copy()
    technologies["telnet"]  = telnet_ports.copy()

    return technologies



#------------SSH Function Launch------------#
def ssh_f(directory, domain, port):
    ## Variable initialization
    index = check_dir_index(directory, "SSH")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create SSH subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".SSH/", False)

    ## Create domain subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".SSH/" + domain, True)

    ## Create port subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".SSH/" + domain + "/port_" + port, True)

    ## Working dir parameter
    working_dir = directory + "/0" + str(counter) + ".SSH/" + domain + "/port_" + port

    ## Grab banner
    try:
        ### Create Banner subdirectory
        dir_create_check(working_dir + "/Banner", True)

        ### Socket connection to grab banner
        host_ip = socket.gethostbyname(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host_ip, int(port)))

        try:
            banner = s.recv(1024).decode()
        except:
            banner = ""
        
        ### Write banner to file
        if banner != "":
            with open(working_dir + "/Banner/banner.txt","w") as fp:
                fp.write(banner)
    except:
        cprint("Error grabbing banner for " + domain + " port " + port, 'red')

    ## SSH-Audit tool
    ### Create SSH-Audit subdirectory
    dir_create_check(working_dir + "/SSH-Audit", True)

    ### Run SSH-Audit script
    output_location = working_dir + "/SSH-Audit/ssh-audit-out.txt"
    if output_location[0] != '/' or output_location[0] != '.':
        output_location = "./" + output_location
    bashCommand = ssh_audit_location + " -p " + port + " " + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    with open(output_location, "w") as fp:
        fp.write(output.decode('ascii'))



#------------FTP Function Launch------------#
def ftp_f(directory, domain, port):
    ## Variable initialization
    index = check_dir_index(directory, "FTP")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create FTP subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".FTP/", False)

    ## Create domain subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".FTP/" + domain, True)

    ## Create port subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".FTP/" + domain + "/port_" + port, True)

    ## Working dir parameter
    working_dir = directory + "/0" + str(counter) + ".FTP/" + domain + "/port_" + port

    ## Grab banner
    try:
        ### Create Banner subdirectory
        dir_create_check(working_dir + "/Banner", True)

        ### Socket connection to grab banner
        host_ip = socket.gethostbyname(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host_ip, int(port)))

        try:
            banner = s.recv(1024).decode()
        except:
            banner = ""
        
        ### Write banner to file
        if banner != "":
            with open(working_dir + "/Banner/banner.txt","w") as fp:
                fp.write(banner)
    except:
        cprint("Error grabbing banner for " + domain + " port " + port, 'red')

    ## Try FTP Anonymous login
    try:
        host_ip = socket.gethostbyname(domain)
        ftp = ftplib.FTP(host_ip)
        ftp.login('anonymous','anonymous')
        cprint("Anonymous FTP login successful to " + domain + " port " + port, "red")
        ftp.quit()

        ### Download all files on FTP server
        dir_create_check(working_dir + "/Contents", True)
        bashCommand = "wget -P " + working_dir + "/Contents/ -m ftp://anonymous:anonymous@" + host_ip
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        ret_code = process.wait()

    except:
        cprint("Anonymous FTP login not successful to " + domain + " port " + port, "blue")



#------------HTTP Function Launch-----------#
def http_f(directory, domain, port):
    ## Variable initialization
    index = check_dir_index(directory, "HTTP")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create HTTP subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".HTTP/", False)

    ## Create domain subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".HTTP/" + domain, True)

    ## Create port subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".HTTP/" + domain + "/port_" + port, True)

    ## Working dir parameter
    working_dir = directory + "/0" + str(counter) + ".HTTP/" + domain + "/port_" + port

    ## Google Dorks
    try:
        ### Create Google Dorks subdirectory
        dir_create_check(working_dir + "/Dorks", True)

        ### Print queries to command prompt
        queries  = 'site:github.com "' + domain + '"\n'
        queries += 'site:pastebin.com "' + domain + '"\n'
        queries += 'site:"' + domain + '"\n'
        queries += 'site:' + domain + ' "admin"\n'
        queries += 'site:' + domain + ' "administrateur"\n'
        queries += 'site:' + domain + ' "login"\n'
        queries += 'site:' + domain + ' "connexion"\n'
        queries += 'site:' + domain + ' "password"\n'
        queries += 'site:' + domain + ' "pwd"\n'
        queries += 'site:' + domain + ' "pass"\n'
        queries += 'site:' + domain + ' filetype:pdf\n'
        queries += 'site:' + domain + ' filetype:txt\n'
        queries += 'site:' + domain + ' filetype:docx\n'
        cprint("\n\nRun the following google dorks queries in order to have more info\n", 'red')
        cprint(queries, 'green')

        ### Write output to file
        with open(working_dir + "/Dorks/commands.txt", "w") as fp:
            fp.write(queries)

    except:
        cprint("\tError running Google Dorks commands for " + domain + " port " + port, 'red')

    ## HTTP Methods
    try:
        ### Create Google Dorks subdirectory
        dir_create_check(working_dir + "/HTTP_Methods", True)
        
        ### Analyze
        cprint("\n\nThe following are the authorized methods by the https://" + domain + " website\n", 'red')
        os.system(httpmethods + " -q -L -k -j " + working_dir + "/HTTP_Methods/http_methods.json https://" + domain)

    except:
        cprint("\tError running Http Methods tool for " + domain + " port " + port, 'red')
    
    ## Wafw00f
    try:
        ### Create WAF subdirectory
        dir_create_check(working_dir + "/WAF", True)

        ### Analyze
        bashCommand = "wafw00f " + domain
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output to file
        with open(working_dir + "/WAF/wafw00f.txt", "w") as fp:
            fp.write(output.decode('ascii'))

    except:
        cprint("\tError running wafw00f for " + domain + " port " + port, 'red')

    ## Webanalyzer
    try:
        ### Create Webanalyzer subdirectory
        dir_create_check(working_dir + "/Webanalyzer", True)

        ### Analyze
        os.system(webanalyze_path + " -host http://" + domain + ":" + port + "/ -output json -silent -search false -redirect | jq > " + working_dir + "/Webanalyzer/webanalyzer_out.json 2>/dev/null")

    except:
        cprint("\tError running Webanalyzer for " + domain + " port " + port, 'red')

    ## Gau
    try:
        ### Create Gau subdirectory
        dir_create_check(working_dir + "/Gau", True)

        ### Analyze
        os.system("echo " + domain + " | " + gau_path + " --o " + working_dir + "/Gau/gau_" + domain + ".txt --providers wayback,commoncrawl,otx,urlscan --threads 100")

    except:
        cprint("\tError running Gau for " + domain + " port " + port, 'red')

    ## HTTP Header analysis
    try:
        ### Create HTTP Headers subdirectory
        dir_create_check(working_dir + "/HTTP_Headers", True)

        ### Analyze
        bashCommand = "hsecscan -u http://" + domain + ":" + port
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write analysis to output file
        with open(working_dir + "/HTTP_Headers/header_analysis.txt", "w") as fp:
            fp.write(output.decode('ascii'))

        ### Write colored analysis to output file
        with open(working_dir + "/HTTP_Headers/header_analysis_colored.txt", "w") as fp:
            out = ""
            for line in output.decode('ascii').splitlines():
                if "Header Field Name:" in line:
                    out = out + os.linesep + "\033[0;31m" + line + "\033[0m"
                elif "Value:" in line:
                    out = out + os.linesep + "\033[0;31m" + line + "\033[0m" + os.linesep
                else:
                    out = out + os.linesep + line
            fp.write(out)

        ### Write only headers to output file
        with open(working_dir + "/HTTP_Headers/headers_only.txt", "w") as fp:
            out = ""
            for line in output.decode('ascii').splitlines():
                if "Header Field Name:" in line:
                    out = out + os.linesep + line
                elif "Value:" in line:
                    out = out + os.linesep + line + os.linesep
            fp.write(out)

    except:
        cprint("\tError analyzing HTTP Headers for " + domain + " port " + port, 'red')



#------------HTTP Function Launch-----------#
def https_f(directory, domain, port):
    ## Variable initialization
    index = check_dir_index(directory, "HTTP")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create HTTP subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".HTTP/", False)

    ## Create domain subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".HTTP/" + domain, True)

    ## Create port subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".HTTP/" + domain + "/port_" + port, True)

    ## Working dir parameter
    working_dir = directory + "/0" + str(counter) + ".HTTP/" + domain + "/port_" + port

    ## Google Dorks
    try:
        ### Create Google Dorks subdirectory
        dir_create_check(working_dir + "/Dorks", True)

        ### Print queries to command prompt
        queries  = 'site:github.com "' + domain + '"\n'
        queries += 'site:pastebin.com "' + domain + '"\n'
        queries += 'site:"' + domain + '"\n'
        queries += 'site:' + domain + ' "admin"\n'
        queries += 'site:' + domain + ' "administrateur"\n'
        queries += 'site:' + domain + ' "login"\n'
        queries += 'site:' + domain + ' "connexion"\n'
        queries += 'site:' + domain + ' "password"\n'
        queries += 'site:' + domain + ' "pwd"\n'
        queries += 'site:' + domain + ' "pass"\n'
        queries += 'site:' + domain + ' filetype:pdf\n'
        queries += 'site:' + domain + ' filetype:txt\n'
        queries += 'site:' + domain + ' filetype:docx\n'
        cprint("\n\nRun the following google dorks queries in order to have more info\n", 'red')
        cprint(queries, 'green')

        ### Write output to file
        with open(working_dir + "/Dorks/commands.txt", "w") as fp:
            fp.write(queries)

    except:
        cprint("\tError running Google Dorks commands for " + domain + " port " + port, 'red')

    ## HTTP Methods
    try:
        ### Create Google Dorks subdirectory
        dir_create_check(working_dir + "/HTTP_Methods", True)
        
        ### Analyze
        ### Analyze
        cprint("\n\nThe following are the authorized methods by the https://" + domain + " website\n", 'red')
        os.system(httpmethods + " -q -L -k -j " + working_dir + "/HTTP_Methods/http_methods.json https://" + domain)

    except:
        cprint("\tError running Http Methods tool for " + domain + " port " + port, 'red')

    ## Wafw00f
    try:
        ### Create WAF subdirectory
        dir_create_check(working_dir + "/WAF", True)

        ### Analyze
        bashCommand = "wafw00f " + domain
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output to file
        with open(working_dir + "/WAF/wafw00f.txt", "w") as fp:
            fp.write(output.decode('ascii'))

    except:
        cprint("\tError running wafw00f for " + domain + " port " + port, 'red')

    ## Webanalyzer
    try:
        ### Create Webanalyzer subdirectory
        dir_create_check(working_dir + "/Webanalyzer", True)

        ### Analyze
        os.system(webanalyze_path + " -host https://" + domain + ":" + port + "/ -output json -silent -search false -redirect | jq > " + working_dir + "/Webanalyzer/webanalyzer_out.json 2>/dev/null")

    except:
        cprint("\tError running Webanalyzer for " + domain + " port " + port, 'red')

    ## Gau
    try:
        ### Create Gau subdirectory
        dir_create_check(working_dir + "/Gau", True)

        ### Analyze
        os.system("echo " + domain + " | " + gau_path + " --o " + working_dir + "/Gau/gau_" + domain + ".txt --providers wayback,commoncrawl,otx,urlscan --threads 100")

    except:
        cprint("\tError running Gau for " + domain + " port " + port, 'red')

    ## HTTP Header analysis
    try:
        ### Create HTTP Header subdirectory
        dir_create_check(working_dir + "/HTTPS_Headers", True)

        ### Analyze
        bashCommand = "hsecscan -u https://" + domain + ":" + port
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write colored analysis to output file
        with open(working_dir + "/HTTPS_Headers/header_analysis_colored.txt", "w") as fp:
            out = ""
            for line in output.decode('ascii').splitlines():
                if "Header Field Name:" in line:
                    out = out + os.linesep + "\033[0;31m" + line + "\033[0m"
                elif "Value:" in line:
                    out = out + os.linesep + "\033[0;31m" + line + "\033[0m" + os.linesep
                else:
                    out = out + os.linesep + line
            fp.write(out)

        ### Write only headers to output file
        with open(working_dir + "/HTTPS_Headers/headers_only.txt", "w") as fp:
            out = ""
            for line in output.decode('ascii').splitlines():
                if "Header Field Name:" in line:
                    out = out + os.linesep + line
                elif "Value:" in line:
                    out = out + os.linesep + line + os.linesep
            fp.write(out)

    except:
        cprint("\tError analyzing HTTPS Headers for " + domain + " port " + port, 'red')



#------------Telnet Function Launch------------#
def telnet_f(directory, domain, port):
    ## Variable initialization
    index = check_dir_index(directory, "TELNET")
    if index == 0:
        counter = dir_counter(directory)
    else:
        counter = index

    ## Create SSH subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".TELNET/", False)

    ## Create domain subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".TELNET/" + domain, True)

    ## Create port subdirectory
    dir_create_check(directory + "/0" + str(counter) + ".TELNET/" + domain + "/port_" + port, True)

    ## Working dir parameter
    working_dir = directory + "/0" + str(counter) + ".TELNET/" + domain + "/port_" + port

    ## Grab banner
    try:
        ### Create Banner subdirectory
        dir_create_check(working_dir + "/Banner", True)

        ### Socket connection to grab banner
        host_ip = socket.gethostbyname(domain)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host_ip, int(port)))

        try:
            banner = s.recv(1024).decode()
        except:
            banner = ""
        
        ### Write banner to file
        if banner != "":
            with open(working_dir + "/Banner/banner.txt","w") as fp:
                fp.write(banner)
    except:
        cprint("Error grabbing banner for " + domain + " port " + port, 'red')

    ## Msf advanced scan
    ### Create Advanced Telnet MSF scan subdirectory
    dir_create_check(working_dir + "/Scan_MSF", True)

    ## MSF Command execution
    output_location = working_dir + "/Scan_MSF/telnet_advanced_msf.txt"
    bashCommand = "msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_version; set RHOSTS " + domain + "; set RPORT " + port + "; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/brocade_enable_login; set RHOSTS  " + domain + "; set RPORT " + port + "; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_encrypt_overflow; set RHOSTS  " + domain + "; set RPORT " + port + "; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_ruggedcom; set RHOSTS  " + domain + "; set RPORT " + port + "; run; exit'"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    with open(output_location, "w") as fp:
        fp.write(output.decode('ascii'))



#---------Screenshot Function Launch--------#
def extended_tests(directory, domains, params):
    ## Initialize variables
    technologies_per_domain = {}

    ## Determine technologies
    for domain in domains:
        technologies_per_domain[domain] = determine_technologies(directory, domain)

    ## Update Webanalyzer
    os.system(webanalyze_path + " -update")

    ## Setup Multithreading
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for domain in domains:
            ## Print to console
            cprint("Starting extended tests for " + domain, 'blue')

            if technologies_per_domain[domain]["ssh"]:
                for port in technologies_per_domain[domain]["ssh"]:
                    ssh_f(directory, domain, port)
            if technologies_per_domain[domain]["ftp"]:
                for port in technologies_per_domain[domain]["ftp"]:
                    ftp_f(directory, domain, port)
            if technologies_per_domain[domain]["http"]:
                for port in technologies_per_domain[domain]["http"]:
                    http_f(directory, domain, port)
            if technologies_per_domain[domain]["https"]:
                for port in technologies_per_domain[domain]["https"]:
                    https_f(directory, domain, port)
            if technologies_per_domain[domain]["telnet"]:
                for port in technologies_per_domain[domain]["telnet"]:
                    telnet_f(directory, domain, port)



#-------------Recon Function------------#
def recon(directory, hosts, params):
    ## Variable copy
    domains = hosts.copy()

    ## Loop over domains to recon
    for domain in hosts:
        ## Print to console
        cprint("Recon of " + domain + "\n",'blue')

        ## Check if domain resolves
        IPs = []
        try:
            ais = socket.getaddrinfo(domain,0,socket.AF_INET,0,0)
            for result in ais:
                IPs.append(result[-1][0])
            IPs = sorted(set(IPs))
        except socket.gaierror:
            None

        ## Throw an error if the specified domain could not be resolved
        if len(IPs) == 0:
            cprint("Error: The domain " + domain + " could not be resolved!\n\n", 'red')
            domains.remove(domain)
            continue

        ## Directory creation
        dir_create_check(directory + "/01.Nmap", False)
        dir_create_check(directory + "/02.DNS", False)
        dir_create_check(directory + "/03.SSL", False)
        
    ## Setup Multithreading
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_nmap = {executor.submit(nmap_f, directory, domain): domain for domain in domains}
        future_dns  = {executor.submit(dns_f, directory, domain): domain for domain in domains}
        future_ssl  = {executor.submit(ssl_f, directory, domain): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_dns):
            cprint("Thread completed", 'blue')
        for future in concurrent.futures.as_completed(future_ssl):
            cprint("Thread completed", 'blue')
        for future in concurrent.futures.as_completed(future_nmap):
            cprint("Thread completed", 'blue')

    ## Launch extended tests if -e is specified
    if (params["do_extended"]):
        extended_tests(directory, domains, params)

    ## Take screenshots of web assets if -s is specified
    if (params["do_screenshots"]):
        screenshot_f(directory, domains)

    if (params["do_nuclei"]):
        nuclei_f(directory, domains)
        
    cprint("All tests complete, good hacking to you young padawan!",'green')



#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')
    exclusive   = parser.add_argument_group('mutually exclusive arguments')
    content     = exclusive.add_mutually_exclusive_group(required=True)

    ## Arguments
    parser.add_argument("-e", "--extended", dest='e', action='store_true', help="Run extended tests (includes SSH, FTP and HTTP tests)")
    parser.add_argument("-n", "--nuclei", dest='n', action='store_true', help="Use Nuclei scanner to scan assets")
    parser.add_argument("-s", "--screenshot", dest='s', action='store_true', help="Use Gowitness to take screenshots of web assets")
    required.add_argument("-d", "--directory", dest="directory", help="Directory that will store results", required=True)
    content.add_argument("-f", "--filename", dest="host_list_file", help="Filename containing domains to scan")
    content.add_argument("-l", "--list", dest="host_list", nargs='+', help="List of domains to scan")
    return parser



#-------------Main Function-------------#
def main(args):
    ## Arguments
    directory       = args.directory
    host_list       = args.host_list
    host_list_file  = args.host_list_file
    do_screenshots  = args.s 
    do_nuclei       = args.n
    do_extended     = args.e
    params          = {
        "do_screenshots": do_screenshots,
        "do_nuclei": do_nuclei,
        "do_extended": do_extended
    }

    ## Check if Output Directory exists
    if (not(os.path.exists(directory))):
        cprint("\nError! The specified output directory: %s does not exist!\n" % (directory), 'red')
        exit_abnormal()

    ## Hosts list creation
    ### Hosts list variable creation
    hosts = []
    
    ### If option -f is specified
    if (host_list == None):
        if (not(os.path.exists(host_list_file))):
            cprint("\nError! The specified host list file: %s does not exist!\n" % (host_list_file), 'red')
            exit_abnormal()
        with open(host_list_file) as file:
            for line in file:
                hosts.append(line.replace("\n", ""))
    ### If option -l is specified
    else:
        hosts = host_list
    
    ## Domains discovery function call
    recon(directory, hosts, params)



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
