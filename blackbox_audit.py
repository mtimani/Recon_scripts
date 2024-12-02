#!/usr/bin/python3


#----------------Imports----------------#
import sys
import argparse
import os
import os.path
import subprocess
import socket
import alive_progress
import concurrent.futures
import ftplib
import time
import json



#----------------Colors-----------------#
from termcolor import colored, cprint



#---------------Constants---------------#
testssl_location    = "/opt/testssl.sh/testssl.sh"
ssh_audit_location  = "/opt/ssh-audit/ssh-audit.py"
httpmethods_path    = "/opt/httpmethods/httpmethods.py"
webanalyze_path     = "/usr/bin/webanalyze"
gau_path            = "/usr/bin/gau"
dns_server          = "8.8.8.8"



#------------Error functions------------#
def usage():
    print(
'''
usage: blackbox_audit.py [-h] [-e] [-n] [-s] -d DIRECTORY (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...])

options:
  -h, --help            show this help message and exit
  -e, --extended        Run extended tests (includes SSH, FTP, SSL and HTTP tests)
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
            #cprint("Creation of " + dir_path + " directory\n", 'blue')
        except FileExistsError:
            #cprint("Directory " + dir_path + " already exists\n", 'blue')
            None
        except:
            raise
    else:
        try:
            os.mkdir(dir_path)
            #cprint("\tCreation of " + dir_path + " directory\n", 'blue')
        except FileExistsError:
            #cprint("\tDirectory " + dir_path + " already exists\n", 'blue')
            None
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
    cprint("Ping scan of " + domain + "\n",'red')

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
    cprint("Nmap scan of " + domain + "\n",'red')

    ## Nmap Command execution
    output_location = directory + "/01.Nmap/02.Nmap/" + domain + "/" + domain + " "
    if ping_failed:
        #bashCommand = "nmap -A -p- -Pn -oA " + output_location + domain
        bashCommand = "nmap -A -p 22,80,81,443,445,623,873,1080,1090,1098,1099,1433,1500,1789,1889,2301,3000,3306,3389,4444,5000,5001,5900,6338,6379,7000-7004,7199,8000,8001,8002,8003,8008,8080,8081,8082,8083,8090,8443,8834,8888,9000,9001,9002,9003,9010,9200,9503,10000,10080,10443,10999,11099,11501,28017,45000,45001,47001,47002 -oA " + output_location + domain
    else:
        bashCommand = "nmap -A -p- -oA " + output_location + domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#-----------DNS Recon Function----------#
def dns_f(directory, domain):
    ## Directory creation
    dir_create_check(directory + "/02.DNS/" + domain, True)

    ## Print to console
    cprint("DNS recon of " + domain + "\n",'red')

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



#-Return Directory Counter Function Launch--#
def dir_counter(directory):
    ## Counter of directories
    max_counter = 0

    ## List of subdirectories in directory
    dir_list = next(os.walk(directory))[1]

    ## Analyze subdirectories
    for dir in dir_list:
        try:
            counter = int(dir.split("0")[1].split(".")[0])
            if (counter > max_counter):
                max_counter = counter
        except:
            None

    max_counter += 1

    return max_counter



#---------Check if directory exists----------#
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



#-----------SSL Audit Function----------#
def ssl_f(directory, domain, port):
    try:
        ## Counter
        index = check_dir_index(directory, "SSL")
        if index == 0:
            counter = dir_counter(directory)
        else:
            counter = index

        ## Create directories
        ### Create SSL subdirectory
        dir_create_check(directory + "/0" + str(counter) + ".SSL/", False)

        ### Create domain subdirectory
        dir_create_check(directory + "/0" + str(counter) + ".SSL/" + domain, True)

        ### Create port subdirectory
        dir_create_check(directory + "/0" + str(counter) + ".SSL/" + domain + "/port_" + port, True)

        ### Working dir parameter
        working_dir = directory + "/0" + str(counter) + ".SSL/" + domain + "/port_" + port

        ## Print to console
        cprint("SSL recon of " + domain + " on port " + port + "\n",'red')
        
        ## TestSSL
        bashCommand = testssl_location + " --connect-timeout 10 --openssl-timeout 10 " + domain + ":" + port
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        ### Write output of testssl command to file
        with open(working_dir + "/testssl.txt","w") as fp:
            fp.write(output.decode('ascii'))

        ## TestSSL json
        output_file = working_dir + "/testssl.json"
        bashCommand = testssl_location + " --connect-timeout 10 --openssl-timeout 10 --jsonfile " + output_file + " " + domain + ":" + port
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
    except Exception as error:
        # handle the exception
        print("An exception occurred:", error)



#---------Screenshot Function Launch--------#
def screenshot_f(directory, domains):
    ## Print to console
    cprint("Screenshots of found web assets with Gowitness launched!\n",'red')

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
    os.system("gowitness file --disable-db --disable-logging -P " + filename_path + "Screenshots/ -f " + filename_path + "domain_list.txt.tmp")

    ## Remove temporary file
    bashCommand = "rm -rf " + filename_path + "domain_list.txt.tmp"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#---------Nuclei Function Launch--------#
def nuclei_f(directory, domains):
    ## Print to console
    cprint("Nuclei scan launched!\n",'red')

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
            ### Variable initialization
            to_write    = {"critical": [], "high": [], "medium": [], "low": [], "other": []}
            to_remove_1 = "[dns]"
            to_remove_2 = "[info]"
            critical    = "[critical]" 
            high        = "[high]"
            medium      = "[medium]"
            low         = "[low]"

            for line in f_read.readlines():
                l = line.rstrip()
                if ((to_remove_1 not in l) and (to_remove_2 not in l)):
                    if (l != "]"):
                        if (critical in l):
                            to_write["critical"].append(l)
                        elif (high in l):
                            to_write["high"].append(l)
                        elif (medium in l):
                            to_write["medium"].append(l)
                        elif (low in l):
                            to_write["low"].append(l)
                        else:
                            to_write["other"].append(l)
                            
            f_write.write(json.dumps(to_write, indent=4))

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
            elif line.endswith("ssh"):
                ssh_ports.append(line.split("/tcp")[0])
            elif "ssh?" in line:
                ssh_ports.append(line.split("/tcp")[0])
            elif "ftp " in line:
                ftp_ports.append(line.split("/tcp")[0])
            elif "ftp?" in line:
                ftp_ports.append(line.split("/tcp")[0])
            elif line.endswith("ftp"):
                ftp_ports.append(line.split("/tcp")[0])
            elif "ssl/http" in line:
                https_ports.append(line.split("/tcp")[0])
            elif "https " in line:
                https_ports.append(line.split("/tcp")[0])
            elif "https?" in line:
                https_ports.append(line.split("/tcp")[0])
            elif line.endswith("https"):
                https_ports.append(line.split("/tcp")[0])
            elif "http " in line:
                http_ports.append(line.split("/tcp")[0])
            elif line.endswith("http"):
                http_ports.append(line.split("/tcp")[0])
            elif "http?" in line:
                http_ports.append(line.split("/tcp")[0])
            elif "telnet " in line:
                telnet_ports.append(line.split("/tcp")[0])
            elif line.endswith("telnet"):
                telnet_ports.append(line.split("/tcp")[0])
            elif "telnet?" in line:
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
        os.system(httpmethods_path + " -q -s -L -k -j " + workiucleig_dir + "/HTTP_Methods/http_methods.json https://" + domain)

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
        os.system(webanalyze_path + " -update")
        os.system(webanalyze_path + " -host http://" + domain + ":" + port + "/ -output json -silent -search false -redirect | jq > " + working_dir + "/Webanalyzer/webanalyzer_out.json 2>/dev/null")

    except:
        cprint("\tError running Webanalyzer for " + domain + " port " + port, 'red')

    ## Gau
    try:
        ### Create Gau subdirectory
        dir_create_check(working_dir + "/Gau", True)

        ### Analyze
        os.system("echo " + domain + " | " + gau_path + " --o " + working_dir + "/Gau/gau_" + domain + ".txt --providers wayback,commoncrawl,otx")

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
    ## Launch SSL audit function
    ssl_f(directory, domain, port)

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
        os.system(httpmethods_path + " -q -s -L -k -j " + working_dir + "/HTTP_Methods/http_methods.json https://" + domain)

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
        os.system(webanalyze_path + " -update")
        os.system(webanalyze_path + " -host https://" + domain + ":" + port + "/ -output json -silent -search false -redirect | jq > " + working_dir + "/Webanalyzer/webanalyzer_out.json 2>/dev/null")

    except:
        cprint("\tError running Webanalyzer for " + domain + " port " + port, 'red')

    ## Gau
    try:
        ### Create Gau subdirectory
        dir_create_check(working_dir + "/Gau", True)

        ### Analyze
        os.system("echo " + domain + " | " + gau_path + " --o " + working_dir + "/Gau/gau_" + domain + ".txt --providers wayback,commoncrawl,otx")

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

    counter = len(domains)

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

    counter = len(domains)

    ## Loop over domains to recon
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'IP address resolution') as bar:
        for domain in hosts:
            bar()

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
        
    ## Setup Multithreading
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_nmap = {executor.submit(nmap_f, directory, domain): domain for domain in domains}
        future_dns  = {executor.submit(dns_f, directory, domain): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_dns):
            #cprint("Thread completed", 'blue')
            None
        for future in concurrent.futures.as_completed(future_nmap):
            #cprint("Thread completed", 'blue')
            None

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
    parser.add_argument("-e", "--extended", dest='e', action='store_true', help="Run extended tests (includes SSH, FTP, SSL and HTTP tests)")
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

    ## Display welcome message
    print()
    cprint("⚙️ Configuration:", "blue")
    print("- Subscript: ", end='')
    cprint("Blackbox_Audit", "green")

    ## Check if Output Directory exists
    if (not(os.path.exists(directory))):
        cprint("\nError! The specified output directory: %s does not exist!\n" % (directory), 'red')
        exit_abnormal()
    # Output to config output
    print("- Output Directory: ", end='')
    cprint("%s" % (directory), "green")

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
        # Output to config output
        print("- Host list file: ", end='')
        cprint("%s" % (host_list_file), "green")
    ### If option -l is specified
    else:
        hosts = host_list
        # Output to config output
        print("- Host list: ", end='')
        cprint("%s" % (host_list), "green")

    if (params["do_extended"]):
        # Output to config output
        print("- Perform extended tests => ", end='')
        cprint("YES", "green")
    else:
        print("- Perform extended tests => ", end='')
        cprint("NO", "red")
    
    if (params["do_screenshots"]):
        # Output to config output
        print("- Capture Screenshots on specified hosts => ", end='')
        cprint("YES", "green")
    else:
        print("- Capture Screenshots on specified hosts => ", end='')
        cprint("NO", "red")

    if (params["do_nuclei"]):
        # Output to config output
        print("- Perform nuclei scans on specified hosts => ", end='')
        cprint("YES", "green")
    else:
        print("- Perform nuclei scans on specified hosts => ", end='')
        cprint("NO", "red")
    
    ## Domains discovery function call
    recon(directory, hosts, params)



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
