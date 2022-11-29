#!/usr/bin/python3


#----------------Imports----------------#
import sys
import argparse
import os
import os.path
import subprocess
import socket
import json
import concurrent.futures
import ipaddress
from cidrize import cidrize



#----------------Colors-----------------#
from termcolor import colored, cprint



#---------------Constants---------------#
dns_bruteforce_wordlist_path    = "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
SANextract_path                 = "/opt/SANextract/SANextract"



#------------Error functions------------#
def usage():
    print(
'''
usage: asset_discovery.py [-h] [-n] [-s] -d DIRECTORY (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...])

options:
  -h, --help            show this help message and exit
  -n, --nuclei          Use Nuclei scanner to scan found assets
  -s, --screenshot      Use Gowitness to take screenshots of found web assets

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results

mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing root domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of root domains to scan
'''
        )

def exit_abnormal():
    usage()
    sys.exit()



#---------Multithreading Function---------#
def worker_f(directory, root_domain, found_domains):
    ## Print to console
    cprint("Finding subdomains for: " + root_domain + "\n\n",'blue')
    
    ## Subfinder
    bashCommand = "subfinder -silent -d " + root_domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    for i in output.decode('ascii').splitlines():
        found_domains.append(i)
    
    ## Aiodnsbrute
    bashCommand = "aiodnsbrute -w " + dns_bruteforce_wordlist_path + " -t 1024 " + root_domain
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    ### Found subdomains extraction
    out = output.decode('ascii').splitlines()
    substring = '[+]'
    temp = [item for item in out if substring.lower() in item.lower()]
    for i in temp:
        found_domains.append(i.split('[0m',1)[1].split('\t',1)[0].strip())



#--------Domains Discovery Function-------#
def first_domain_scan(directory, hosts):
    ## Root and found domains list initialization
    root_domains  = hosts.copy()
    found_domains = hosts.copy()

    ## Loop over root domains
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_f = {executor.submit(worker_f, directory, root_domain, found_domains): root_domain for root_domain in root_domains}
        
        for future in concurrent.futures.as_completed(future_f):
            cprint("Thread completed", 'blue')
    
    ## Sort - Uniq Found domains list
    found_domains = sorted(set(found_domains))

    return found_domains.copy()



#--------Domains Discovery Function-------#
def domains_discovery(directory, hosts):
    ## First domain scan function call
    found_domains = first_domain_scan(directory, hosts)

    ## SANextract
    temp = []
    for i in found_domains:
        bashCommand_1 = "echo " + i
        bashCommand_2 = SANextract_path
        p1 = subprocess.Popen(bashCommand_1.split(), stdout=subprocess.PIPE)
        p2 = subprocess.Popen(bashCommand_2.split(), stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for j in p2.stdout.read().decode('ascii').splitlines():
            if j[0] != '*':
                temp.append(j)
    found_domains.extend(temp)
    found_domains = sorted(set(found_domains))

    ## Write found domains to a file
    with open(directory+"/domain_list.txt","w") as fp:
        for item in found_domains:
            fp.write("%s\n" % item)

    return found_domains



#---------IP Discovery Function---------#
def IP_discovery(directory, found_domains):
    ## Print to console
    cprint("\n\nFinding IPs for found subdomains\n\n",'blue')

    ## Variables initialization
    ip_dict = {}
    ip_list = []
    keys = range(len(found_domains))

    ## IP addresses lookup
    for domain in found_domains:
        try:
            ais = socket.getaddrinfo(domain,0,socket.AF_INET,0,0)
            IPs = []
            for result in ais:
                IPs.append(result[-1][0])
                ip_list.append(result[-1][0])
            IPs = sorted(set(IPs))
            ip_dict[domain] = IPs.copy()
        except socket.gaierror:
            None
    
    ## Sort and uniq IP addresses
    ip_list = sorted(set(ip_list))

    ## Write found IPs to a file
    with open(directory+"/IPs.txt","w") as fp:
        for item in ip_list:
            fp.write("%s\n" % item)

    return (ip_list,ip_dict)



#-------------Whois Function------------#
def whois(directory,ip_list,ip_dict):
    ## Print to console
    cprint("Whois magic\n\n",'blue')

    ## Create Whois directory
    try:
        os.mkdir(directory+"/Whois")
    except FileExistsError:
        None
    except:
        raise

    ## Variable initialization
    whois_list = []
    whois_dict = {}

    ## Whois list retreival
    for ip in ip_list:
        try:
            bashCommand = "whois " + ip
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            whois_list.append(output.decode('ascii'))
        except:
            cprint("Error: Failed to whois the following IP address : " + ip + "\n", 'red')

    ## Sort - Uniq on the retreived whois_list
    whois_list = sorted(set(whois_list))

    ## Find correct name for whois file and write to file
    value_1 = "inetnum:"
    value_2 = "CIDR:"
    for whois_element in whois_list:
        ### Variable initialization
        filename = ""

        ### Loop through lines of whois output
        for line in whois_element.splitlines():
            if (value_1 in line):
                filename = line.strip().split(":")[1].replace(" ", "").strip().split(",")[0].strip()
            elif (value_2 in line):
                filename = line.strip().split(":")[1].replace(" ", "").strip().split(",")[0].strip()
                break
        
        ## Uniformize Filename
        cidr = str(cidrize(filename, strict=True)[0])
        filename = cidr.replace("/","_").strip() + ".txt"

        ### Write to file
        with open(directory + "/Whois/" + filename,"w") as fp:
            fp.writelines(whois_element)

        ### Complete dictionnary
        value_3  = "Organization:"
        value_4  = "org-name"
        value_5  = "netname:"
        ip_owner = ""
        for line in whois_element.splitlines():
            if (value_3 in line) or (value_4 in line) or (value_5 in line):
                ip_owner = line.split(":")[1].strip()
                break
        
        whois_dict[cidr] = ip_owner

    ## Append IP Network Owner
    for dict1_key in ip_dict.keys():
        ip = ip_dict[dict1_key][0]
        for dict2_key in whois_dict.keys():
            if ipaddress.ip_address(ip) in ipaddress.ip_network(str(dict2_key)):
                ip_dict[dict1_key].append(dict2_key)
                ip_dict[dict1_key].append(whois_dict[dict2_key])
    ### Write Domains and corresponding IPs to a json file
    with open(directory+"/domain_and_IP_list.json","w") as fp:
        fp.write(json.dumps(ip_dict, sort_keys=True, indent=4))
 
    ## Write whois dictionnary to file
    with open(directory+"/IP_ranges_and_owners.txt","w") as fp:
        fp.write("{:<40} | {:<40}\n".format('IP Range', 'Owner'))
        for ip_range, owner in whois_dict.items():
            fp.write("{:<40} | {:<40}\n".format(ip_range, owner))



#---------Nuclei Function Launch--------#
def nuclei_f(directory):
    ## Print to console
    cprint("Nuclei scan launched!\n",'blue')

    ## Create Nuclei output directory
    dir_path = directory + "/Nuclei"
    try:
        os.mkdir(dir_path)
        cprint("Creation of " + dir_path + " directory\n", 'blue')
    except FileExistsError:
        cprint("Directory " + dir_path + " already exists\n", 'blue')
    except:
        raise
    
    ## Nuclei scan launch
    bashCommand = "nuclei -l " + directory + "/domain_list.txt -o " + dir_path + "/nuclei_all_findings.txt"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    ## Extract interresting findings
    with open(dir_path + "/nuclei_all_findings.txt", "r") as f_read:
        with open(dir_path + "/nuclei_important_findings.txt", "w") as f_write:
            to_remove = "[dns]"
            for line in f_read.readlines():
                if (to_remove not in line):
                    f_write.write(line)



#---------Screenshot Function Launch--------#
def screenshot_f(directory):
    ## Print to console
    cprint("Screenshots of found web assets with Gowitness launched!\n",'blue')
    
    ## Gowitness tool launch
    try:
        os.mkdir(directory + "/Screenshots")
        cprint("Creation of " + directory + "/Screenshots directory\n", 'blue')
    except FileExistsError:
        cprint("Directory " + directory + "/Screenshots already exists\n", 'blue')
    except:
        raise

    bashCommand = "gowitness file --disable-db --disable-logging -P " + directory + "Screenshots/ -f " + directory + "domain_list.txt.tmp"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()



#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')
    exclusive   = parser.add_argument_group('mutually exclusive arguments')
    content     = exclusive.add_mutually_exclusive_group(required=True)

    ## Arguments
    parser.add_argument("-n", "--nuclei", dest='n', action='store_true', help="Use Nuclei scanner to scan found assets")
    parser.add_argument("-s", "--screenshot", dest='s', action='store_true', help="Use Gowitness to take screenshots of found web assets")
    required.add_argument("-d", "--directory", dest="directory", help="Directory that will store results", required=True)
    content.add_argument("-f", "--filename", dest="host_list_file", help="Filename containing root domains to scan")
    content.add_argument("-l", "--list", dest="host_list", nargs='+', help="List of root domains to scan")
    return parser



#-------------Main Function-------------#
def main(args):
    ## Arguments
    directory       = args.directory
    host_list       = args.host_list
    host_list_file  = args.host_list_file
    do_nuclei       = args.n
    do_screenshots  = args.s

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
    found_domains = domains_discovery(directory, hosts)

    ## IP discovery function call
    ip_list, ip_dict = IP_discovery(directory, found_domains)

    ## Whois function call
    whois(directory, ip_list, ip_dict)

    ## Take screenshots of found web assets if -s is specified
    if (do_screenshots):
        screenshot_f(directory)

    ## Nuclei scan if -n is specified
    if (do_nuclei):
        nuclei_f(directory)

    cprint("All tests complete, good hacking to you young padawan!",'green')



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
