#!/usr/bin/python3

import argparse
import sys
import argparse
import os
import os.path
import subprocess
import socket
import threading
import json
import alive_progress
import concurrent.futures
import ipaddress
from cidrize import cidrize



#----------------Colors-----------------#
from termcolor import colored, cprint



#------------Error functions------------#
def usage():
    print(
'''
usage: script.py [-h] -d DIRECTORY -f HOST_LIST_FILE

options:
  -h, --help            show this help message and exit

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing root domains to scan
'''
        )

def exit_abnormal():
    usage()
    sys.exit()



#---------IP Discovery Function---------#
def IP_discovery(directory, found_domains):
    ## Print to console
    cprint("\n\nFinding IPs for found subdomains\n\n",'red')

    ## Variables initialization
    ip_dict = {}
    ip_list = []
    keys = range(len(found_domains))

    counter = len(found_domains)

    ## IP addresses lookup
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'IP address resolution') as bar:
        for domain in found_domains:
            bar()
            try:
                ais = socket.getaddrinfo(domain,0,socket.AF_INET,0,0)
                IPs = []
                for result in ais:
                    IPs.append(result[-1][0])
                    ip_list.append(result[-1][0])
                IPs = sorted(set(IPs))
                ip_dict[domain] = IPs.copy()
            except:
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
    cprint("Whois magic\n",'red')

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

    counter = len(ip_list)

    ## Whois list retreival
    with alive_progress.alive_bar(counter, ctrl_c=True, title=f'Whois resolution') as bar:
        for ip in ip_list:
            bar()
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
        try:
            cidr = str(cidrize(filename, strict=True)[0])
            filename = cidr.replace("/","_").strip() + ".txt"
        except:
            cprint("Cidrize failed for: " + filename + "\n", "red")
            continue

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
        
        if (cidr not in whois_dict):
            percentage  = round(1 / counter * 100,2)
            l = {'Owner': ip_owner, 'Counter': 1, 'Percentage': percentage}
            whois_dict[cidr] = l
        else:
            whois_dict[cidr]['Counter'] += 1
            percentage = round(whois_dict[cidr]['Counter'] / counter * 100,2)
            whois_dict[cidr]['Percentage'] = percentage

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
        for ip_range, l in whois_dict.items():
            owner = l["Owner"]
            percentage = str(l["Percentage"]) + " %"
            fp.write("{:<40} | {:<60} | {:<40}\n".format(ip_range, owner, percentage))



#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')

    ## Arguments
    required.add_argument("-d", "--directory", dest="directory", help="Directory that will store results", required=True)
    required.add_argument("-f", "--filename", dest="host_list_file", help="Filename containing root domains to scan", required=True)
    return parser



#-------------Main Function-------------#
def main(args):
    ## Arguments
    directory       = args.directory
    host_list_file  = args.host_list_file

    ## Check if Output Directory exists
    if (not(os.path.exists(directory))):
        cprint("\nError! The specified output directory: %s does not exist!\n" % (directory), 'red')
        exit_abnormal()

    ## Hosts list creation
    
    ### Hosts list variable creation
    hosts = []
    if (not(os.path.exists(host_list_file))):
        cprint("\nError! The specified host list file: %s does not exist!\n" % (host_list_file), 'red')
        exit_abnormal()
    with open(host_list_file) as file:
        for line in file:
            hosts.append(line.replace("\n", ""))
    
    ## IP discovery function call
    ip_list, ip_dict = IP_discovery(directory, hosts)

    ## Whois function call
    whois(directory, ip_list, ip_dict)

    cprint("All tests complete, good hacking to you young padawan!",'green')



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
