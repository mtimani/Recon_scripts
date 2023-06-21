#!/usr/bin/python3

#----------------Imports----------------#
import json
import argparse
import tldextract
import operator
import os
import sys



#----------------Colors-----------------#
from termcolor import colored, cprint



#------------Error functions------------#
def usage():
    print(
'''
usage: root_domains_extractor.py [-h] -d DIRECTORY -r ROOT_DOMAINS -l DOMAIN_AND_IP_LIST

options:
  -h, --help            show this help message and exit

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results
  -r ROOT_DOMAINS, --root_domains ROOT_DOMAINS
                        Filename containing root domains
  -l DOMAIN_AND_IP_LIST, --list DOMAIN_AND_IP_LIST
                        domains_and_IP_list.json file from asset_discovery.py scan
'''
        )

def exit_abnormal():
    usage()
    sys.exit()



#-----Root domain extractor function----#
def root_dom_extraction(directory, original_root_domains, data):
    ## Variables initialization
    new_root_domains = []
    temp = []

    ## New root domains extraction
    for key in data.keys():
        root_domain = tldextract.extract(key).registered_domain
        if not(root_domain in original_root_domains):
            temp.append(root_domain)

    new_root_domains = sorted(set(temp))

    ## New root domains storage
    if (len(new_root_domains) > 0):
        cprint("New root domains found!\n",'green')
        cprint("Check new_root_domains.txt file\n",'blue')
        with open(directory + "/new_root_domains.txt","w") as fp:
            for item in new_root_domains:
                fp.write("%s\n" % item)
    else:
        cprint("No new root domains!\n",'red')



#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')

    ## Arguments
    required.add_argument("-d", "--directory", dest="directory", help="Directory that will store results", required=True)
    required.add_argument("-r", "--root_domains", dest="root_domains", help="Filename containing root domains", required=True)
    required.add_argument("-l", "--list", dest="domain_and_IP_list", help="domains_and_IP_list.json file from asset_discovery.py scan", required=True)
    return parser



#-------------Main Function-------------#
def main(args):
    ## Arguments
    directory           = args.directory
    root_domains        = args.root_domains
    domain_and_IP_list  = args.domain_and_IP_list

    ## Check if Output Directory exists
    if (not(os.path.exists(directory))):
        cprint("\nError! The specified output directory: %s does not exist!\n" % (directory), 'red')
        exit_abnormal()

    ## Setup and verifications
    ### Variable initialization
    original_root_domains = []
    data = {}
    
    ### If option -r is specified
    if (not(os.path.exists(root_domains))):
        cprint("\nError! The specified root domains list file: %s does not exist!\n" % (root_domains), 'red')
        exit_abnormal()
    with open(root_domains) as file:
        for line in file:
            original_root_domains.append(line.replace("\n", ""))

    ### If option -l is specified
    if (not(os.path.exists(domain_and_IP_list))):
        cprint("\nError! The specified domain_and_IP_list.json file: %s does not exist!\n" % (domain_and_IP_list), 'red')
        exit_abnormal()
    with open(domain_and_IP_list) as file:
        data = json.load(file)
    
    ## Root domain extractor function call
    root_dom_extraction(directory, original_root_domains, data)



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)
