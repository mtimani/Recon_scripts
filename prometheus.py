#!/usr/bin/python3


#----------------Imports----------------#
import sys
import os.path
import subprocess
import re



#------------Error functions------------#
def usage_standard():
    print(
'''
usage: prometheus.py [-h] (asset_discovery PARAMETERS | blackbox_audit PARAMETERS)

options:
  -h, --help            show this help message and exit

mutually exclusive arguments:
  asset_discovery PARAMETERS
                        Launch asset_discovery.py script in a dockerized environment (All the parameters are passed to the asset_discovery.py script)
  blackbox_audit PARAMETERS
                        Launch blackbox_audit.py script in a dockerized environment (All the parameters are passed to the blackbox_audit.py script)
'''
        )
    
def usage_asset_discovery():
    print(
'''
usage: prometheus.py asset_discovery [-h] [-n] [-s] [-w] [-g] [-i] [-pc PROVIDER_CONFIGURATION_SUBFINDER] -d DIRECTORY
                          (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...] | -b SUBDOMAIN_LIST_FILE)

options:
  -h, --help            show this help message and exit
  -n, --nuclei          Use Nuclei scanner to scan found assets
  -s, --screenshot      Use EyeWitness to take screenshots of found web assets
  -w, --webanalyzer     Use Webanalyzer to list used web technologies
  -g, --gau             Use gau tool to find interresting URLs on found web assets
  -i, --wafwoof         Use wafw00f to determine the WAF technology protecting the found web assets
  -pc PROVIDER_CONFIGURATION_SUBFINDER, --provider_configuration_subfinder PROVIDER_CONFIGURATION_SUBFINDER
                        Specify a subfinder configuration file to pass API keys for various providers

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results

mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing root domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of root domains to scan
  -b SUBDOMAIN_LIST_FILE, --bypass-domain-discovery SUBDOMAIN_LIST_FILE
                        Bypass subdomain discovery and pass a subdomain list as an argument
'''
        )
    
def usage_blackbox_audit():
    print(
'''
usage: prometheus.py blackbox_audit [-h] [-e] [-n] [-s] -d DIRECTORY (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...])

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

def exit_abnormal(function):
    if function == "standard":
        usage_standard()
    elif function == "asset_discovery":
        usage_asset_discovery()
    elif function == "blackbox_audit":
        usage_blackbox_audit()
    sys.exit()



#--------Insert Text after Target-------#
def insert_after_target(text, target, substring):
    # Find the index of the target text
    index = text.find(target)
    
    # If the target text is found, insert the substring after it
    if index != -1:
        # Slice the string into two parts and insert the substring
        return text[:index + len(target)] + substring + text[index + len(target):]
    else:
        # If target text is not found, return the original text
        return text



#-----Replace last string occurence-----#
def replace_last_occurrence(main_string, old_substring, new_substring):
    # Find the last index of the old_substring
    index = main_string.rfind(old_substring)
    
    # If the substring is found, replace it
    if index != -1:
        main_string = main_string[:index] + new_substring + main_string[index + len(old_substring):]
    
    return main_string
    


#-------Filter Parameters Function------#
def filter_params(command, function):
    ## Variables initialization
    final_command = command

    ## If the directory parameter is specified
    if ("-d" in final_command) or ("--directory" in final_command):
        ### Variant of option specified (Extract values of -d or --directory parameters)
        match = re.search(r'(-d|--directory)\s+(\S+)', final_command)
        
        ### If the value extraction was successful, modify the command
        if match:
            dir_path = match.group(2)
            old_dir_path = dir_path
            if dir_path[-1] == '/':
                dir_path = dir_path[:-1]
            
            dir_name = dir_path.split('/')[-1]

            #### Check if Output Directory exists
            if (not(os.path.exists(dir_path))):
                print("\nError! The specified output directory: %s does not exist!\n" % (dir_path))
                exit_abnormal(function)

            #### Replace old directory name by location in docker
            if (final_command.endswith(dir_path)):
                str_to_replace = old_dir_path
                str_replacing  = "/data/" + dir_name
                final_command = replace_last_occurrence(final_command, str_to_replace, str_replacing)
            else:
                str_to_replace = old_dir_path + " "
                str_replacing  = "/data/" + dir_name + " "
                final_command = final_command.replace(str_to_replace, str_replacing, 1)
            
            #### Add ./ if no slashes in path
            if not('/' in dir_path):
                dir_path = "./" + dir_path

            #### Add shared volume for results directory
            to_add = " -v " + dir_path + ":/data/" + dir_name
            final_command = insert_after_target(final_command, "-t --rm", to_add)
        
    ## If the file parameter is specified
    if ("-f" in final_command) or ("--filename" in final_command):
        ### Variant of option specified (Extract values of -f or --filename parameters)
        match = re.search(r'(-f|--filename)\s+(\S+)', final_command)
        
        ### If the value extraction was successful, modify the command
        if match:
            file_path = match.group(2)
            file_name = file_path.split('/')[-1]


            #### Check if host list file exists
            if (not(os.path.exists(file_path))):
                print("\nError! The specified host list file: %s does not exist!\n" % (file_path))
                exit_abnormal(function)

            #### Replace old file name by location in docker
            if (final_command.endswith(file_path)):
                str_to_replace = file_path
                str_replacing  = "/data/" + file_name
                final_command = replace_last_occurrence(final_command, str_to_replace, str_replacing)
            else:
                str_to_replace = file_path + " "
                str_replacing  = "/data/" + file_name + " "
                final_command = final_command.replace(str_to_replace, str_replacing, 1)

            #### Add ./ if no slashes in path
            if not('/' in file_path):
                file_path = "./" + file_path

            #### Add shared volume for host list file
            to_add = " -v " + file_path + ":/data/" + file_name
            final_command = insert_after_target(final_command, "-t --rm", to_add)
    
    ## If the subdomain file parameter is specified
    if ("-b" in final_command) or ("--bypass-domain-discovery" in final_command):
        ### Variant of option specified (Extract values of -b or --bypass-domain-discovery parameters)
        match = re.search(r'(-b|--bypass-domain-discovery)\s+(\S+)', final_command)
        
        ### If the value extraction was successful, modify the command
        if match:
            file_path = match.group(2)
            file_name = file_path.split('/')[-1]

            #### Check if subdomain list file exists
            if (not(os.path.exists(file_path))):
                print("\nError! The specified subdomain list file: %s does not exist!\n" % (file_path))
                exit_abnormal(function)

            #### Replace old file name by location in docker
            if (final_command.endswith(file_path)):
                str_to_replace = file_path
                str_replacing  = "/data/" + file_name
                final_command = replace_last_occurrence(final_command, str_to_replace, str_replacing)
            else:
                str_to_replace = file_path + " "
                str_replacing  = "/data/" + file_name + " "
                final_command = final_command.replace(str_to_replace, str_replacing, 1)

            #### Add ./ if no slashes in path
            if not('/' in file_path):
                file_path = "./" + file_path

            #### Add shared volume for subdomain list file
            to_add = " -v " + file_path + ":/data/" + file_name
            final_command = insert_after_target(final_command, "-t --rm", to_add)
    
    ## If the subdomain file parameter is specified
    if ("-pc" in final_command) or ("--provider_configuration_subfinder" in final_command):
        ### Variant of option specified (Extract values of -b or --bypass-domain-discovery parameters)
        match = re.search(r'(-pc|--provider_configuration_subfinder)\s+(\S+)', final_command)
        
        ### If the value extraction was successful, modify the command
        if match:
            file_path = match.group(2)
            file_name = file_path.split('/')[-1]

            #### Check if subdomain list file exists
            if (not(os.path.exists(file_path))):
                print("\nError! The specified subfinder configuration file: %s does not exist!\n" % (file_path))
                exit_abnormal(function)

            #### Replace old file name by location in docker
            if (final_command.endswith(file_path)):
                str_to_replace = file_path
                str_replacing  = "/data/" + file_name
                final_command = replace_last_occurrence(final_command, str_to_replace, str_replacing)
            else:
                str_to_replace = file_path + " "
                str_replacing  = "/data/" + file_name + " "
                final_command = final_command.replace(str_to_replace, str_replacing, 1)

            #### Add ./ if no slashes in path
            if not('/' in file_path):
                file_path = "./" + file_path

            #### Add shared volume for subdomain list file
            to_add = " -v " + file_path + ":/data/" + file_name
            final_command = insert_after_target(final_command, "-t --rm", to_add)
    
    return final_command



#----Asset_discovery Launch Function----#
def asset_discovery(params):
    ## Basic docker command to launch the asset_discovery.py script
    base_command = "docker run -t --rm mtimani/prometheus asset_discovery.py" + params

    ## Modify parameters to allow passing host files to the docker containers (used to pass the files required for the parameters of the script)
    to_run = filter_params(base_command, "asset_discovery")
    
    ## Run command and display live output
    process = subprocess.Popen(to_run.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in iter(process.stdout.readline, ""):
        if line != '\n':
            sys.stdout.write(line)

    ## Wait for the process to finish
    process.wait()



#-----Blackbox_audit Launch Function----#
def blackbox_audit(params):
    ## Basic docker command to launch the blackbox_audit.py script
    base_command = "docker run -t --rm mtimani/prometheus blackbox_audit.py" + params

    ## Modify parameters to allow passing host files to the docker containers (used to pass the files required for the parameters of the script)
    to_run = filter_params(base_command, "blackbox_audit")
    
    ## Run command and display live output
    process = subprocess.Popen(to_run.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in iter(process.stdout.readline, ""):
        if line != '\n':
            sys.stdout.write(line)

    ## Wait for the process to finish
    process.wait()



#-------------Main Function-------------#
def main():
    ## Print tool logo
    print("""
 ____                           _   _                    
|  _ \ _ __ ___  _ __ ___   ___| |_| |__   ___ _   _ ___ 
| |_) | '__/ _ \| '_ ` _ \ / _ \ __| '_ \ / _ \ | | / __|
|  __/| | | (_) | | | | | |  __/ |_| | | |  __/ |_| \__ \\
|_|   |_|  \___/|_| |_| |_|\___|\__|_| |_|\___|\__,_|___/
                                           Version: 1.0.0
                                           Author: mtimani
    """)

    ## Command line arguments
    s = ' '
    cmd_args_list = sys.argv[1:]
    cmd_args = s.join(cmd_args_list)

    ## Check if parameters are passed to the program
    if (not cmd_args):
        exit_abnormal("standard")
    ## Check if the first parameter is asset_discovery or blackbox_audit
    elif not (cmd_args.startswith("asset_discovery") or cmd_args.startswith("blackbox_audit")):
        exit_abnormal("standard")
    ## Display help
    elif (cmd_args.startswith("-h") or cmd_args.startswith("--help")):
        exit_abnormal("standard")
    
    ## Pass parameters to the asset_discovery function that will launch the asset_discovery.py script in a dockerized environment
    if (cmd_args.startswith("asset_discovery")):
        params = cmd_args.replace("asset_discovery","",1)
        asset_discovery(params)
    ## Pass parameters to the blackbox_audit function that will launch the blackbox_audit.py script in a dockerized environment
    elif (cmd_args.startswith("blackbox_audit")):
        params = cmd_args.replace("blackbox_audit","",1)
        blackbox_audit(params)



#-----------Main Function Call----------#
if __name__ == "__main__":
    main()
