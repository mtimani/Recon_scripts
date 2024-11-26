# Recon Scripts

Recon scripts for Red Team and Web blackbox auditing.

## Asset_discovery.py script

### Description
Small script that allows to perform DNS asset discovery, Nuclei scans, determine used technologies, find known URLs, take screenshots of found web assets by combining the output of several tools.

The script needs a root_domain to bruteforce and an output_directory as arguments.
Ex: `asset_discovery.py -d $(pwd) -l target.com -n -s`

> :warning: **In Kali Linux, do not run as root! Screenshots won't work**

### Usage
```
usage: asset_discovery.py [-h] [-n] [-s] [-w] [-g] -d DIRECTORY (-f HOST_LIST_FILE | -l HOST_LIST [HOST_LIST ...])

options:
  -h, --help            show this help message and exit
  -n, --nuclei          Use Nuclei scanner to scan found assets
  -s, --screenshot      Use EyeWitness to take screenshots of found web assets
  -w, --webanalyzer     Use Webanalyzer to list used web technologies
  -g, --gau             Use gau tool to find interresting URLs on found web assets

required arguments:
  -d DIRECTORY, --directory DIRECTORY
                        Directory that will store results

mutually exclusive arguments:
  -f HOST_LIST_FILE, --filename HOST_LIST_FILE
                        Filename containing root domains to scan
  -l HOST_LIST [HOST_LIST ...], --list HOST_LIST [HOST_LIST ...]
                        List of root domains to scan
```

## Recon.py script

### Description
Have you ever done an audit with a lot of hosts to audit and were lazy to do all the blackbox tests by hand?

I made a nice little script that does a lot of blackbox tests (Ping, Nmap, DNS+DNSSec tests, sslscan + testssl) on a set of hosts you provide to the script.

The script provides almost no output, but stores the results in different folders/files:

![image.png](./image.png)

NB.: If your testssl script is not located in `/opt/testssl.sh/testssl.sh`, modify the path in the recon.py script.


### Usage
```
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
```

## Installation 

### Pull recon_scripts docker image from Docker Hub
The following command must be executed in order to pull recon_scripts docker image from Docker Hub
```
docker pull mtimani/recon_scripts:v1
```

### Build recon_scripts docker container locally

The following command must be executed in order to build the recon_scripts docker image locally
```
docker build -t recon_scripts .
```

### Local installation without docker (Not recommended)

The following command must be executed in order to install the recon.py and asset_discovery.py scripts locally without docker
```
sudo ./setup.sh
```
> :warning: **Please check the global variables in each script before launching it! Be very careful here!**
