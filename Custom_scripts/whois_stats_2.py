#!/usr/bin/python3

import json
import tldextract
import operator

# Variables initialization
subdomain_stats = {}
data = {}

# Results file import
with open("Results/domain_and_IP_list.json","r") as fp:
    data = json.load(fp)

# Recover root domains
for key in data.keys():
    root_domain = tldextract.extract(key).registered_domain
    if root_domain in subdomain_stats:
        subdomain_stats[root_domain] += 1
    else:
        subdomain_stats[root_domain] = 1

sorted_subdomain_stats = dict( sorted(subdomain_stats.items(), key=operator.itemgetter(1),reverse=True))
with open("Results/subdomain_distribution.csv","w") as fp:
    for key in sorted_subdomain_stats.keys():
        line = key + "," + str(subdomain_stats[key]) + "\n"
        fp.write(line)