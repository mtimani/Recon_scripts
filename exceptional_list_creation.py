#!/usr/bin/python3


#----------------Imports----------------#
import json
import sys
import argparse
import os
import os.path
import numpy as np
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.web import JsonLexer
from termcolor import colored, cprint



#-----------Global variables------------#
nb_strategies = 3



#-----Validate Directory Parameter------#
class validateDirectoryParameter(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        global nb_strategies

        if not os.path.isdir(values):
            parser.error(f"Please enter a valid directory that contains results from previous tests. Got: {values}")
        else:
            for strategy in range(1,nb_strategies+1):
                if not os.path.isfile(values + "/Strategy_" + str(strategy) + "_testing/exceptional.json"):
                    parser.error(f"Please enter a valid directory that contains results from previous tests. Got: {values}")
        setattr(namespace, self.dest, values)



#--------Arguments Parse Function-------#
def parse_command_line():
    ## Arguments groups
    parser      = argparse.ArgumentParser()
    required    = parser.add_argument_group('required arguments')

    ## Arguments
    parser.add_argument("-l", "--logging", action='store_true', dest="logging", help="enable logging in the console")
    required.add_argument("-d", "--directory", dest="directory", help="directory that contains results from previous tests", required=True, action=validateDirectoryParameter)
    return parser



#-------------Main Function-------------#
def main(args):
    ## Variables
    global nb_strategies
    directory   = args.directory
    logging     = args.logging
    final       = {}

    ## Create output directories
    try:
        os.mkdir(directory + "/Exceptional_combination")
        if logging:
            cprint("\n[INFO]\t\tCreation of " + directory + "/Exceptional_combination", 'blue')
    except FileExistsError:
        if logging:
            cprint("\n[INFO]\t\tDirectory " + directory + "/Exceptional_combination", 'blue')
        else:
            None
    except:
        raise

    ## Open exceptional files
    for strategy in range(1,nb_strategies+1):
        with open(directory + "/Strategy_" + str(strategy) + "_testing/exceptional.json", "r") as fp:
            tmp = json.load(fp)

        for coin in tmp:
            if coin in final:
                if final[coin]["average"] < tmp[coin]["average"]:
                    final[coin] = tmp[coin].copy()
            else:
                final[coin] = tmp[coin].copy()
    
    ## Format JSON
    formatted_final = json.dumps(final, indent=4)

    ## Display to console if the logging is on
    if logging:
        colorful = highlight(formatted_final, lexer=JsonLexer(), formatter=Terminal256Formatter())
        print(colorful)
    
    ## Write exceptional to file
    output_file = directory + "/Exceptional_combination/exceptional_final.json"
    with open(output_file, "w") as fp:
        fp.write(json.dumps(final, sort_keys=True, indent=4))



#-----------Main Function Call----------#
if __name__ == "__main__":
    args = parse_command_line().parse_args()
    main(args)