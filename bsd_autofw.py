#!/usr/local/bin/python3.6 

import argparse
from random import choice
from string import ascii_letters
from subprocess import Popen, PIPE, STDOUT
from subprocess import check_output as ckout
from collections import Counter

class AutoFirewallRules:


    def __init__(self):
        
        self.ALL_OFF = 	'\033[0m'
        self.FG_YELLOW  = 	'\033[93m'
        self.FG_PURPLE = 	'\033[35m'
        self.REVERSE = 	'\033[7m'

    def load_args(self):
        parser = argparse.ArgumentParser(
            description='Include firewall rules by tcpdump output')
        parser.add_argument('-i', action='store', dest='interface', 
            required=True, help='Select a interface to sniff')    
        parser.add_argument('-t', action='store', dest='timeout', 
            type=int, help='timeout of tcpdump command')
        parser.add_argument('-rt', action='store', dest='rule_timeout', 
            type=int, help='rollback rule after seconds')   
        parser.add_argument('--filter', action='store', dest='filters', 
            help='filters in tcpdump format(separated by comma)')   
        parser.add_argument('-n', type=int, action='store', dest='connections', 
            help='Maximum connections before apply rule')
        parser.add_argument('--syn', action='store_true', 
            help="Deny only SYN packets (keep estabilished connections)")
        parser.add_argument('--debug', action='store_true', 
            help="show match packets")
        parser.add_argument('--apply', action='store_true', 
            help="Aplly Rules based on number of connections passed on -n parameter")
        parser.add_argument('address')
        self.args = parser.parse_args()


    def check_output(self):
        """
        Check and count output of tcpdump command
        """
        _src = []
        count = 0
        while True:
            line = self.tcpdump.stdout.readline().decode('utf-8').rstrip().split()
            # print(line)
            if not line:
                break
            try:
                if 'IP' == line[1]:
                    src_addr = '.'.join(line[2].split('.')[:4])
                    dest = line[4].rstrip(':')
                    tmp = src_addr + ' --> ' + dest
                    _src.append(tmp)
                    if self.args.debug:
                        print(self.FG_PURPLE + ' '.join(line) + self.ALL_OFF)
            except IndexError:
                pass
        _counter = Counter(_src)
        print('\nDETAILS')
        print('='*80)
        print(_counter.most_common())
        print('='*80)
        return _counter.most_common()

    def block_bruteforce_attempt(self, counter, max_tries):
        """
        Add a firewall rule based on number of new connections 
        defined in '-n' parameter
        """
        for connection, count in counter:
            if count > max_tries:
                src_ip = connection.split()[0]
                dst_ip = '.'.join(connection.split()[2].split('.')[:-1])
                port = connection.split()[2].split('.')[-1]
                ipfw_com = 'ipfw -q add '
                params = "1 deny tcp from {} to {} {} in".format(src_ip, dst_ip, port)
                command = ipfw_com + params
                if self.args.syn == True:
                    command += ' setup'
                if self.args.rule_timeout:
                    self.rule_timeout(params, '/tmp/ipfw.' + self.random_char(6))
                print('\n' + self.REVERSE + 'RULES' + self.ALL_OFF)
                print(self.FG_YELLOW + '{}'.format(command) + self.ALL_OFF)
                print()
                if self.args.apply:
                    Popen(command, stdout=PIPE, stderr=STDOUT, shell=True)
                    print(self.REVERSE + 'Firewall updated !' + self.ALL_OFF)
                    print(self.REVERSE + 'Rollback in {} seconds!'.format(
                        self.args.rule_timeout) + self.ALL_OFF)
                    print()


    def prepare_filters(self):
        """
        Prepare filters to append in tcpdump command
        """
        filters = []
        if self.args.filters:
            filters = [ 'and '+_ for _ in self.args.filters.split(',') ]
        filters.append('and tcp[13] == 2')
        return ' '.join(filters)

    def invoke_tcpdump(self):
        """
        Invoke tcpdump command to self.tcpdump variable
        parameters: 
            -nn : no resolve hostnames or port names
            -l  : Single line output
            -S  : helps prevent "state accumulation" 
            -p  : promiscuous mode
        """
        interface = self.args.interface
        host_ip = self.args.address
        filters = self.prepare_filters()
        timeout = self.args.timeout or 10
        basecomm = 'tcpdump -nnlSp -i {}'.format(interface)
        command =  "timeout {} {} 'host {} {}' ".format(timeout, basecomm, 
                                                      host_ip, filters)
        print('='*80)
        print('{}COMMAND{}: {}'.format(self.REVERSE, self.ALL_OFF, command))
        print()
        self.tcpdump = Popen(command, stdout=PIPE, stderr=STDOUT, shell=True)

    def rule_timeout(self, pattern, filename):
        """
        Remove auto-added rule after x seconds
        """
        with open(filename, 'w') as f:
            f.write('ipfw -q -f flush\n')
        result = ckout('ipfw list', shell=True).decode('utf-8').split('\n')
        with open(filename, 'a') as f:
            for line in result:
                if pattern in line:
                    continue
                f.write('ipfw -q add ' + line + '\n')
        command = "nohup sleep {} && sh {}".format(self.args.rule_timeout, filename)
        command += " ; rm -f {} &".format(filename)
        Popen(command, stdout=PIPE, stderr=STDOUT, shell=True)

    def random_char(self, y):
        """
        Returns random chars to append in temporary filename
        """
        return ''.join(choice(ascii_letters) for x in range(y))

FW = AutoFirewallRules()
if __name__ == '__main__':
    FW.load_args()
    FW.invoke_tcpdump()
    if FW.args.connections:
        counter, max_tries = (FW.check_output(), FW.args.connections)
        FW.block_bruteforce_attempt(counter, max_tries)
    else: 
        FW.check_output()
    
