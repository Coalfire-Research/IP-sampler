#! /usr/bin/env python2

import os
import re
import sys
import argparse
import random
import signal
from math import ceil
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from multiprocessing import Lock, Process, Queue, Pool

def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Enter the hosts list file")
    parser.add_argument("-p", "--percent", default=5, type=float, help="Enter the percent of IPs per netblock to sample")
    parser.add_argument("-w", "--workers", default=10, type=int, help="Enter the number of paralell workers")
    parser.add_argument("--portscan", action="store_true", help="Instead of doing an ICMP ping sweep, check for at least one of the top 5 ports to respond with SYN/ACK")
    return parser.parse_args()

def main(args):
    '''
    Set up async workers then print final results
    '''
    procs = []
    lock = Lock()
    q = Queue()
    pingtype = args.portscan
    percent = args.percent / float(100)

    if not args.hostlist:
        sys.exit('[-] Enter a hostlist file using the -l flag')

    hosts_list = open(args.hostlist, 'r').readlines()

    # Create list of netblocks
    for l in hosts_list:
        l = l.strip()
        q.put(l)

    # Can't use Pool because pool makes process daemonic which can't produce children
    # NmapProcess is a child of the worker process
    procs = []
    for w in xrange(args.workers):
        p = Process(target=worker, args=(q, lock, percent, pingtype))
        p.start()
        procs.append(p)
        q.put('STOP')

    for p in procs:
        p.join()

    if os.path.isfile('SampleIPs.txt'):
        print '[+] Check SampleIPs.txt for a random {0}% sample of total online hosts'.format(str(percent * 100))
    else:
        print '[-] No online hosts found'

def worker(q, lock, percent, pingtype):
    '''
    Create Nmap processes to ping sweep each subnet then add a percentage
    of the hosts that are up to the master sample list
    '''
    for netblock in iter(q.get, 'STOP'):
        if pingtype:
            nmap_args = '--top-ports 5 --max-rtt-timeout 150ms --max-retries 3'
        else:
            nmap_args = '-T4 -PE -sn --max-rtt-timeout 150ms --max-retries 3'
        print '[*] nmap {0} {1}'.format(nmap_args, netblock)
        nmap_proc = NmapProcess(targets=netblock, options=nmap_args)
        rc = nmap_proc.run()
        xml = nmap_proc.stdout
        try:
            report = NmapParser.parse(xml)
        except NmapParserException as e:
            print 'Exception raised while parsing scan: {0}'.format(e.msg)
            return

        subnet_hosts_up = []
        for host in report.hosts:
            if host.is_up():
                ip = host.address
                hostname = None
                if len(host.hostnames) != 0:
                    hostname = host.hostnames[0]
                if pingtype:
                    for s in host.services:
                        if re.search('open|filtered', s.state):
                            subnet_hosts_up.append(ip)
                            break
                else:
                    subnet_hosts_up.append(ip)

        num_hosts = float(len(subnet_hosts_up))
        random_sample_num = int(ceil(num_hosts * percent))

        sample = []
        for i in xrange(random_sample_num):
            s = random.choice(subnet_hosts_up)
            sample.append(s)

        print '[+] Hosts up in subnet {0}:'.format(netblock)
        for ip in sample:
            print '     ', ip

        if len(sample) > 0:
            with lock:
                with open('SampleIPs.txt', 'a+') as f:
                    for ip in sample:
                        f.write(ip+'\n')

main(parse_args())
