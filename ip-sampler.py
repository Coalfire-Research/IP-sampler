#! /usr/bin/env python2

import sys
import os
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
    return parser.parse_args()

def main(args):
    '''
    Set up async workers then print final results
    '''
    procs = []
    lock = Lock()
    q = Queue()
    percent = args.percent / float(100)

    hosts_list = open(args.hostlist, 'r').readlines()

    # Create list of netblocks
    #netblocks =[]
    for l in hosts_list:
        l = l.strip()
        q.put(l)
        #netblocks.append(l)

    # Set max number of workers
    #pool = Pool(args.workers)

    procs = []
    # Can't use Pool because pool makes process daemonic which can't produce children
    # NmapProcess is a child of the worker process
    for w in xrange(args.workers):
        p = Process(target=worker, args=(q, lock, percent))
        #p.daemon = True
        p.start()
        procs.append(p)
        q.put('STOP')

    for p in procs:
        p.join()

    print '[*] {0}% of total online hosts:'.format(str(percent * 100))
    with open('SampleIPs.txt', 'r') as f:
        print f.read()

    #for netblock in netblocks:
    #    proc = pool.apply_async(worker, (netblock, percent))
    #    proc.daemon = False
    #    procs.append(proc)
    ##pool.close()
    #for proc in procs:
    #    print proc.get()

def worker(q, lock, percent):
    '''
    Create Nmap processes to ping sweep each subnet then add a percentage
    of the hosts that are up to the master sample list
    '''
    for netblock in iter(q.get, 'STOP'):
        nmap_args = '-T4 -sn --max-rtt-timeout 150ms --max-retries 3'
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
                print ip, hostname
                if hostname:
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
