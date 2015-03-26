## IP-sampler

Give the script a newline separated list of subnets and it will scan each subnet for live hosts then write a certain percentage (5% by default) of random live IPs from each subnet to a SampleIPs.txt.

#### Requirements

Just needs python-libnmap

```
sudo pip install -r requirements.txt
```

#### Usage


Run an ICMP ping sweep against all subnets in hostlist.txt, then take a 5% sample from of all the hosts that are up within each subnet and write them to SampleIPs.txt

```./ip-sampler.py -l hostlist.txt```


Run an ARP ping sweep against all subnets in hostlist.txt

```./ip-sampler.py -l hostlist.txt --arpscan```


Run a top 5 port scan against all subnets in hostlist.txt and collect a 5% sample of all hosts that respond with at least one port open

```./ip-sampler.py -l hostlist.txt --portscan```


Create pool of 5 workers instead of the default 10

```./ip-sampler.py -l hostlist.txt -w 5```


Take a 10% sample instead of the default 5% sample of hosts that are up across all subnets

```./ip-sampler.py -l hostlist.txt -p 10```
