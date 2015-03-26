## Sample-IP

Run ping sweep against all subnets in hostlist.txt, then take a 5% sample of all the hosts that are up and write them to SampleIPs.txt

```./ip-sampler.py -l hostlist.txt```


Create pool of 5 workers instead of the default 10

```./ip-sampler.py -l hostlist.txt -w 10```


Take a 10% sample instead of the default 5% sample of hosts that are up across all subnets

```./ip-sampler.py -l hostlist.txt -p 5```
