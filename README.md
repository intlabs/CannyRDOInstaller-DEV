openstack-rdo-scripts
=====================

RDO automatic deployment scripts

These were originally forked from https://github.com/cloudbase/openstack-rdo-scripts

They will (soon!) provide a production ready OpenStack Havana Enviroment, that can be depolyed on hardware or a virtual enviroment.

They are very much a work in progress! don't be surprised if its broken (like my grammar :)


IMMEDIATE ISSUES:
 - Icehouse install is not currently launching instances - this seems to be a icehouse bug not an installation one :(


I'm updating these for a physical installation initially following the tutorial from cloudbase (http://www.cloudbase.it/rdo-multi-node-havana/).

The configuration of the final depolyment will be as follows:

- controller:
 - Runs keystone, glance etc.

- dashboard:
 - Runs horizon

- fileserver:
 - Does not run any OpenStack Services
 - Runs iscsi backend for glance etc.

- network:
 - Runs neuron with openVSwitch (havana), ML2 (icehouse) and gre tunnels

- compute[1 to x]:
 - Runs nova-compute with kvm

These will be initially depolyed from the CentOS 6.5 minimal iso (http://mirror.ox.ac.uk/sites/mirror.centos.org/6.5/isos/x86_64/CentOS-6.5-x86_64-minimal.iso)
The machines may be physical or vitualised in VMware, with the following configuation:

- controller:
 - eth0: mangement network

- dashboard:
 - eth0: mangement network

- fileserver:
 - eth0: mangement network
 - 4 block devices at /dev/sdb -> /dev/sde (the last two will be used to make a lvm striped volume so match them!) - Installation will be destructive so be careful!

- network:
 - eth0: mangement network
 - eth1: vm data network
 - eth2: external network

- compute[1 to x]:
 - eth0: mangement network
 - eth1: vm data network

The servers should be installed without any configuration other than setting the eth0 (management network) to connect via dhcp, where:

- management network
  - Physical enviroment: >1Gb Ethernet, connected to unmanged switch (management switch)
  - Virtual enviroment: VMware Fusion "share with my mac"

- vm data network
  - Physical enviroment: >1Gb Ethernet, connected to unmanged switch (vm data switch)
  - Virtual enviroment: VMware Fusion "private to my mac"

- external network
  - Physical enviroment: >1Gb Ethernet, connected to gateway (OPT1,)
  - Virtual enviroment: VMware Fusion "share with my mac"

In a physical enviroment the additional components are required:

- gateway:
 - pfSense firewall configured with:
  - WAN:
   - Gets address via dhcp
  - LAN:
   - offers dhcp and dns
   - 192.168.0.0/24
   - fixed leases:
    - controller        192.168.0.11
    - dashboard        192.168.0.12
    - fileserver        192.168.0.10
    - network            192.168.0.13
    - compute[1 to x]    192.168.0.2x
   - NAT:
    - port [80] forwarded to 192.168.0.12 (dashboard)
  - OPT1:
   - offers dhcp
   - 192.168.1.0/24
   - fixed leases:
    - network            192.168.1.2
   - 1:1 NAT to 192.168.1.2

- management switch:
 - >1gb unamanged switch
 - connected to gateway (LAN)

- vm data switch:
 - >1gb unamanged switch

Eventually this script will do a few other things like:
 - Setup SELinux and firewalls properly
 - Run all services via SSL/TLS
 - PCI passthrough