Mignis
======

Mignis is a semantic based tool for firewall configuration.

Mignis is designed to help writing iptables rules using an more human-readable syntax, without restricting iptables functionalities.

### Requirements
* Python 2.7 or higher (Python 3.x supported).

<!--
* [regex][], an alternative regular expression module. It can be installed manually by executing `easy_install regex`. This also requires the package python-dev as a dependency (execute `apt-get install python-dev` on a debian distribution).
-->

<!--
[ipaddr-py][], a python IP address manipulation library. It can be installed manually by executing `easy_install ipaddr`.
-->

### Description
There are many possible ways to write a set of iptables rules for a specific purpose, we decided to use the following approach:

* define each interface and its corresponding subnet.
* bind the interface to the subnet (on the mangle-prerouting chain). This allows us to specify interfaces and/or IP addresses interchangeably (this is for example exploited in the translation of a masquerade rule).
* give higher priority to deny rules, so that they are placed before any other abstract firewall rule (this has to be kept in mind when writing rules).
* use logging rules to analyze mismatched traffic (which will be dropped).

Rules' ordering is fundamental when writing iptables rules. Our approach instead allows to write a set of abstract **rules** which are **order-independent**.

### Usage
```
    usage: mignis.py [-h] -c filename (-w filename | -e | -q query) [-d {0,1,2,3}]
                     [-n] [-f]

    A semantic based tool for firewall configuration

    optional arguments:
      -h            show this help message and exit
      -c filename   configuration file
      -w filename   write the rules to file
      -e            execute the rules without writing to file
      -q query      perform a query over the configuration (unstable)
      -d {0,1,2,3}  set debugging output level (0-2)
      -n            do not execute/write the rules (dryrun)
      -f            force rule execution or writing
```

Mignis takes a configuration file and generates a series of iptables rules.

Rules can either be written to a file (in a format parsable by the `iptables-restore` command) or directly executed via the `iptables` command.

Usage example:
```bash
./mignis.py -c config/ex_simple.config -w ex_simple.iptables
```

This will create an *ex_simple.iptables* file from the *ex_simple.config* configuration.
To actually use the rules we just have to execute `iptables-restore ex_simple.iptables`.

#### Configuration file example
```
OPTIONS
default_rules   yes
logging         no

INTERFACES
lan     eth0    10.0.0.0/24
ext     eth1    0.0.0.0/0
dummy   eth2    none         ignore

ALIASES
mypc            10.0.0.2
router_ext_ip   1.2.3.4
malicious_host  5.6.7.8

FIREWALL
# ssh accessible from the outside
* > local:22  tcp

# machines inside the lan are NAT'ed (using masquerade) when communicating through ext
lan [.] > ext

# forbid the communication with a malicious host
lan / malicious_host

# dnat to mypc on port 8888
ext > [router_ext_ip:8888] mypc:8888  udp

# allow access to port 80 on this machine
ext > local:80  tcp

POLICIES
* // *  icmp
* // *  udp
* / *

CUSTOM
# log and accept packets on port 7792
-A INPUT -p tcp --dport 7792 -j LOG --log-prefix "PORT 7792 "
-A INPUT -p tcp --dport 7792 -j ACCEPT
```

Each configuration file needs 6 sections:

* **OPTIONS**: at the moment two generic mignis options can be specified:

    * `default_rules` is used to choose whether to insert default rules or not. Default rules are usually safe to use and are hardcoded into mignis and concern broadcast/multicast packets, invalid packets drops and localhost loopback communication.
    * `logging` is used to choose whether to log unexplicitly dropped packets or not (i.e. packets which don't match any rule and get dropped by the default policy).

* **INTERFACES**: defines each interface with their alias (which can be used when writing rules). The syntax is `alias interface-name subnet options`. If the interface doesn't have an ip address the keyword `none` must be used in place of the subnet. At the moment the only option allowed is `ignore`, which is used to tell mignis to always allow traffic on that interface (i.e. it is not taken into account in firewall rules).
* **ALIASES**: defines aliases for IP addresses. The syntax is `alias ip-address`.
* **FIREWALL**: contains abstract rules. The syntax is `abstract-rule | iptables-filters`.

    First we define an *address*, which is either an interface, an alias or an IP address.

    An *abstract rule* is defined as follows:<br>
    `from [source_nat] opt [dest_nat] to`

    * *from* and *to* are addresses,
    * *source_nat* is the address *from* will be SNAT'ed to (it's possible to use "." to indicate a masquerade),
    * *dest_nat* is the address *to* will be DNAT'ed to,
    * *opt* is one of: "/" (deny with DROP), "//" (deny with REJECT), ">" (one-way forward), "<>" (two-way forward)

    Finally an *iptables filter* is any iptables option used for filtering packets.<br>
    Common options may be "--icmp-type echo-reply", "-m module", etc.

* **POLICIES**: the default mignis behavior for unmatched packets is to drop them. This section is useful if one wants to reject packets instead, using the mignis syntax for rules matching (only drop or reject rules can be specified). In the example we are rejecting icmp and udp packets, while we're dropping the rest (this last rule may be omitted, we wrote it there only for clarity).

* **CUSTOM**: contains raw iptables rules. Note that you can also modify the tool's behavior here, since you can use the _-D_ and _-I_ switches for deleting and inserting rules in specific locations. We provide this section to add more flexibility, but we cannot guarantee that your custom rules will not conflict with the abstract ones, so please use this section with care and only if you know what you're doing.

#### Firewall rules examples
Let's see some examples from the configuration above, to clearify how rules can be written and to see how they're translated into iptables rules.

1. ```* > local:22  tcp```<br>
    Allows _ssh_ (tcp port 22) connections towards localhost from any interface.

        iptables -A INPUT -p tcp --dport 22 -j ACCEPT

1. ```lan [.] > ext```<br>
    Allows packets originating from the _lan_ interface to go to _ext_, using a source NAT (masquerade).

        iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
        iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth1 -j MASQUERADE

1. ```lan / malicious_host```<br>
    Forbids the communication from the _lan_ towards a *malicious host*.

        iptables -A FORWARD -i eth0 -d 5.6.7.8 -j DROP

1. ```ext > [router_ext_ip:8888] mypc:8888  udp```<br>
    UDP packets originating from _ext_ to *router_ext_ip* on port 8888, are DNAT'ed to _mypc_ on port 8888.

        iptables -t mangle -A PREROUTING -p udp -i eth1 -d 10.0.0.2 --dport 8888 -m state --state NEW, INVALID -j DROP
        iptables -A FORWARD -p udp -i eth1 -d 10.0.0.2 --dport 8888 -j ACCEPT
        iptables -t nat -A PREROUTING -p udp -i eth1 -d 1.2.3.4 --dport 8888 -j DNAT --to-destination 10.0.0.2:8888

    Note: the first mangle rule is used to block packets which are trying to reach _mypc_ bypassing the NAT.

1. ```ext > local:80  tcp```<br>
    Allow access from _ext_ to port 80 on the local machine.

        iptables -A INPUT -p tcp -i eth1 --dport 80 -j ACCEPT


### Work in progress features (still unstable)
* Lists operations for excluding hosts/lists from a list. For example if we define a list alias "list1 (eth0, eth1)" and want a rule that is valid for _list1_ except for the host _1.1.1.1_ (which belongs to the interface _eth0_), we can write ```list1/1.1.1.1 > eth2```.
* Improving checks for identifying overlapping rules.
* Rules queries to list all the connections that match a particular host, this is useful to see all the packets a host can send/receive. This has to be expanded with lists and rules (exploiting the overlapping checks).

### Future work
* Abstract-level rules optimizations.
* Accept different kinds of configuration files (e.g. JSON, python scripts) and/or consider a richer language for writing the rules.
* Provide a 2nd-level abstract semantic using security roles.

[ipaddr-py]:    https://code.google.com/p/ipaddr-py/
[regex]:        https://pypi.python.org/pypi/regex/
