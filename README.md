Mignis
======

Mignis is a semantic based tool for firewall configuration.

Mignis is designed to help writing iptables rules using an more human-readable syntax, without restricting iptables functionalities.

### Requirements
* Python 2.7 or higher (Python 3.x supported).
* [regex][], an alternative regular expression module. It can be installed manually by executing `easy_install regex`. This also requires the package python-dev as a dependency (execute `apt-get install python-dev` on a debian distribution).

<!--
[ipaddr-py][], a python IP address manipulation library. It can be installed manually by executing `easy_install ipaddr`.
-->

### Description
There are many possible ways to write a set of iptables rules for a specific purpose, we decided to use the following approach:

* define each interface and its corresponding subnet.
* bind the interface to the subnet (on the mangle-prerouting chain). This allows us to specify interfaces and/or IP addresses interchangeably (this is for example exploited in the translation of a masquerade rule).
* define default policies on the chains we use for filtering
* give higher priority to deny rules, so that they are placed before any other abstract firewall rule (this has to be kept in mind when writing rules).
* logging rules useful to analyze mismatched traffic

Rules' ordering is fundamental when writing iptables rules. Our approach instead allows to write a set of abstract **rules** which are **order-independent**.

### Usage
```
	usage: mignis.py [-h] -c filename [-d {0,1,2}] [-x] [-n] (-w filename | -e) [-f]
	
	A semantic based tool for firewall configuration
	
	optional arguments:
	  -h           show this help message and exit
	  -c filename  configuration file
	  -d {0,1,2}   set debugging output level (0-2)
	  -x           do not insert default rules
	  -n           do not execute the rules (dryrun)
	  -w filename  write the rules to file
	  -e           execute the rules without writing to file
	  -f           force rule execution or writing
```

Mignis takes a configuration file and generates a series of iptables rules.

Rules can either be written to a file (in a format parsable by the `iptables-restore` command) or directly executed via the `iptables` command.

Usage example:
```bash
./mignis.py -c ex_simple.config -w ex_simple.iptables
```

This will create an *ex_simple.iptables* file from the *ex_simple.config* configuration.
To actually use the rules we just have to execute `iptables-restore ex_simple.iptables`.

#### Configuration file example
```
INTERFACES
lan		eth0	10.0.0.0/24
ext		eth1	0.0.0.0/0

ALIASES
mypc			10.0.0.2
router_ext_ip	1.2.3.4
malicious_host	5.6.7.8

FIREWALL
# machines inside the lan are NAT'ed (using masquerade) when communicating through ext
lan [.] > ext

# forbid the communication with a malicious host
lan ! malicious_host

# dnat to mypc on port 8888
ext > [router_ext_ip:8888] mypc:8888	-p udp

# allow access to port 80 on this machine
ext > local:80

CUSTOM
# ssh
-A INPUT -p tcp --dport 22 -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED -j ACCEPT
```

Each configuration file needs 4 sections (beware of using the TAB character when specified):

* **INTERFACES**: defines each interface with their alias (which can be used when writing rules). The syntax is `alias <TAB> interface-name <TAB> subnet`.
* **ALIASES**: defines aliases for IP addresses. The syntax is `alias <TAB> ip-address`.
* **FIREWALL**: contains abstract rules. The syntax is `abstract-rule <TAB> iptables-filters`.

	First we define an *address*, which is either an interface, an alias or an IP address.

	An *abstract rule* is defined as follows:<br>
	`from [source_nat] opt [dest_nat] to`

	* *from* and *to* are addresses,
	* *source_nat* is the address *from* will be SNAT'ed to (it's possible to use "." to indicate a masquerade),
	* *dest_nat* is the address *to* will be DNAT'ed to,
	* *opt* is one of: "!" (deny), ">" (one-way forward), "<>" (two-way forward)

	Finally an *iptables filter* is any iptables option used for filtering packets.<br>
	Common options may be "-p udp", "-p tcp", "-p icmp --icmp-type echo-reply", etc.

* **CUSTOM**: contains raw iptables rules. Note that you can also modify the tool's behavior here, since you can use the _-D_ and _-I_ switch for deleting and inserting rules in specific locations. We provide this section to add more flexibility, but we cannot guarantee that your custom rules will not conflict with the abstract ones, so please use this section with care and only if you know what you're doing.

#### Firewall rules examples
Let's see some examples from the configuration above, to clearify how rules can be written and to see how they're translated into iptables rules.

1. ```lan [.] > ext```<br>
	Allows packets originating from the _lan_ interface to go to _ext_, using a source NAT (masquerade).

		iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
		iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
		iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth1 -j MASQUERADE
		

1. ```lan ! malicious_host```<br>
	Forbids the communication from the _lan_ towards a *malicious host*.

		iptables -A FORWARD -i eth0 -d 5.6.7.8 -j DROP

1. ```ext > [router_ext_ip:8888] mypc:8888	-p udp```<br>
	UDP packets originating from _ext_ to *router_ext_ip* on port 8888, are DNAT'ed to _mypc_ on port 8888.

		iptables -t mangle -A PREROUTING -p udp -i eth1 -d 10.0.0.2 --dport 8888 -m state --state NEW, INVALID -j DROP
		iptables -A FORWARD -p udp -i eth1 -d 10.0.0.2 --dport 8888 -j ACCEPT
		iptables -A FORWARD -p udp -s 10.0.0.2 --sport 8888 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
		iptables -t nat -A PREROUTING -p udp -i eth1 -d 1.2.3.4 --dport 8888 -j DNAT --to-destination 10.0.0.2:8888

	Note: the first mangle rule is used to block packets which are trying to reach _mypc_ bypassing the NAT.

1. ```ext > local:80```<br>
	Allow access from _ext_ to port 80 on the local machine.

		iptables -A INPUT -p tcp -i eth1 --dport 80 -j ACCEPT
		iptables -A OUTPUT -p tcp --sport 80 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT


### Future work
* Abstract-level rules optimizations.
* Accept different kinds of configuration files (e.g. JSON, python scripts) and/or consider a richer language for writing the rules.
* Improve checks for identifying overlapping rules.
* Provide a 2nd-level abstract semantic using security roles.

[ipaddr-py]:	https://code.google.com/p/ipaddr-py/
[regex]:		https://pypi.python.org/pypi/regex/
