Mignis
======

Mignis is a semantic based tool for firewall configuration. It is designed to help
writing **iptables rules** using a more **human-readable syntax**,
without restricting iptables functionalities. It can also generate Linux
Traffic Control rules for egress and ingress bandwidth limits.

The traslation from Mignis syntax into the corresponding iptables ruleset has been
**formally verified** in a paper published in Computer Security Foundations Symposium (CSF), 2014:

-  `Mignis: A Semantic Based Tool for Firewall Configuration <http://ieeexplore.ieee.org/abstract/document/6957122/>`_
-  `Extended version <https://www.math.tecnico.ulisboa.pt/~padao/projects/ComFormCrypt/report3/papers-submitted/SUB-Mignis.pdf>`_

Requirements
~~~~~~~~~~~~

-  Python 3.6 or higher.
-  No external Python package dependencies (uses the standard library
   ``ipaddress`` module).
-  ``iptables`` for firewall rule execution.
-  ``ip`` and ``tc`` from ``iproute2`` when using the optional ``LIMITS``
   section. Ingress shaping also requires Linux IFB support.

Installation
~~~~~~~~~~~~

Latest working version is available on PyPI:

``pip install mignis``

Most up-to-date way is to directly install the master branch from GitHub:

``pip install --upgrade git+https://github.com/secgroup/Mignis.git``

Description
~~~~~~~~~~~

There are many possible ways to write a set of iptables rules for a
specific purpose, we decided to use the following approach:

-  define each interface and its corresponding subnet.
-  bind the interface to the subnet (on the mangle-prerouting chain).
   This allows us to specify interfaces and/or IP addresses
   interchangeably (this is for example exploited in the translation of
   a masquerade rule).
-  give higher priority to deny rules, so that they are placed before
   any other abstract firewall rule (this has to be kept in mind when
   writing rules).
-  use logging rules to analyze mismatched traffic (which will be
   dropped).

Rules' ordering is fundamental when writing iptables rules. Our approach
instead allows to write a set of abstract **rules** which are
**order-independent**.

Usage
~~~~~

::

        usage: mignis.py [--help] [-F] [-c filename] [-w filename | -e | -q query]
                 [-d {0,1,2,3}] [-n] [-f]

        A semantic based tool for firewall configuration

        optional arguments:
          --help, -h            show this help message and exit
          -d {0,1,2,3}, --debug {0,1,2,3}
                                set debugging output level (0-2)
          -n, --dryrun          do not execute/write the rules (dryrun)
          -f, --force           force rule execution or writing

        possible actions::
          -F, --flush           flush iptables ruleset and Mignis traffic shaping
          -c filename, --config filename
                                read mignis rules from file

        options for --config/-c:
          -w filename, --write filename
                                write rules to file (plus .tc/.tc.sh when shaping)
          -e, --execute         execute the rules without writing to file
          -q query, --query query
                                perform a query over the configuration (unstable)

Mignis takes a configuration file and generates a series of iptables
rules and, when requested, traffic-control rules.

Rules can either be written to files or directly applied. Without traffic
limits, ``-w`` keeps its original behavior and writes only an
``iptables-restore`` file. When ``LIMITS`` is present, it also writes a
``.tc`` sidecar suitable for ``tc -batch``. Configurations with ingress
limits additionally get an executable ``.tc.sh`` runner that safely creates
the required IFB interfaces and ``clsact`` qdiscs before loading the batch.

Usage example:

.. code:: bash

    ./mignis.py -c config/ex_simple.config -w ex_simple.iptables

This will create an *ex\_simple.iptables* file from the
*ex\_simple.config* configuration. To actually use the rules we just
have to execute ``iptables-restore ex_simple.iptables``.

For a configuration containing bandwidth limits:

.. code:: bash

    ./mignis.py -c examples/ex_limits.config -w ex_limits.iptables
    iptables-restore ex_limits.iptables
    ./ex_limits.iptables.tc.sh

For an egress-only configuration, the last command can remain
``tc -batch ex_limits.iptables.tc``.

Configuration file example
^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    OPTIONS
    default_rules   yes
    logging         no

    INTERFACES
    lan     eth0    10.0.0.0/24
    ext     eth1    0.0.0.0/0    wan
    dummy   eth2    none         ignore
    vpn     tun0    10.8.0.0/24

    ALIASES
    mypc            10.0.0.2
    router_ext_ip   1.2.3.4
    malicious_host  5.6.7.8
    host_over_vpn   10.8.0.123
    remote_host_1   20.20.20.1
    remote_host_2   30.30.30.2
    remote_host_3   40.40.40.3
    remote_hosts    (remote_host_1, remote_host_2, remote_host_3)

    FIREWALL
    # no restrictions on outgoing connections
    local > *

    # ssh accessible from the outside
    * > local:22  tcp

    # machines inside the lan are NAT'ed (using masquerade) when communicating through ext
    lan [.] > ext

    # forbid the communication with a malicious host
    lan / malicious_host

    # dnat to mypc on port 8888
    ext > [router_ext_ip:8888] mypc:8888  udp

    # dnat to mypc on port 443 with NAT reflection (hairpinning)
    ext > [router_ext_ip:443] mypc:443  tcp | reflection

    # dnat to host_over_vpn on port 9999 with masquerade
    ext [.] > [router_ext_ip:9999] host_over_vpn:9999  tcp

    # allow access to port 80 and 443 on this machine
    ext > local:(80, 443)  tcp

    # allow only a limited set of hosts to access our vpn
    remote_hosts > local:1194  udp

    POLICIES
    * // *  icmp
    * // *  udp
    * / *

    LIMITS
    # aggregate WAN egress ceiling
    on ext egress * > * 100mbit

    # shape traffic as it enters the router from the LAN
    on lan ingress * > * 100mbit
    on lan ingress mypc > * 10mbit

    # aggregate LAN egress and download ceiling for mypc
    on lan egress * > * 100mbit
    on lan egress * > mypc 25mbit

    CUSTOM
    # log and accept packets on port 7792
    -A INPUT -p tcp --dport 7792 -j LOG --log-prefix "PORT 7792 "
    -A INPUT -p tcp --dport 7792 -j ACCEPT

Each configuration file needs 6 sections. ``LIMITS`` is an optional
seventh section:

-  **OPTIONS**: at the moment two generic mignis options can be
   specified:

   -  ``default_rules`` is used to choose whether to insert default
      rules or not. Default rules are usually safe to use and are
      hardcoded into mignis and concern broadcast/multicast packets,
      invalid packets drops and localhost loopback communication.
   -  ``logging`` is used to choose whether to log unexplicitly dropped
      packets or not (i.e. packets which don't match any rule and get
      dropped by the default policy).

-  **INTERFACES**: defines each interface with their alias (which can be
   used when writing rules). The syntax is
   ``alias interface-name subnet options``. If the interface doesn't
   have an ip address the keyword ``none`` must be used in place of the
   subnet. Available options are:

   -  ``ignore``: always allow traffic on that interface (i.e.
      it is not taken into account in firewall rules).
   -  ``wan``: marks the interface as a WAN interface. This is used by
      NAT reflection to identify which interfaces are external and
      which are internal (LAN). Hairpin rules are generated for all
      non-WAN interfaces.
   -  ``pub=IP``: specifies the real public IP address for NAT reflection
      when the WAN interface is behind a double NAT (e.g. ISP router).
      In this case, the DNAT rules use the local WAN IP for external
      traffic, while hairpin rules use the public IP that LAN clients
      connect to. Example: ``ext eth0 172.16.21.0/24 wan pub=93.92.241.21``
-  **ALIASES**: defines aliases for IP addresses. The syntax is
   ``alias ip-address``.
-  **FIREWALL**: contains abstract rules. The syntax is
   ``abstract-rule | iptables-filters``.

   First we define an *address*, which is either an interface, an alias
   or an IP address.

   An *abstract rule* is defined as follows:
   ``from [source_nat] opt [dest_nat] to``

   -  *from* and *to* are addresses,
   -  *source\_nat* is the address *from* will be SNAT'ed to (it's
      possible to use "." to indicate a masquerade),
   -  *dest\_nat* is the address *to* will be DNAT'ed to,
   -  *opt* is one of: "/" (deny with DROP), "//" (deny with REJECT),
      ">" (one-way forward), "<>" (two-way forward)

   Finally an *iptables filter* is any iptables option used for
   filtering packets. Common options may be "--icmp-type echo-reply",
   "-m module", etc.

   A special ``reflection`` modifier can be added to DNAT rules to enable
   NAT reflection (hairpinning). This allows LAN clients to access
   services via the gateway's public IP address. When enabled, additional
   DNAT, FORWARD and MASQUERADE rules are generated for each non-WAN
   interface. Example: ``ext > [public_ip:443] server:443 tcp | reflection``

-  **POLICIES**: the default mignis behavior for unmatched packets is to
   drop them. This section is useful if one wants to reject packets
   instead, using the mignis syntax for rules matching (only drop or
   reject rules can be specified). In the example we are rejecting icmp
   and udp packets, while we're dropping the rest (this last rule may be
   omitted, we wrote it there only for clarity).

-  **LIMITS**: optionally defines bandwidth ceilings using:
   ``on interface direction from > to rate``, where ``direction`` must be
   either ``egress`` or ``ingress``. The interface is a Mignis interface
   alias. ``from`` and ``to`` can be ``*``, an interface alias, an IP
   alias, an IPv4 address or an IPv4 subnet. The special ``local`` alias
   is not currently a selector; use a concrete local IPv4 address instead.
   Rates accept ``bit``, ``kbit``, ``mbit`` and ``gbit``.

   Every shaped interface and direction must have exactly one aggregate
   ``* > *`` limit. More specific limits become child classes and cannot
   exceed the aggregate rate:

   ::

       LIMITS
       on ext egress * > * 100mbit
       on lan ingress * > * 100mbit
       on lan ingress mypc > * 10mbit
       on lan egress * > * 100mbit
       on lan egress * > mypc 25mbit

   Egress limits use HTB plus packet marks on the selected physical
   interface. Ingress limits redirect packets from that interface to a
   Mignis-owned IFB and apply HTB there. In the example, traffic entering
   the router from ``lan`` is capped at 100 Mbit/s and traffic sourced by
   ``mypc`` at 10 Mbit/s. Traffic leaving ``lan`` is capped at 100 Mbit/s
   and traffic destined for ``mypc`` at 25 Mbit/s. The specific limits are
   ceilings, not bandwidth reservations.

   Ingress selectors see packets before routing and NAT. For example, a
   destination selector on WAN ingress sees the public destination of a
   DNAT flow, not the translated private address. Specific selectors on
   the same interface and in the same direction must not overlap. Mignis
   rejects ambiguous overlaps rather than making their meaning depend on
   configuration order.

-  **CUSTOM**: contains raw iptables rules. Note that you can also
   modify the tool's behavior here, since you can use the *-D* and *-I*
   switches for deleting and inserting rules in specific locations. We
   provide this section to add more flexibility, but we cannot guarantee
   that your custom rules will not conflict with the abstract ones, so
   please use this section with care and only if you know what you're
   doing.

Traffic shaping behavior
^^^^^^^^^^^^^^^^^^^^^^^^

Traffic limits apply to IPv4 egress and ingress traffic. Both directions
use an HTB hierarchy with ``fq_codel`` leaf queues. Egress packets are
classified in ``mangle/POSTROUTING`` before source NAT and selected by
``tc`` through firewall marks. The upper 16 bits of the packet mark are
reserved for this purpose; the lower 16 bits are preserved. Ingress
packets are redirected through a Mignis-owned IFB and classified with
``flower``.

Ingress and egress can be enabled simultaneously, including on the same
physical interface. Egress uses its root qdisc, while ingress uses a
``clsact`` redirect plus the IFB root qdisc.

Interactive execution reports existing non-Mignis traffic-control state
before asking for confirmation; ``--force`` explicitly permits its
replacement. Mignis records managed interfaces and IFBs in
``/run/mignis/tc-state.json``. Applying a later configuration without a
previously managed direction, or running ``--flush``, removes only
Mignis-owned qdiscs, redirect filters and IFBs.

Firewall rules examples
^^^^^^^^^^^^^^^^^^^^^^^

Let's see some examples from the configuration above, to clearify how
rules can be written and to see how they're translated into iptables
rules.

1. ``* > local:22  tcp``\  Allows *ssh* (tcp port 22) connections
   towards localhost from any interface.

   ::

       iptables -A INPUT -p tcp --dport 22 -j ACCEPT

2. ``lan [.] > ext``\  Allows packets originating from the *lan*
   interface to go to *ext*, using a source NAT (masquerade).

   ::

       iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
       iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth1 -j MASQUERADE

3. ``lan / malicious_host``\  Forbids the communication from the *lan*
   towards a *malicious host*.

   ::

       iptables -A FORWARD -i eth0 -d 5.6.7.8 -j DROP

4. ``ext > [router_ext_ip:8888] mypc:8888  udp``\  UDP packets
   originating from *ext* to *router\_ext\_ip* on port 8888, are DNAT'ed
   to *mypc* on port 8888.

   ::

       iptables -t mangle -A PREROUTING -p udp -i eth1 -d 10.0.0.2 --dport 8888 -m state --state NEW -j DROP
       iptables -A FORWARD -p udp -i eth1 -d 10.0.0.2 --dport 8888 -j ACCEPT
       iptables -t nat -A PREROUTING -p udp -i eth1 -d 1.2.3.4 --dport 8888 -j DNAT --to-destination 10.0.0.2:8888

   Note: the first mangle rule is used to block packets which are trying
   to reach *mypc* bypassing the NAT.

5. ``ext [.] > [router_ext_ip:9999] host_over_vpn:9999  tcp``\  TCP packets
   originating from *ext* to *router\_ext\_ip* on port 9999, are DNAT'ed
   to *host\_over\_vpn* on port 9999 using a source NAT (masquerade). The masquerade
   ensures that answers from *host\_over\_vpn* are routed through the vpn interface.

   ::

       iptables -t mangle -A PREROUTING -p tcp -i eth1 -d 10.8.0.123 --dport 9999 -m state --state NEW -j DROP
       iptables -A FORWARD -p tcp -i eth1 -d 10.8.0.123 --dport 9999 -j ACCEPT
       iptables -t nat -A POSTROUTING -p tcp -s 0.0.0.0/0 -d 10.8.0.123 --dport 9999 -j MASQUERADE
       iptables -t nat -A PREROUTING -p tcp -i eth1 -d 1.2.3.4 --dport 9999 -j DNAT --to-destination 10.8.0.123:9999

   Note: the first mangle rule is used to block packets which are trying
   to reach *host\_over\_vpn* bypassing the NAT.

6. ``ext > local:(80, 443)  tcp``\  Allow access from *ext* to port 80 and 443 on the
   local machine.

   ::

       iptables -A INPUT -p tcp -i eth1 --dport 80 -j ACCEPT
       iptables -A INPUT -p tcp -i eth1 --dport 443 -j ACCEPT

7. ``remote_hosts > local:1194  udp``\  Only the list of hosts specified in *remote\_hosts* can connect to our VPN.

   ::

       iptables -A INPUT -p udp -s 20.20.20.1 --dport 1194 -j ACCEPT
       iptables -A INPUT -p udp -s 30.30.30.2 --dport 1194 -j ACCEPT
       iptables -A INPUT -p udp -s 40.40.40.3 --dport 1194 -j ACCEPT

8. ``ext > [router_ext_ip:443] mypc:443  tcp | reflection``\  TCP packets
   originating from *ext* to *router\_ext\_ip* on port 443, are DNAT'ed
   to *mypc* on port 443. The ``reflection`` modifier also generates hairpin
   rules so that LAN clients can access the service via the public IP.

   ::

       iptables -t mangle -A PREROUTING -p tcp -i eth1 -d 10.0.0.2 --dport 443 -m state --state NEW -j DROP
       iptables -A FORWARD -p tcp -i eth1 -d 10.0.0.2 --dport 443 -j ACCEPT
       iptables -t nat -A PREROUTING -p tcp -i eth1 -d 1.2.3.4 --dport 443 -j DNAT --to-destination 10.0.0.2:443

   For each non-WAN interface (e.g. *lan*), the following hairpin rules are added:

   ::

       iptables -A FORWARD -p tcp -i eth0 -d 10.0.0.2 --dport 443 -j ACCEPT
       iptables -t nat -A PREROUTING -p tcp -i eth0 -d 1.2.3.4 --dport 443 -j DNAT --to-destination 10.0.0.2:443
       iptables -t nat -A POSTROUTING -p tcp -s 10.0.0.0/24 -d 10.0.0.2 --dport 443 -j MASQUERADE

   Note: the MASQUERADE rule rewrites the source to the router's LAN IP,
   ensuring replies go through the router for proper de-NAT.


Work in progress features (still unstable)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Lists operations for excluding hosts/lists from a list. For example
   if we define a list alias "list1 (eth0, eth1)" and want a rule that
   is valid for *list1* except for the host *1.1.1.1* (which belongs to
   the interface *eth0*), we can write ``list1/1.1.1.1 > eth2``.
-  Improving checks for identifying overlapping rules.
-  Rules queries to list all the connections that match a particular
   host, this is useful to see all the packets a host can send/receive.
   This has to be expanded with lists and rules (exploiting the
   overlapping checks).

Future work for Mignis v2
~~~~~~~~~~~~~~~~~~~~~~~~~

-  Complete code rewrite with a modular compiler-like design.
-  Support multiple firewall languages (iptables, nftables, Cisco, etc.)
-  Abstract-level rules optimizations.
-  Accept different kinds of configuration files (e.g. JSON, python
   scripts) and/or consider a richer language for writing the rules.
-  Provide a 2nd-level abstract semantic using security roles.

Testing
~~~~~~~

The deterministic parser and rule-generation tests use only the Python
standard library:

.. code:: bash

    python3 -m unittest discover -s tests -v

An end-to-end Docker laboratory routes two clients through a Mignis
container and checks aggregate and per-IP ceilings in both directions
with ``iperf3``. It also verifies reapplication, direction changes and
cleanup:

.. code:: bash

    tests/integration/traffic_shaping/run.sh

The Docker test requires access to the Docker daemon. The router and
clients receive ``NET_ADMIN``; privileged mode is not required.
