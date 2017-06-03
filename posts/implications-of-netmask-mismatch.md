.. title: Possible implications of netmask mismatch
.. slug: netmask-mismatch
.. date: 2015-10-03 13:51:00
.. tags: network
.. description: 

**Summary:** an IPv4 host with a netmask not matching that of the subnet to which the interface is connected likely builds incorrect routing tables, misses some broadcasts, may incorrectly identify broadcasts as unicasts, and unintentionally broadcast to own subnet.

## What does it mean - a "wrong netmask"?

The _netmask_ (in IPv4 terminology) and _network prefix_ (in IPv6 terminology)
can be associated with an _IP subnet_, and correspondingly with a 
_network interface_. This post handles IPv4 only, so the term "netmask"
will be used. Together with own IP address, the netmask determines whether
another IP address belongs to the same IP subnet as the NIC.

Good, so how is this knowledge used?

Processing of **multicast** packets is not affected by the netmask,
thus multicast would not be mentioned here further. For **unicast**
and **broadcast**, the netmask is consulted in three different situations,
listed in the following sections.

## Case 1. Netmask can be used as input for constructing the routing table.

The routing system normally automatically creates routes to the subnet
to which each network interface belongs. I.e. for each network interface
`I` with address `AI` and netmask `M`, the host calculates the subnet of
this interface as `SI = AI & M`.
Outgoing packets to any address `AP` such that `AP & M = SI` would be
emitted from the interface `I`.

While this behavior is typical, nothing mandates hosts to create such
routing table entry. For example, if a host has two interfaces on the
same subnet, then obviously some more information is needed to decide,
which of the interfaces shall emit the packets destined to their common
subnet. Another example is a firewall with more restrictive forwarding
policy than just _"put every packet for subnet `SI` to interface `I`"_.

## Case 2. Netmask is used to determine whether an arrived packet is a (directed) broadcast to a subnet of some local interface.

After the routing is covered, we can limit our further 
investigation to only:

* **Unicast** packets, destined to "this host" (i.e. one of its interfaces).
* **Directed broadcast** packets to "this network". There can be more than 
  one "this" network if the host has more than one network interface
  (the host can be or not be a router).

Really,

* **Directed broadcast** to a network not in "our network" set is handled as
  any other packet subject to possible routing.
* **Local broadcast** packets are obviously not affected by the netmask
  setting.

For hosts which are **not routers** [RFC922](https://tools.ietf.org/html/rfc922)
defines handling of broadcast packets in a simple way:

    In the absence of broadcasting, a host determines if it is the
    recipient of a datagram by matching the destination address against
    all of its IP addresses.  With broadcasting, a host must compare the
    destination address not only against the host's addresses, but also
    against the possible broadcast addresses for that host.

Now imagine that an interface of some host has netmask, which does not
match one of the subnet this interface is connected to. This is what
happens.

### Netmask of the interface is shorter

* Interface misconfigured with a **shorter netmask** fails to process broadcasts:
  they are understood as unicasts by such host.

  * Example: in `/24` network <span style="color: red;">1.1.1</span>.<span style="color: #38761d;">0</span>, a packet to a broadcast address <span style="color: red;">1.1.1</span>.<span style="color: #38761d;">255</span> will not be recognized as broadcast by a misconfigured interface <span style="color: red;">1.1</span>.<span style="color: #38761d;">1.1</span>/16.

  That is, unless the network has all bits in the netmask difference equal to 1.

  * Example: in `/24` network <span style="color: red;">1.1.255</span>.<span style="color: #38761d;">0</span>, </i>a packet to a broadcast address <span style="color: red;">1.1.255</span>.<span style="color: #38761d;">255</span> will be, by a coincidence, correctly accepted as broadcast by a misconfigured interface <span style="color: red;">1.1</span>.<span style="color: #38761d;">1.1</span>/16.

* Broadcast packet which is incorrectly understood as unicast by a 
  misconfigured interface can also happen to bear the destination address
  of this interface itself.

  * Example: in `/16` network <span style="color: red;">1.1</span>.<span style="color: #38761d;">0.0</span>, a broadcast packet to <span style="color: red;">1.1</span>.<span style="color: #38761d;">255.255</span> will be received as unicast by a misconfigured interface <span style="color: red;">1</span>.<span style="color: #38761d;">1.255.255</span>/8.

* Additionally, the host may attempt to send a unicast packet which would
  appear as a valid broadcast on the network.

  * Example: in `/16` network <span style="color: red;">1.1</span>.<span style="color: #38761d;">0.0</span>, a host misconfigured as <span style="color: red;">1</span>.<span style="color: #38761d;">1.1.1</span>/8 sends a unicast to destination address <span style="color: red;">1</span>.<span style="color: #38761d;">1.255.255</span>. It appears as broadcast on this network. In fact, there can be no host with address <span style="color: red;">1.1</span>.<span style="color: #38761d;">255.255</span> on this network (as it is a broadcast address), so nobody answers ARP query and the host will not be able to send such packet.

### Netmask of the interface is longer

* Interface misconfigured with a **longer netmask** fails to process broadcasts
as well: it will consider them not belonging to own subnet.

  * Example: in `/8` network <span style="color: red;">1</span>.<span style="color: #38761d;">0.0.0</span>, a packet to a broadcast address <span style="color: red;">1</span>.<span style="color: #38761d;">255.255.255</span> will not be received by a misconfigured interface <span style="color: red;">1.1</span>.<span style="color: #38761d;">1.1</span>/16.

  Again, unless the address of the misconfigured interface happens to have
  all bits in the netmask difference being equal to 1.

  * Example: in that same network, that same broadcast packet will be
    accepted just fine by a misconfigured interface
    <span style="color: red;">1.255</span>.<span style="color: #38761d;">1.1</span>/16.


For hosts which **are routers**, RFC922 adds the clause concerning for broadcast packets destined to other interface than the one on which the packet is received:

    ...if the datagram is addressed to a hardware network
    to which the gateway is connected, it should be sent as a
    (data link layer) broadcast on that network.  Again, the
    gateway should consider itself a destination of the datagram.

In this case, the netmask of the router's interface, where the packet has been received, is not relevant - packet should be processed anyway. Instead, the packet's destination interface configuration is the basis for the decision. Correspondingly, mismatch between the netmask of the destination interface and the sender's expectation of the netmask leads to same consequences as listed above for non-forwarding hosts.

Have we covered all cases? Three independent factors affect the outcome:

* Is the receiver's netmask shorter or longer than of the subnet it is connected to?
* Are the bits from the difference in netmask lengths all equal to one?
* Is the packet unicast or (directed) broadcast?

All 8 possibilities have been considered above.

## Case 3. Netmask is used for setting destination address of outgoing broadcast packets.

When a host wishes to send a broadcast packet from certain interface,
it sets the destination address to that of the interface and puts `1` to
all bits which are zeros in the netmask. Correspondingly:

### Netmask of the network interface is shorter

Host with **shorter netmask** will set too many bits to `1`.
On the local subnet, these packets will be recognized as belonging
to other subnet by other hosts and consequently not processed.

* Example: in `/24` network <span style="color: red;">1.1.1</span>.<span style="color: #38761d;">0</span>/24, host misconfigured as <span style="color: red;">1.1</span>.<span style="color: #38761d;">1.1</span>/16 sends what it thinks a "broadcast" with destination <span style="color: red;">1.1</span>.<span style="color: #38761d;">255.255</span>. (It will be sent as link-layer broadcast.) No other host on this network accepts it.

  Unless if the network has all bits in the netmask difference being equal to one.

  * Example: in /24 network <span style="color: red;">1.1.255</span>.<span style="color: #38761d;">0</span>/24, a misconfigured host <span style="color: red;">1.1</span>.<span style="color: #38761d;">255.1</span>/16 sends a "broadcast" packet to <span style="color: red;">1.1</span>.<span style="color: #38761d;">255.255</span>, which happens to be a valid broadcast on this network.

### Netmask of the network interface is longer

Host with **longer netmask** will not set enough bits to `1`.
The packets sent as broadcast will be recognized as unicast by other hosts
on this subnet.

* Example: in `/8` network <span style="color: red;">1</span>.<span style="color: #38761d;">0.0.0</span>/8, a host misconfigured as <span style="color: red;">1.1</span>.<span style="color: #38761d;">1.1</span>/16 sends what it thinks to be a broadcast packet to <span style="color: red;">1.1</span>.<span style="color: #38761d;">255.255</span>. It appears as valid unicast on this subnet. If there is a host with address <span style="color: red;">1</span>.<span style="color: #38761d;">1.255.255</span>, this host will accept this packet. (Besides probably unexpected IP content, the host may also notice that the layer 2 address of this packet was a layer 2 broadcast.)

Naturally, these cases are "reversed" repetition of the cases for the receiving hosts.

## Conclusion

Netmask is normally (but not necessarily) used as input for the **routing table** construction. If used, then a wrong interface netmask makes possible the following routing failures:

* **Too long netmask**: the host will have no route for some packets, actually belonging to a subnet of this interface. Attempt to send packet to a host outside the too long misconfigured netmask but inside the correct netmask of the net results in ICMP error *"Destination net unreachable"*. If there is a default outgoing interface, the host will not generate the error, but send the packets to the default interface instead of the interface of this subnet.
* **Too short netmask**: the host may attempt to send to the interface packets, which would not be received by any host of the connected subnet. This attempt probably fails, because no host answers the ARP request. This results in ICMP error "Destination host unreachable".

In IPv4, **directed broadcast** packets are sent and received utilizing the netmask information. Directed broadcast is a marginal case; such packets are rarely used and dropped by most routers as per [RFC2644](https://tools.ietf.org/html/rfc2644).
But if directed broadcasts are used, then mismatched netmask results in any of:

  * failure to receive broadcast packets
  * failure to forward broadcast packets by routers
  * forwarding broadcast packets, destined to own network
  * accepting unicast packets, destined to some host, as broadcasts
  * accepting broadcast packets as unicast.


