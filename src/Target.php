<?php
/**
 * @author Alex Milenin
 * @email  admin@azrr.info
 * @copyright Copyright (c)Alex Milenin (https://azrr.info/)
 */

namespace Azurre\Iptables;

class Target
{
    // Will cause the current packet to stop traveling through the chain (or sub-chain)
    const RETURN = 'RETURN';

    // The rule is accepted and will not continue traversing the current chain or any other ones in the same table.
    // Note however, that a packet that was accepted in one chain might still travel through chains within other tables,
    // and could still be dropped there
    const ACCEPT = 'ACCEPT';

    // only available within PREROUTING and OUTPUT chains in the nat table,
    // and any of the chains called upon from any of those listed chains
    const DNAT = 'DNAT';

    // Valid only in nat table, within the POSTROUTING chain
    const SNAT = 'SNAT';

    // Drops the packet, right there right then
    const DROP = 'DROP';

    // Sends a response back (unlike drop). Valid in the INPUT, FORWARD and OUTPUT chains or their sub chains
    const REJECT = 'REJECT';

    // Note: Does not work on namespaces. Also can fill up your kernel log.
    // iptables -A INPUT -p tcp -j LOG --log-prefix "INPUT packets"
    const LOG = 'LOG';

    // Packet information is multicasted together with the whole packet through a netlink socket.
    // One or more user-space processes may then subscribe to various multicast groups and receive the packet
    const ULOG = 'ULOG';

    // Only valid in mangle table. Note that the mark value is not set within the actual package,
    // but is a value that is associated within the kernel with the packet.
    // In other words does not make it out of the machine
    // iptables -t mangle -A PREROUTING -p tcp --dport 22 -j MARK --set-mark 2
    const MARK = 'MARK';

    // Similar to SNAT but used on a outbound network interface when the outbound IP can change.
    // Say a DHCP interface Only valid within the POSTROUTING
    const MASQUERADE = 'MASQUERADE';

    // Redirect packets and streams to the machine itself. Valid within the PREROUTING and OUTPUT chains of the nat table.
    // It is also valid within user-defined chains that are only called from those chains
    const REDIRECT = 'REDIRECT';
}
