using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {


    //http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    //http://www.faqs.org/rfcs/rfc1700.html
    //https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml (more and newer protocols than rfc 1700)

    public enum RFC1700Protocol : byte {
        HOPOPT = 0x00,//IPv6 Hop-by-Hop Option
        ICMP = 0x01,
        IGMP = 0x02,
        IPv4 = 0x04,//IPv4 encapsulation [RFC2003]
        TCP = 0x06,
        UDP = 0x11,
        IPv6 = 0x29,
        RSVP = 0x2e,//46
        GRE = 0x2f,
        ESP = 0x32,
        ICMPv6 = 0x3a,
        OSPF = 0x59,
        SCTP = 0x84,
        Unknown = 0xff//really defined as "Reserved" in RFC1700
    };

    public interface IIPPacket : IPacket {

        System.Net.IPAddress SourceIPAddress { get; }
        System.Net.IPAddress DestinationIPAddress { get; }
        int PayloadLength { get; }
        byte HeaderLength { get; }
        /// <summary>
        /// Time To Live (TTL) measured in Hops
        /// </summary>
        byte HopLimit { get; }
        byte NextRFC1700Protocol { get; }
    }
}
