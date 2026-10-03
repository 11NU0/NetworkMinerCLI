//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PacketParser.Packets {
    /**
     *    0                   1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |     Type      |     Code      |          Checksum             |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |                             Message body                      |
     *   Z                             ...                               Z
     *   |                                                               |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    public class Icmpv6Packet : AbstractPacket, ITransportLayerPacket {


        public static bool IsUnidirectionalType(byte type) {
            _ = GetReverseType(type, 0, out bool unidirectional);
            return unidirectional;
        }
        private static byte GetReverseType(byte type, byte code, out bool unidirectional) {
            //used to figure out the destination "port" for Community ID https://github.com/corelight/community-id-spec
            unidirectional = false;
            switch (type) {
                case 128: return 129;//echo => echo reply
                case 129: return 128;
                case 130: return 131;//MLD_LISTENER => Report
                case 131: return 130;
                case 133: return 134;//ROUTER_SOLICIT => ADVERT
                case 134: return 133;
                case 135: return 136;//NEIGHBOR_SOLICIT => ADVERT
                case 136: return 135;
                case 139: return 140;//WRU_REQUEST => REPLY
                case 140: return 139;
                case 144: return 145;//HAAD_REQUEST => REPLY
                case 145: return 144;
                default: {
                        unidirectional = true;
                        return code;
                    }
            }
        }

        private readonly byte type;
        private readonly byte code;
        private readonly ushort checksum;

        public ushort SourcePort { get { return this.type; } }//The logic of using ICMP Type as source port is borrowed from how Cumminty ID's are generated for ICMP: https://github.com/corelight/community-id-spec
        public ushort DestinationPort { get { return GetReverseType(this.type, this.code, out _); } }
        public byte DataOffsetByteCount { get { return 8; } }
        public byte FlagsRaw { get { return type; } }
        public ushort Checksum { get { return this.checksum; } }
        public RFC1700Protocol TransportProtocol => RFC1700Protocol.ICMPv6;

        internal Icmpv6Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "ICMP") {
            this.type = parentFrame.Data[packetStartIndex];
            this.code = parentFrame.Data[packetStartIndex + 1];
            this.checksum = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
        }

        

    }
}
