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
     *   |                             unused                            |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |      Internet Header + 64 bits of Original Data Datagram      |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    public class IcmpPacket : AbstractPacket, ITransportLayerPacket {


        public static bool IsUnidirectionalType(byte type) {
            _ = GetReverseType(type, 0, out bool unidirectional);
            return unidirectional;
        }
        private static byte GetReverseType(byte type, byte code, out bool unidirectional) {
            //used to figure out the destination "port" for Community ID https://github.com/corelight/community-id-spec
            unidirectional = false;
            switch (type) {
                case 0: return 8;//echo reply => echo
                case 8: return 0;//echo => echo reply
                case 9: return 10;//Router advertisment => Router solicit
                case 10: return 9;// Router solicit => Router advertisment
                case 13: return 14;//Timestamp => Timestamp reply
                case 14: return 13;//Timestamp reply => Timestamp
                case 15: return 16;//Info => Info reply
                case 16: return 15;//Info reply => Info
                case 17: return 18;//Mask => Mask reply
                case 18: return 17;//Mask reply => Mask
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
        public RFC1700Protocol TransportProtocol => RFC1700Protocol.ICMP;

        internal IcmpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "ICMP") {
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
