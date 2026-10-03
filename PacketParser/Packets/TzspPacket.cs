using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class TzspPacket : AbstractPacket {
        //TaZmen Sniffer Protocol (TZSP)
        //https://wiki.mikrotik.com/wiki/Manual:Tools/Packet_Sniffer
        //https://en.wikipedia.org/wiki/TZSP


        public enum TzspEncapsulation : ushort {
            Ethernet = 1,
            TokenRing = 2,
            SLIP = 3,
            PPP = 4,
            FDDI = 5,
            RAW = 7,
            IEEE_802_11 = 18,
            IEEE_802_11_PRISM = 119,
            IEEE_802_11_RADIOTAP = 126,
            IEEE_802_11_AVS = 127,
        }

        private enum TzspTag : byte {
            Padding = 0,
            End = 1,
            //there are other tag values as well
        }
        public byte Version { get; }
        public byte Type { get; }
        public ushort Encapsulation { get; }

        private int encapsulatedPacketStartIndex;

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket tzspPacket) {
            tzspPacket = null;
            if (parentFrame.Data[packetStartIndex] != 1)
                return false;
            ushort encap = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            if (!Enum.IsDefined(typeof(TzspEncapsulation), encap))
                return false;
            else {
                try {
                    tzspPacket = new TzspPacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }
                catch { return false; }
            }

        }

        public TzspPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "TZSP") {
            this.Version = parentFrame.Data[packetStartIndex];
            this.Type = parentFrame.Data[packetStartIndex + 1];
            this.Encapsulation = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);

            bool foundEndTag = false;
            for (int i = packetStartIndex + 4; i <= packetEndIndex; i++) {
                byte tag = parentFrame.Data[i];
                if (tag == (byte)TzspTag.End) {
                    foundEndTag = true;
                    this.encapsulatedPacketStartIndex = i + 1;
                    if (this.encapsulatedPacketStartIndex > packetEndIndex)
                        throw new Exception("Malformed TZSP packet");
                    break;
                }
                else if (tag == (byte)TzspPacket.TzspTag.Padding)
                    continue;
                else {
                    /**
                     * 	uint8_t type;
                     * 	uint8_t length;
                     * 	char  data[];
                     **/
                    byte length = parentFrame.Data[i + 1];
                    i += length;
                }
            }
            if (!foundEndTag)
                throw new Exception("No TZSP End tag found in options.");
        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            AbstractPacket encapsulatedPacket = null;
            if (this.Encapsulation == (ushort)TzspEncapsulation.Ethernet)
                encapsulatedPacket = new Ethernet2Packet(this.ParentFrame, this.encapsulatedPacketStartIndex, this.PacketEndIndex);
            else if (this.Encapsulation == (ushort)TzspEncapsulation.PPP)//or is this PointToPointOverEthernetPacket?
                encapsulatedPacket = new PointToPointPacket(this.ParentFrame, this.encapsulatedPacketStartIndex, this.PacketEndIndex);
            else if (this.Encapsulation == (ushort)TzspEncapsulation.RAW)
                encapsulatedPacket = new IPv4Packet(this.ParentFrame, this.encapsulatedPacketStartIndex, this.PacketEndIndex);
            else if (this.Encapsulation == (ushort)TzspEncapsulation.IEEE_802_11)
                encapsulatedPacket = new IEEE_802_11Packet(this.ParentFrame, this.encapsulatedPacketStartIndex, this.PacketEndIndex);
            else if (this.Encapsulation == (ushort)TzspEncapsulation.IEEE_802_11_RADIOTAP)
                encapsulatedPacket = new IEEE_802_11RadiotapPacket(this.ParentFrame, this.encapsulatedPacketStartIndex, this.PacketEndIndex);


            if (encapsulatedPacket != null) {
                yield return encapsulatedPacket;
                foreach (AbstractPacket subPacket in encapsulatedPacket.GetSubPackets(false))
                    yield return subPacket;
            }
            

        }
    }
}
