using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/IPv6
    public class IPv6Packet : AbstractPacket, IIPPacket {

        public class HopByHopOption : AbstractPacket {
            public readonly byte NextHeaderRFC1700Protocol;
            
            private readonly int nextHeaderStartOffset;

            internal HopByHopOption(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IPv6 Hop-by-Hop Option") {
                this.NextHeaderRFC1700Protocol = parentFrame.Data[packetStartIndex];
                //Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
                byte length = parentFrame.Data[packetStartIndex + 1];
                this.nextHeaderStartOffset = 8 + (8 * length);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
                if (this.PacketStartIndex + this.nextHeaderStartOffset < this.PacketEndIndex) {
                    AbstractPacket packet;
                    if (IPv4Packet.TryGetSubPacket(this.NextHeaderRFC1700Protocol, this.ParentFrame, this.PacketStartIndex + this.nextHeaderStartOffset, this.PacketEndIndex, out packet))
                        yield return packet;
                    else {
                        packet = new RawPacket(this.ParentFrame, this.PacketStartIndex + this.nextHeaderStartOffset, this.PacketEndIndex);
                        yield return packet;
                    }
                    foreach (AbstractPacket subPacket in packet?.GetSubPackets(false))
                        yield return subPacket;
                }
            }
        }

        private const byte IPV6_HEADER_LENGTH = 40;

        private ushort payloadLength;
        private byte nextHeader;
        private byte hopLimit;
        private System.Net.IPAddress sourceIP, destinationIP;

        public System.Net.IPAddress SourceIPAddress { get { return this.sourceIP; } }
        public System.Net.IPAddress DestinationIPAddress { get { return destinationIP; } }
        public int PayloadLength { get { return this.payloadLength; } }
        public byte HopLimit { get { return this.hopLimit; } }
        public byte HeaderLength { get { return IPV6_HEADER_LENGTH; } }
        public byte NextRFC1700Protocol { get { return this.nextHeader; } }

        internal IPv6Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IPv6") {

            if (!this.ParentFrame.QuickParse)
                if((parentFrame.Data[packetStartIndex]>>4)!=0x06)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetStartIndex, "IP Version!=6 ("+(parentFrame.Data[packetStartIndex]>>4)+")"));
            //skip traffic class
            //skip flow label

            //get payload length
            this.payloadLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
            //adjust end-index in case there is trailing data at the end of the frame
            if (this.PacketEndIndex > this.PacketStartIndex + this.HeaderLength + this.payloadLength - 1)
                this.PacketEndIndex = this.PacketStartIndex + this.HeaderLength + this.payloadLength - 1;
            this.nextHeader=parentFrame.Data[this.PacketStartIndex +6];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Next Header", "0x"+nextHeader.ToString("X2"));
            this.hopLimit=parentFrame.Data[this.PacketStartIndex +7];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Hop Limit", hopLimit.ToString());

            //source (offset=8)
            byte[] sourceIpBytes=new byte[16];
            Array.Copy(parentFrame.Data, packetStartIndex+8, sourceIpBytes, 0, sourceIpBytes.Length);
            this.sourceIP=new System.Net.IPAddress(sourceIpBytes);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source IP", sourceIP.ToString());
            //destination (offset=8+16=24)
            byte[] destinationIpBytes=new byte[16];
            Array.Copy(parentFrame.Data, packetStartIndex+24, destinationIpBytes, 0, destinationIpBytes.Length);
            this.destinationIP=new System.Net.IPAddress(destinationIpBytes);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination IP", destinationIP.ToString());

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if(this.PacketStartIndex + IPV6_HEADER_LENGTH < this.PacketEndIndex) {
                AbstractPacket packet;
                if (IPv4Packet.TryGetSubPacket(this.nextHeader, this.ParentFrame, this.PacketStartIndex + IPV6_HEADER_LENGTH, this.PacketEndIndex, out packet))
                    yield return packet;
                else {
                    packet = new RawPacket(this.ParentFrame, this.PacketStartIndex + IPV6_HEADER_LENGTH, this.PacketEndIndex);
                    yield return packet;
                }
                foreach (AbstractPacket subPacket in packet?.GetSubPackets(false))
                    yield return subPacket;
            }
        }


    }
}
