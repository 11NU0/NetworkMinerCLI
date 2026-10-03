using System;
using System.Collections.Generic;
using System.Net.Sockets;
//using System.Runtime.Remoting.Messaging;
using System.Text;
using static PacketParser.Packets.CotpPacket;

namespace PacketParser.Packets {
    public class GtpPacket : AbstractPacket {

        //https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol

        private byte flagData;
        private byte version;
        private byte messageType;
        //a 16-bit field that indicates the length of the payload in bytes (rest of the packet following the mandatory 8-byte GTP header). Includes the optional fields.
        private ushort messageLength;
        private uint tunnelEndpointID;
        private byte? nextExtensionHeaderType;
        private (int offset, int length)? tunneledPacketInfo = null;

        [Flags]
        enum GTPv1Flags : byte {
            ProtocolIsGTP = 1<<4,//false => GTP' = charging transfer
            HasExtension = 1<<2,
            HasSequenceNumber = 1<<1,
            HasNpduNumber = 1,
        }

        [Flags]
        enum GTPv2Flags : byte {
            Piggybacking = 1 << 4,
            HasTeid = 1 << 3,
        }

        //Additional message types are defined 3GPP TS 29.060 section 7.1
        enum MessageType : byte {
            EchoRequest = 1,
            EchoResponse = 2,
            ErrorIndication = 26,
            SupportedExtensionHeadersNotification = 31,
            EndMarker = 254,
            GPDU = 255,
        }


        internal GtpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "GTP") {
            this.version = (byte)(parentFrame.Data[packetStartIndex] >> 5);
            this.flagData = parentFrame.Data[packetStartIndex];
            this.messageType = parentFrame.Data[packetStartIndex+1];
            this.messageLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);
            int offset = 4;
            if (this.version == 1 || this.HasFlag(GTPv2Flags.HasTeid)) {
                this.tunnelEndpointID = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                offset += 4;
            }
            if (this.HasFlag(GTPv1Flags.HasExtension)) {
                offset += 3;//skip potential sequence number and n-pdu
                byte nextExtensionHeaderType = parentFrame.Data[packetStartIndex + offset];
                offset++;
                while (nextExtensionHeaderType != 0) {
                    //This field states the length of this extension header, including the length, the contents, and the next extension header field, in 4-octet units, so the length of the extension must always be a multiple of 4.
                    int extensionLengthInBytes = 4 * parentFrame.Data[packetStartIndex + offset];
                    if (extensionLengthInBytes < 4)
                        throw new FormatException("Malformed GTP Extension");
                    offset += extensionLengthInBytes - 1;
                    nextExtensionHeaderType = parentFrame.Data[packetStartIndex + offset];
                    offset++;
                }
            }
            else if (this.HasFlag(GTPv1Flags.HasSequenceNumber) || this.HasFlag(GTPv1Flags.HasNpduNumber)) {
                offset += 4;
            }
            if(version == 1 && messageType == (byte)MessageType.GPDU) {
                //G-PDU is a vanilla user plane message, which carries the original packet (T-PDU).
                //In G-PDU message, GTP-U header is followed by a T-PDU
                
                //messageLength indicates the length of the payload in bytes (rest of the packet following the mandatory 8-byte GTP header). Includes the optional fields.
                int tunneledPacketLength = messageLength - offset + 8;
                if(tunneledPacketLength > 0)
                    this.tunneledPacketInfo = (offset, tunneledPacketLength);
            }
        }

        private bool HasFlag(GTPv1Flags flag) {
            return this.version == 1 && (this.flagData & (byte)flag) != 0;
        }
        private bool HasFlag(GTPv2Flags flag) {
            return this.version == 2 && (this.flagData & (byte)flag) != 0;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if(this.tunneledPacketInfo?.length > 0) {
                //the payload can be IPv4, IPv6 or PPP
                AbstractPacket payloadPacket = null;
                int payloadStartIndex = this.PacketStartIndex + this.tunneledPacketInfo.Value.offset;
                int payloadEndIndex = payloadStartIndex + this.tunneledPacketInfo.Value.length - 1;
#if DEBUG
                if (payloadEndIndex != this.PacketEndIndex)
                    System.Diagnostics.Debugger.Break();
#endif
                if (!IPv4Packet.TryParse(this.ParentFrame, payloadStartIndex, payloadEndIndex, out payloadPacket)) {
                    try {
                        payloadPacket = new IPv6Packet(this.ParentFrame, payloadStartIndex, payloadEndIndex);
                    }
                    catch { }
                }
                if (payloadPacket != null) {
                    yield return payloadPacket;
                    foreach (AbstractPacket subPacket in payloadPacket.GetSubPackets(false))
                        yield return subPacket;
                }
            }
        }
    }
}
