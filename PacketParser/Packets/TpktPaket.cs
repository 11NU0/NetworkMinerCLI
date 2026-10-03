//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //https://tools.ietf.org/html/rfc1006
    public class TpktPacket : AbstractPacket, ISessionPacket {


        private byte version;
        private ushort length;
        private TcpPacket parentTcpPacket;

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, TcpPacket parentTcpPacket, out AbstractPacket result) {
            result = null;
            //must be at least 4 bytes
            if (packetStartIndex + 3 > packetEndIndex) {
                return false;
            }
            if (parentFrame.Data[packetStartIndex] != 3)//"This field is always 3 for the version of the protocol described in this memo."
                return false;
            if (parentFrame.Data[packetStartIndex + 1] != 0)//the "reserved" value should be 0
                return false;

            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);

            if (length > packetEndIndex - packetStartIndex + 1 || length < 4)
                return false;

            try {
                result = new TpktPacket(parentFrame, packetStartIndex, packetEndIndex, parentTcpPacket);
            }
            catch (Exception e){
                SharedUtils.Logger.Log("Exception when parsing frame " + parentFrame.FrameNumber + " as TPKT packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                result = null;
            }

            if(result==null)
                return false;
            else
                return true;
        }

        private TpktPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, TcpPacket parentTcpPacket)
            : base(parentFrame, packetStartIndex, packetEndIndex, "TPKT") {
            this.version = parentFrame.Data[packetStartIndex];
            this.length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);
            this.parentTcpPacket = parentTcpPacket;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            AbstractPacket packet = null;

            if (base.PacketLength >= this.length) {

                if (parentTcpPacket.DestinationPort == 3389 || parentTcpPacket.SourcePort == 3389)
                    packet = new CotpPacket(base.ParentFrame, base.PacketStartIndex + 4, base.PacketStartIndex + this.length - 1, CotpPacket.PayloadProtocol.RDP);
                else if (parentTcpPacket.DestinationPort == 102 || parentTcpPacket.SourcePort == 102)
                    packet = new CotpPacket(base.ParentFrame, base.PacketStartIndex + 4, base.PacketStartIndex + this.length - 1, CotpPacket.PayloadProtocol.S7Comm);

                if (packet != null) {
                    yield return packet;
                    foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                        yield return subPacket;
                }
            }
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete {
            get { return base.PacketLength >= 4; }
        }

        public int ParsedBytesCount {
            get {
                if (base.PacketLength >= this.length)
                    return this.length;
                else
                    return 0;
            }
        }

        #endregion
    }
}
