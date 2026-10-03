using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class OscarPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {


        public override Type[] ParsedTypes { get; } = { typeof(OscarPacket) };

        public OscarPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region ITcpSessionPacketHandler Members

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Oscar; }
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            OscarPacket oscarPacket = null;
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(OscarPacket)) oscarPacket = (OscarPacket)p;
                else if (p.GetType() == typeof(TcpPacket)) {
                    tcpPacket = (TcpPacket)p;
                }
            }

            if (oscarPacket != null && tcpPacket != null) {
                if (oscarPacket.ImText != null) {
                    NetworkHost sourceHost, destinationHost;
                    if (transferIsClientToServer) {
                        sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                        destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
                    }
                    else {
                        sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                        destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
                    }
                    MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(ApplicationLayerProtocol.Oscar, sourceHost, destinationHost, oscarPacket.ParentFrame.FrameNumber, oscarPacket.ParentFrame.Timestamp, oscarPacket.SourceLoginId, oscarPacket.DestinationLoginId, oscarPacket.ImText, oscarPacket.ImText, Encoding.Default, oscarPacket.Attributes, oscarPacket.PacketLength));
                }
                return oscarPacket.BytesParsed;
            }
            return 0;
        }

        public void Reset() {
            //do nothing
        }

        #endregion
    }
}
