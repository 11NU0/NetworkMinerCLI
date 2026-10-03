using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class NetBiosSessionServicePacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.NetBiosSessionService; }
        }

        public NetBiosSessionServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) { }

        public override Type[] ParsedTypes { get; } = { typeof(NetBiosSessionService) };

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            int bytesParsed = 0;
            foreach (AbstractPacket p in packetList)
                //if(p.GetType().IsSubclassOf(typeof(Packets.NetBiosSessionService)))
                if (p.GetType() == typeof(NetBiosSessionService))
                    bytesParsed += ((NetBiosSessionService)p).ParsedBytesCount;
            return bytesParsed;
        }

        public void Reset() {
            //do nothing
        }
    }
}
