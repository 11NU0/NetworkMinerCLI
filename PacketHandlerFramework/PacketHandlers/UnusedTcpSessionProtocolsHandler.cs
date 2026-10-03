//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class UnusedTcpSessionProtocolsHandler : AbstractPacketHandler, ITcpSessionPacketHandler {


        //public override Type[] ParsedTypes { get; } = new Type[0];

        public override Type[] ParsedTypes { get; } = {
            typeof(NetBiosDatagramServicePacket),
            typeof(NetBiosNameServicePacket),
        };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Unknown; }
        }

        public UnusedTcpSessionProtocolsHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //nothing extra?
        }

        #region ITcpSessionPacketHandler Members

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            foreach (AbstractPacket p in packetList) {
                if (this.ParsedTypes.Contains(p.GetType()))
                    return p.ParentFrame.Data.Length;//it is OK to return larger values than the parsed # bytes as long as there aren't additional trailing packets to parse at the end of the data
            }

            return 0;
        }

        public void Reset() {
            //do nothing since this one holds no state
        }

        #endregion
    }
}
