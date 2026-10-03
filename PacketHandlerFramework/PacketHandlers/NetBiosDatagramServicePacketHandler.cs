//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class NetBiosDatagramServicePacketHandler : AbstractPacketHandler, IPacketHandler {


        public override Type[] ParsedTypes { get; } = { typeof(NetBiosDatagramServicePacket) };

        public NetBiosDatagramServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty..
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {

            foreach (AbstractPacket p in packetList)
                if (p.GetType() == typeof(NetBiosDatagramServicePacket))
                    ExtractData((NetBiosDatagramServicePacket)p, sourceHost);
        }

        private void ExtractData(NetBiosDatagramServicePacket netBiosDatagramServicePacket, NetworkHost sourceHost) {
            if (netBiosDatagramServicePacket != null)
                if (netBiosDatagramServicePacket.SourceNetBiosName != null && netBiosDatagramServicePacket.SourceNetBiosName.Length > 0)
                    sourceHost.AddHostName(netBiosDatagramServicePacket.SourceNetBiosName, netBiosDatagramServicePacket.PacketTypeDescription);
        }

        public void Reset() {
            //do nothing
        }

        #endregion
    }
}
