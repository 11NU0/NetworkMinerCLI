//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

namespace PacketHandlerFramework.PacketHandlers {
    public abstract class AbstractPacketHandler : ICanParse {

        private PacketHandler mainPacketHandler;
        internal PacketHandler MainPacketHandler { get { return this.mainPacketHandler; } }

        //public abstract Type ParsedType { get; }
        public abstract Type[] ParsedTypes { get; }

        internal AbstractPacketHandler(PacketHandler mainPacketHandler) {
            this.mainPacketHandler=mainPacketHandler;
        }

        public virtual bool CanParse(HashSet<Type> packetTypeSet) {
            return packetTypeSet.Overlaps(this.ParsedTypes);
            //return this.ParsedTypes.Any(t => packetTypeSet.Contains(t));
        }

        protected internal bool TryGetPacket<T>(IEnumerable<AbstractPacket> packetList, out T l7Packet) where T : AbstractPacket {
            return this.TryGetPackets(packetList, out l7Packet, out _, out _);
        }

        protected internal bool TryGetPackets<T>(IEnumerable<AbstractPacket> packetList, out T l7Packet, out ITransportLayerPacket transportLayerPacket, out IIPPacket ipPacket) where T : AbstractPacket {
            l7Packet = null;
            transportLayerPacket = null;
            ipPacket = null;

            foreach (AbstractPacket p in packetList) {
                if (p is IIPPacket l3)
                    ipPacket = l3;
                else if (p is ITransportLayerPacket l4)
                    transportLayerPacket = l4;
                else if (p.GetType() == typeof(T))
                    l7Packet = (T)p;
            }
            return l7Packet != null;
        }
    }
}
