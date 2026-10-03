//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace PacketHandlerFramework {
    public class NetworkPacketList /*: System.Collections.Generic.List<NetworkPacket>*/{
        private long totalBytes;
        private int packetCount;
        private DateTime firstSeen = DateTime.MaxValue;

        public int Count { get { return this.packetCount; } }
        public long TotalBytes { get { return this.totalBytes; } }
       
        public DateTime FirsPacketTimestamp { get { return this.firstSeen; } }




        public NetworkPacketList() /*: base()*/{

        }

        public override string ToString() {
            return this.packetCount + " packets (" + this.TotalBytes.ToString("n0") + " Bytes)";
        }

        public void AddRange(IEnumerable<NetworkPacket> collection) {
            lock (this) {
                foreach (NetworkPacket p in collection)
                    this.Add(p);
            }
        }
        public void Add(NetworkPacket packet) {
            lock (this) {
                //base.Add(packet);
                this.packetCount++;
                this.totalBytes += packet.PacketBytes;
                if (packet.Timestamp < this.firstSeen)
                    this.firstSeen = packet.Timestamp;
            }
        }


    }
}
