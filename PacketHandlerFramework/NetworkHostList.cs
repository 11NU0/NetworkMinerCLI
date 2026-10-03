//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketHandlerFramework {
    public class NetworkHostList {
        private readonly SortedDictionary<ulong, NetworkHost> networkHostDictionary;

        public int Count {
            get {
                lock (this.networkHostDictionary)
                    return networkHostDictionary.Count;
            }
        }
        public ICollection<NetworkHost> Hosts {
            get {
                lock (this.networkHostDictionary)
                    return networkHostDictionary.Values;
            }
        }

        internal NetworkHostList() {
            this.networkHostDictionary = new SortedDictionary<ulong, NetworkHost>();
        }

        internal void Clear() {
            lock (this.networkHostDictionary)
                this.networkHostDictionary.Clear();
        }

        internal bool ContainsIP(IPAddress ip) {
            ulong ipULong = PacketParser.Utils.ByteConverter.ToUInt64(ip);
            lock (this.networkHostDictionary)
                return networkHostDictionary.ContainsKey(ipULong);
        }

        internal void Add(NetworkHost host) {
            lock (this.networkHostDictionary)
                this.networkHostDictionary.Add(PacketParser.Utils.ByteConverter.ToUInt64(host.IPAddress), host);
        }

        public NetworkHost GetNetworkHost(IPAddress ip) {
            ulong ipULong = PacketParser.Utils.ByteConverter.ToUInt64(ip);
            lock (this.networkHostDictionary) {
                if (this.networkHostDictionary.ContainsKey(ipULong))
                    return networkHostDictionary[ipULong];
                else
                    return null;
            }
        }
    }
}
