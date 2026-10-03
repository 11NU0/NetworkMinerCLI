//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketHandlerFramework;
using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;
using static PacketHandlerFramework.PacketHandlers.HttpPacketHandler;

namespace PacketHandlerFramework.PacketHandlers {
    class UpnpPacketHandler : AbstractPacketHandler, IPacketHandler {

        private UserAgentFingerprinter userAgentFingerprinter;
        public override Type[] ParsedTypes { get; } = { typeof(UpnpPacket) };

        public UpnpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.userAgentFingerprinter = new UserAgentFingerprinter {
                Name = "UPnP USER-AGENT"
            };
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(UpnpPacket))
                    ExtractData((UpnpPacket)p, sourceHost);
            }
        }

        private void ExtractData(UpnpPacket upnpPacket, NetworkHost sourceHost) {
            if (upnpPacket.FieldList.Count > 0) {
                if (sourceHost.UniversalPlugAndPlayFieldList == null)
                    sourceHost.UniversalPlugAndPlayFieldList = new SortedList<string, string>();
                lock (sourceHost.UniversalPlugAndPlayFieldList)
                    foreach (string field in upnpPacket.FieldList)
                        if (!sourceHost.UniversalPlugAndPlayFieldList.ContainsKey(field)) {
                            sourceHost.UniversalPlugAndPlayFieldList.Add(field, field);
                            if(field.StartsWith("USER-AGENT:")) {
                                string userAgent = field.Substring(11).Trim();
                                if(!string.IsNullOrEmpty(userAgent)) {
                                    sourceHost.AddHttpUserAgentBanner(userAgent);
                                    if (UserAgentFingerprinter.TryExtractUserAgentOS(userAgent, out var osID))
                                        sourceHost.AddProbableOs(osID.ToString(), this.userAgentFingerprinter, 0.5);
                                }
                            }
                        }
            }
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
        }

        #endregion
    }
}
