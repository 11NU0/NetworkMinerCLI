using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class SnmpPacketHandler : AbstractPacketHandler, IPacketHandler {


        public override Type[] ParsedTypes { get; } = { typeof(SnmpPacket) };

        public SnmpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
            SnmpPacket snmpPacket = null;
            UdpPacket udpPacket = null;

            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(SnmpPacket))
                    snmpPacket = (SnmpPacket)p;
                else if (p.GetType() == typeof(UdpPacket))
                    udpPacket = (UdpPacket)p;

                if (snmpPacket != null && udpPacket != null) {
                    string packetDescription = "SNMP";
                    if (Enum.IsDefined(typeof(SnmpPacket.Version), snmpPacket.VersionRaw))
                        packetDescription = Enum.GetName(typeof(SnmpPacket.Version), snmpPacket.VersionRaw);
                    System.Collections.Specialized.NameValueCollection tmpCol = new System.Collections.Specialized.NameValueCollection();

                    if (!string.IsNullOrEmpty(snmpPacket.CommunityString)) {
                        tmpCol.Add("SNMP community", snmpPacket.CommunityString);
                        MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, packetDescription, "SNMP community", snmpPacket.CommunityString, snmpPacket.ParentFrame.Timestamp));
                    }
                    foreach (string snmpString in snmpPacket.CarvedStrings) {
                        if (!string.IsNullOrEmpty(snmpString)) {
                            tmpCol.Add("SNMP parameter", snmpString);

                            //https://opensource.apple.com/source/cups/cups-218/cups/backend/snmp.txt.auto.html
                            if (snmpString.StartsWith("MFG:"))
                                sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.SnmpParameter, snmpString);
                            else if (snmpString.IndexOf("printer", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.SnmpParameter, snmpString);
                            else if (snmpString.IndexOf("MANUFACTURER", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.SnmpParameter, snmpString);
                            else if (snmpString.IndexOf("JETDIRECT", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.SnmpParameter, snmpString);
                            else if (snmpString.IndexOf("http", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.SnmpParameter, snmpString);
                            else if (snmpString.IndexOf("Firmware", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.SnmpParameter, snmpString);

                        }
                    }
                    if (tmpCol.Count > 0)
                        MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(snmpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, udpPacket.TransportProtocol, udpPacket.SourcePort, udpPacket.DestinationPort, tmpCol, snmpPacket.ParentFrame.Timestamp, packetDescription));
                }

            }
        }

        public void Reset() {
            //throw new NotImplementedException();
        }
    }
}
