using PacketHandlerFramework;
using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketHandlerFramework.PacketHandlers {
    class SyslogPacketHandler : AbstractPacketHandler, IPacketHandler {

        public override Type[] ParsedTypes { get; } = { typeof(SyslogPacket) };

        public SyslogPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
            SyslogPacket syslogPacket = null;
            UdpPacket udpPacket = null;

            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(SyslogPacket))
                    syslogPacket = (SyslogPacket)p;
                else if (p.GetType() == typeof(UdpPacket))
                    udpPacket = (UdpPacket)p;

                if (syslogPacket != null && udpPacket != null && syslogPacket.SyslogMessage != null && syslogPacket.SyslogMessage.Length > 0) {

                    System.Collections.Specialized.NameValueCollection tmpCol = new System.Collections.Specialized.NameValueCollection();

                    tmpCol.Add("Syslog Message", syslogPacket.SyslogMessage);

                    MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(syslogPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, udpPacket.TransportProtocol, udpPacket.SourcePort, udpPacket.DestinationPort, tmpCol, syslogPacket.ParentFrame.Timestamp, "Syslog Message"));

                }
            }
        }

        public void Reset() {
            //throw new NotImplementedException();
        }
    }
}
