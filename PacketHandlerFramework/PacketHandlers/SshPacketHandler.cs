using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class SshPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public override Type[] ParsedTypes { get; } = { typeof(SshPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.SSH; }
        }

        public SshPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty?
        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            foreach (AbstractPacket p in packetList) {
                if (p is SshPacket sshPacket) {
                    NetworkHost sender;
                    if (transferIsClientToServer)
                        sender = tcpSession.Flow.FiveTuple.ClientHost;
                    else
                        sender = tcpSession.Flow.FiveTuple.ServerHost;

                    sender.AddNumberedExtraDetail("SSH Version", sshPacket.SshVersion);
                    sender.AddNumberedExtraDetail("SSH Application", sshPacket.SshApplication);

                    return p.PacketLength;
                }
            }
            return 0;
        }

        public void Reset() {
            //do nothgin; no state...
        }

        #endregion
    }
}
