using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public interface IPortProtocolFinder {
        PacketParser.ApplicationLayerProtocol GetApplicationLayerProtocol(Packets.RFC1700Protocol transport, ushort sourcePort, ushort destinationPort);
    }
}
