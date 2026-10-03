using PacketParser;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework {

    public interface ISessionProtocolFinder : PacketParser.ISessionProtocolFinder {
        NetworkHost Server { get; }
        NetworkHost Client { get; }
        ushort ServerPort { get; }
        ushort ClientPort { get; }
        NetworkFlow Flow { get; }

        //ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol();
        //void SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint);


        void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, NetworkHost source, NetworkHost destination);
        //IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols();


    }
}
