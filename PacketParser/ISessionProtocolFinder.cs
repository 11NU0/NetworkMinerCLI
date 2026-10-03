using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {


    //this finder is extended by PacketHandlerFramework.ISessionProtocolFinder
    public interface ISessionProtocolFinder {
        PacketParser.ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol();
        void SetConfirmedApplicationLayerProtocol(PacketParser.ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint);
        IEnumerable<PacketParser.ApplicationLayerProtocol> GetProbableApplicationLayerProtocols();
    }
}
