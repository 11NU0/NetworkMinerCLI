using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework {
    public interface ISessionProtocolFinderFactory {
        PacketHandler PacketHandler { get; set; }

        bool PortIndependentProtocolIdentificationEnabled { get; set; }
        ISessionProtocolFinder CreateProtocolFinder(NetworkFlow flow, long startFrameNumber);

        void Reset();
    }
}
