using PacketParser;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework {
    public class PortProtocolFinderFactory : ISessionProtocolFinderFactory {

        public PacketHandler PacketHandler { get; set; }

        public bool PortIndependentProtocolIdentificationEnabled {
            get {
                return false;
            }

            set {
                throw new NotImplementedException("PIPI is not supported in the free version of NetworkMiner");
            }
        }

        public PortProtocolFinderFactory(PacketHandler packetHandler) {
            this.PacketHandler = packetHandler;
        }

        public ISessionProtocolFinder CreateProtocolFinder(NetworkFlow flow, long startFrameNumber) {
            if (flow.FiveTuple.Transport == FiveTuple.TransportProtocol.TCP)
                return new TcpSessionProtocolFinder(flow, startFrameNumber, this.PacketHandler);
            else
                throw new Exception("There is only a protocol finder for TCP");
        }

        public void Reset() { }

    }
}
