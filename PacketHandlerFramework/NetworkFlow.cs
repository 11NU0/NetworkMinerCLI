using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketHandlerFramework {
    public class NetworkFlow : PacketParser.ITcpFlowInfo {
        public FiveTuple FiveTuple { get; }
        public DateTime StartTime { get; }
        public DateTime EndTime { get; set; }
        public long BytesSentClient { get; set; }
        public long BytesSentServer { get; set; }

        public ushort ClientPort => this.FiveTuple.ClientPort;
        public ushort ServerPort => this.FiveTuple.ServerPort;

        public NetworkFlow(NetworkTcpSession networkTcpSession) : this(new FiveTuple(networkTcpSession.ClientHost, networkTcpSession.ClientTcpPort, networkTcpSession.ServerHost, networkTcpSession.ServerTcpPort, FiveTuple.TransportProtocol.TCP), networkTcpSession.StartTime, networkTcpSession.EndTime, networkTcpSession.ClientToServerTcpDataStream.TotalByteCount, networkTcpSession.ServerToClientTcpDataStream.TotalByteCount) {
            //nothing more required
        }

        public NetworkFlow(FiveTuple fiveTuple, DateTime startTime) : this(fiveTuple, startTime, startTime, 0, 0) {
            //nothing more required
        }

        public NetworkFlow(FiveTuple fiveTuple, DateTime startTime, DateTime endTime, long bytesSentClient, long bytesSentServer) {
            this.FiveTuple = fiveTuple;
            this.StartTime = startTime;
            this.EndTime = endTime;
            this.BytesSentClient = bytesSentClient;
            this.BytesSentServer = bytesSentServer;
        }

    }
}
