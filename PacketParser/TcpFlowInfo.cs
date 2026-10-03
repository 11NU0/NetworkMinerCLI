using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketParser {
    public class TcpFlowInfo : ITcpFlowInfo {

        public ushort ClientPort { get; }

        public ushort ServerPort { get; }

        public long BytesSentClient { get; set; }

        public long BytesSentServer { get; set; }

        public IPAddress ClientIP { get; }

        public IPAddress ServerIP { get; }

        public TcpFlowInfo(ushort clientPort, ushort serverPort) {
            this.ClientPort = clientPort;
            this.ServerPort = serverPort;
            //client and server IP are not required for TCP reassembly
            this.ClientIP = null;
            this.ServerIP = null;
        }
        public TcpFlowInfo(System.Net.IPEndPoint client, System.Net.IPEndPoint server) {
            this.ClientIP = client.Address;
            this.ServerIP = server.Address;
            this.ClientPort = (ushort)client.Port;
            this.ServerPort = (ushort)server.Port;
            this.BytesSentClient = 0;
            this.BytesSentServer = 0;
        }
    }
}
