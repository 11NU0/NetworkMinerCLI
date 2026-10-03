using PacketParser;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PacketHandlerFramework {
    public class TcpSessionProtocolFinder : ISessionProtocolFinder {


        private readonly List<ApplicationLayerProtocol> probableProtocols;
        private ApplicationLayerProtocol confirmedProtocol;
        private readonly long startFrameNumber;
        private readonly DateTime startTimestamp;
        private readonly PacketHandler packetHandler;




        public NetworkHost Client { get; }
        public NetworkHost Server { get; }

        public ushort ClientPort { get; }
        public ushort ServerPort { get; }

        public NetworkFlow Flow { get; }

        public ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol() {
            return this.confirmedProtocol;
        }

        public void SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint) {
            if (this.confirmedProtocol == ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
                this.packetHandler.OnSessionDetected(new Events.SessionEventArgs(this.Flow, value, this.startFrameNumber));
                if (setAsPersistantProtocolOnServerEndPoint && value != ApplicationLayerProtocol.Unknown) {
                    lock (this.Server.NetworkServiceMetadataList)
                        if (this.Server.NetworkServiceMetadataList.ContainsKey(this.ServerPort))
                            this.Server.NetworkServiceMetadataList[this.ServerPort].ApplicationLayerProtocol = value;
                }
            }
            else if (value != PacketParser.ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
            }
        }

        public TcpSessionProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler) : this(flow.FiveTuple.ClientHost, flow.FiveTuple.ServerHost, flow.FiveTuple.ClientPort, flow.FiveTuple.ServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.Flow = flow;
        }

        internal TcpSessionProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler, NetworkHost nextHopServer, ushort nextHopServerPort) : this(flow.FiveTuple.ClientHost, nextHopServer, flow.FiveTuple.ClientPort, nextHopServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.Flow = flow;
        }

        private TcpSessionProtocolFinder(NetworkHost client, NetworkHost server, ushort clientPort, ushort serverPort, long startFrameNumber, DateTime startTimestamp, PacketHandler packetHandler, bool clientMightBeServer = false) {

            this.confirmedProtocol = ApplicationLayerProtocol.Unknown;
            this.Client = client;
            this.Server = server;
            this.ClientPort = clientPort;
            this.ServerPort = serverPort;

            this.startFrameNumber = startFrameNumber;
            this.startTimestamp = startTimestamp;

            this.packetHandler = packetHandler;

            this.probableProtocols = TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(client?.IPAddress, server?.IPAddress, clientPort, serverPort, clientMightBeServer);
        }

        public void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, NetworkHost source, NetworkHost destination) {
            //do nothing
        }

        public IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols() {
            if (this.confirmedProtocol != ApplicationLayerProtocol.Unknown) {
                yield return this.confirmedProtocol;
                if (this.confirmedProtocol == PacketParser.ApplicationLayerProtocol.HTTP)
                    yield return PacketParser.ApplicationLayerProtocol.HTTP2;
                else if (this.confirmedProtocol == PacketParser.ApplicationLayerProtocol.HTTP2)
                    yield return PacketParser.ApplicationLayerProtocol.HTTP;
            }
            else {
                foreach (ApplicationLayerProtocol p in this.probableProtocols)
                    yield return p;
            }
        }

    }
}
