using System;
using System.Collections.Generic;
using System.Text;
using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;

namespace PacketHandlerFramework.PacketHandlers {

    class SocksPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private PopularityList<NetworkTcpSession, KeyValuePair<System.Net.IPAddress, ushort>> socksConnectIpPorts;

        public override Type[] ParsedTypes { get; } = { typeof(SocksPacket) };

        public SocksPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.socksConnectIpPorts = new PopularityList<NetworkTcpSession, KeyValuePair<System.Net.IPAddress, ushort>>(64);//64 parallell SOCKS sessions should be enough for everyone ;)
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.SOCKS;
            }
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {


            SocksPacket socksPacket = null;
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
                else if (p.GetType() == typeof(SocksPacket))
                    socksPacket = (SocksPacket)p;
            }
            if (socksPacket != null && tcpPacket != null) {
                string paramName = "SOCKS";
                if (socksPacket.ClientToServer) {
                    if (socksPacket.CommandOrReply == 1) {
                        paramName += " Connect";
                        if (!this.socksConnectIpPorts.ContainsKey(tcpSession)) {
                            if (socksPacket.IpAddress != null)
                                this.socksConnectIpPorts.Add(tcpSession, new KeyValuePair<System.Net.IPAddress, ushort>(socksPacket.IpAddress, socksPacket.Port));
                            else
                                this.socksConnectIpPorts.Add(tcpSession, new KeyValuePair<System.Net.IPAddress, ushort>(tcpSession.ClientHost.IPAddress, socksPacket.Port));
                        }
                    }
                    else if (socksPacket.CommandOrReply == 2)
                        paramName += " Bind";
                    else if (socksPacket.CommandOrReply == 3)
                        paramName += " DNS Associate";

                    if (socksPacket.Username != null && socksPacket.Password != null)                         //base.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "SOCKS", socksPacket.Username, socksPacket.Password, socksPacket.ParentFrame.Timestamp)));
                        MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "SOCKS", socksPacket.Username, socksPacket.Password, socksPacket.ParentFrame.Timestamp));
                }
                else {
                    if (socksPacket.CommandOrReply == 0) {
                        paramName += " Bind Succeeded";
                        if (this.socksConnectIpPorts.ContainsKey(tcpSession)) {
                            KeyValuePair<System.Net.IPAddress, ushort> target = this.socksConnectIpPorts[tcpSession];
                            ushort serverPort = target.Value;
                            NetworkHost serverHost;
                            if (MainPacketHandler.NetworkHostList.ContainsIP(target.Key))
                                serverHost = MainPacketHandler.NetworkHostList.GetNetworkHost(target.Key);
                            else
                                serverHost = tcpSession.ClientHost;

                            tcpSession.ProtocolFinder = new TcpSessionProtocolFinder(tcpSession.Flow, tcpPacket.ParentFrame.FrameNumber, MainPacketHandler, serverHost, serverPort);
                        }
                    }
                    else if (socksPacket.CommandOrReply == 1)
                        paramName += " General SOCKS server failure";
                    else if (socksPacket.CommandOrReply == 2)
                        paramName += " Connection not allowed by ruleset";
                    else if (socksPacket.CommandOrReply == 3)
                        paramName += " Network unreachable";
                    else if (socksPacket.CommandOrReply == 4)
                        paramName += " Host unreachable";
                    else if (socksPacket.CommandOrReply == 5)
                        paramName += " Connection refused";
                    else if (socksPacket.CommandOrReply == 6)
                        paramName += " TTL expired";
                    else if (socksPacket.CommandOrReply == 7)
                        paramName += " Command not supported";
                    else if (socksPacket.CommandOrReply == 8)
                        paramName += " Address type not supported";
                }

                if (socksPacket.ATyp == SocksPacket.ATYP.DOMAINNAME) {
                    System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                    parms.Add(paramName, socksPacket.DomainName + ":" + socksPacket.Port.ToString());
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(socksPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, socksPacket.ParentFrame.Timestamp, "SOCKS Connection"));
                }
                else if (socksPacket.ATyp == SocksPacket.ATYP.IPv4 || socksPacket.ATyp == SocksPacket.ATYP.IPv6) {
                    System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                    parms.Add(paramName, socksPacket.IpAddress.ToString() + ":" + socksPacket.Port.ToString());
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(socksPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, socksPacket.ParentFrame.Timestamp, "SOCKS Connection"));
                }
            }
            if (socksPacket != null)
                return socksPacket.ParsedBytesCount;
            else
                return 0;
        }

        public void Reset() {
            this.socksConnectIpPorts.Clear();
        }
    }
}
