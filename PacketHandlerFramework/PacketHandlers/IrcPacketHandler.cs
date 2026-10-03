using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class IrcPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private const char CTCP_DELIMITER = (char)0x01;

        private class IrcSession {
            private string nick = null;
            private string user = null;
            private string pass = null;

            internal string Nick { set { this.nick = value; } }
            internal string User { set { this.user = value; } }
            internal string Pass { set { this.pass = value; } }

            internal NetworkCredential GetCredential(NetworkHost sourceHost, NetworkHost destinationHost, DateTime timestamp) {
                string credentialUser = "";
                if (this.nick != null)
                    credentialUser = this.nick;
                if (this.user != null)
                    credentialUser += "(IRC User: " + this.user + ")";
                string credentialPassword = "N/A";
                if (this.pass != null)
                    credentialPassword = this.pass;
                return new NetworkCredential(sourceHost, destinationHost, "IRC", credentialUser, credentialPassword, timestamp);
            }
        }

        private PopularityList<NetworkTcpSession, IrcSession> ircSessionList;

        public override Type[] ParsedTypes { get; } = { typeof(IrcPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.IRC; }
        }

        public IrcPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.ircSessionList = new PopularityList<NetworkTcpSession, IrcSession>(1000);
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }


            IrcPacket ircPacket = null;
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
                else if (p.GetType() == typeof(IrcPacket))
                    ircPacket = (IrcPacket)p;
            }
            if (ircPacket != null && tcpPacket != null) {
                System.Collections.Specialized.NameValueCollection tmpCol = new System.Collections.Specialized.NameValueCollection();
                foreach (IrcPacket.Message m in ircPacket.Messages) {
                    tmpCol.Add(m.Command, m.ToString());
                    if (m.Command.Equals("USER", StringComparison.InvariantCultureIgnoreCase)) {
                        //the first parameter is the username
                        List<string> parameters = new List<string>();
                        foreach (string s in m.Parameters)
                            parameters.Add(s);
                        if (parameters.Count > 0) {
                            string ircUser = parameters[0];
                            IrcSession ircSession;
                            if (this.ircSessionList.ContainsKey(tcpSession))
                                ircSession = ircSessionList[tcpSession];
                            else {
                                ircSession = new IrcSession();
                                this.ircSessionList.Add(tcpSession, ircSession);
                            }
                            ircSession.User = ircUser;
                            //tcpSession.Flow.FiveTuple.ClientHost.AddNumberedExtraDetail("IRC Username", ircUser);
                            sourceHost.AddNumberedExtraDetail("IRC Username", ircUser);
                            this.MainPacketHandler.AddCredential(ircSession.GetCredential(sourceHost, destinationHost, ircPacket.ParentFrame.Timestamp));
                        }
                        if (parameters.Count > 1)
                            sourceHost.AddHostName(parameters[1], ircPacket.PacketTypeDescription);
                        if (parameters.Count > 2)
                            destinationHost.AddHostName(parameters[2], ircPacket.PacketTypeDescription);
                    }
                    else if (m.Command.Equals("NICK", StringComparison.InvariantCultureIgnoreCase)) {
                        IEnumerator<string> enumerator = m.Parameters.GetEnumerator();
                        if (enumerator.MoveNext()) {//move to the first position
                            string ircNick = enumerator.Current;
                            IrcSession ircSession;
                            if (this.ircSessionList.ContainsKey(tcpSession))
                                ircSession = ircSessionList[tcpSession];
                            else {
                                ircSession = new IrcSession();
                                this.ircSessionList.Add(tcpSession, ircSession);
                            }
                            ircSession.Nick = ircNick;
                            sourceHost.AddNumberedExtraDetail("IRC Nick", ircNick);
                            //NetworkCredential ircNicCredential = new NetworkCredential(sourceHost, destinationHost, "IRC", enumerator.Current, "N/A (only IRC Nick)", ircPacket.ParentFrame.Timestamp);
                            this.MainPacketHandler.AddCredential(ircSession.GetCredential(sourceHost, destinationHost, ircPacket.ParentFrame.Timestamp));
                        }
                    }
                    else if (m.Command.Equals("PASS", StringComparison.InvariantCultureIgnoreCase)) {
                        IEnumerator<string> enumerator = m.Parameters.GetEnumerator();
                        if (enumerator.MoveNext()) {//move to the first position
                            string ircPass = enumerator.Current;
                            IrcSession ircSession;
                            if (this.ircSessionList.ContainsKey(tcpSession))
                                ircSession = ircSessionList[tcpSession];
                            else {
                                ircSession = new IrcSession();
                                this.ircSessionList.Add(tcpSession, ircSession);
                            }
                            ircSession.Pass = ircPass;
                            this.MainPacketHandler.AddCredential(ircSession.GetCredential(sourceHost, destinationHost, ircPacket.ParentFrame.Timestamp));
                        }
                    }
                    else if (m.Command.Equals("PRIVMSG", StringComparison.InvariantCultureIgnoreCase)) {
                        //first parameter is recipient, second is message
                        List<string> parameters = new List<string>();
                        foreach (string s in m.Parameters)
                            parameters.Add(s);
                        if (parameters.Count >= 2) {
                            System.Collections.Specialized.NameValueCollection attributes = new System.Collections.Specialized.NameValueCollection();
                            attributes.Add("Command", m.Command);
                            string from = "";
                            if (m.Prefix != null && m.Prefix.Length > 0) {
                                attributes.Add("Prefix", m.Prefix);
                                from = m.Prefix;
                            }
                            for (int i = 0; i < parameters.Count; i++) {
                                string parm = parameters[i];
                                parm = parm.Trim(CTCP_DELIMITER);
                                attributes.Add("Parameter " + (i + 1), parm);
                                if (parm.StartsWith("DCC SEND")) {
                                    //https://modern.ircdocs.horse/dcc.html#dcc-send
                                    //DCC SEND <filename> <host> <port> [size] [??]
                                    //DCC SEND message.wav 199 0 11888756 47
                                    //DCC SEND message.wav 3232235550 51991 11888756 47
                                    string[] parts = parm.Split(' ');
                                    string filename = parts[2];
                                    string ipString = parts[3];
                                    string portString = parts[4];
                                    if (uint.TryParse(ipString, out uint ipInt) && ushort.TryParse(portString, out ushort port)) {
                                        if(port > 0) {
                                            //IPAddress ip = new IPAddress(ipInt); this doesn't work, bytes get reversed!!!
                                            byte[] ipBytes = PacketParser.Utils.ByteConverter.ToByteArray(ipInt, false);
                                            IPAddress ip = new IPAddress(ipBytes);
                                            //TODO reassemble file sent to ip/port - problem we don't have the client's port
                                        }
                                    }
                                }
                            }
                            string message = parameters[1]?.Trim(CTCP_DELIMITER);
                            MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(ApplicationLayerProtocol.IRC, sourceHost, destinationHost, ircPacket.ParentFrame.FrameNumber, ircPacket.ParentFrame.Timestamp, from, parameters[0], message, message, attributes, ircPacket.PacketLength));
                        }
                    }
                }
                if (tmpCol.Count > 0) {
                    MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(ircPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, tmpCol, tcpPacket.ParentFrame.Timestamp, "IRC packet"));
                    return ircPacket.ParsedBytesCount;
                }
            }
            return 0;
        }

        public void Reset() {
            this.ircSessionList.Clear();
        }

    }
}
