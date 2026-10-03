//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using PacketParser;
using PacketParser.Packets;
using SharedUtils;
using System;
using System.Collections.Generic;
using PacketParser.Packets;

namespace PacketHandlerFramework {
    public class NetworkTcpSession : IComparable, IComparable<NetworkTcpSession> {//only TCP sessions


        private readonly long startFrameNumber;
        private bool finPacketReceived;
        private uint clientToServerFinPacketSequenceNumber;
        private uint serverToClientFinPacketSequenceNumber;
        private bool? requiredNextTcpDataStreamIsClientToServer = null;
        private readonly Func<DateTime, string> toCustomTimeZoneStringFunction;
        private readonly List<EventHandler<Frame>> sessionClosedHandlers;

        private DateTime handshakeTimestampSyn = DateTime.MinValue;
        private DateTime handshakeTimestampSynAck = DateTime.MinValue;
        private DateTime handshakeTimestampAck = DateTime.MinValue;

        //public event OnSessionClosed;
        public event EventHandler<Frame> OnSessionClosed {
            add {
                this.sessionClosedHandlers.Add(value);
            }
            remove {
                this.sessionClosedHandlers.Remove(value);
            }
        }

        /// <summary>
        /// iRTT
        /// </summary>
        public TimeSpan InitialRoundTripTime {
            get {
                //time between SYN and final ACK in handshake
                //Jasper explains this very nicely here:
                //https://blog.packet-foo.com/2014/07/determining-tcp-initial-round-trip-time/
                if (this.handshakeTimestampSyn > DateTime.MinValue && this.handshakeTimestampAck > DateTime.MinValue)
                    return TimeSpan.FromTicks((this.handshakeTimestampAck - this.handshakeTimestampSyn).Ticks / 2);
                else
                    return TimeSpan.Zero;
            }
        }
        public TimeSpan LatencyClient {
            get {
                //time between SYN-ACK and ACK / 2
                if (this.handshakeTimestampSynAck > DateTime.MinValue && this.handshakeTimestampAck > DateTime.MinValue)
                    return TimeSpan.FromTicks((this.handshakeTimestampAck - handshakeTimestampSynAck).Ticks / 2);
                else
                    return TimeSpan.Zero;
            }
        }
        public TimeSpan LatencyServer {
            get {
                //time between SYN and SYN-ACK / 2
                if (this.handshakeTimestampSyn > DateTime.MinValue && this.handshakeTimestampSynAck > DateTime.MinValue)
                    return TimeSpan.FromTicks((this.handshakeTimestampSynAck - this.handshakeTimestampSyn).Ticks / 2);
                else
                    return TimeSpan.Zero;
            }
        }
        public NetworkHost ClientHost { get { return this.Flow.FiveTuple.ClientHost; } }
        public NetworkHost ServerHost { get { return this.Flow.FiveTuple.ServerHost; } }
        public ushort ClientTcpPort { get { return this.Flow.FiveTuple.ClientPort; } }
        public ushort ServerTcpPort { get { return this.Flow.FiveTuple.ServerPort; } }
        public DateTime StartTime { get { return this.Flow.StartTime; } }//in NetworkFlow
        public DateTime EndTime { get { return this.Flow.EndTime; } }//in NetworkFlow
        public bool SynPacketReceived { get; private set; }
        public bool SynAckPacketReceived { get; private set; }
        public bool FinPacketReceived {
            get {
                //https://sourceforge.net/projects/networkminer/forums/forum/665610/topic/4946533/index/page/1
                return this.finPacketReceived &&
                    (this.ClientToServerTcpDataStream == null ||
                    this.ServerToClientTcpDataStream == null ||
                    this.ClientToServerTcpDataStream == null ||
                    this.clientToServerFinPacketSequenceNumber <= this.ClientToServerTcpDataStream.ExpectedTcpSequenceNumber && this.serverToClientFinPacketSequenceNumber < this.ServerToClientTcpDataStream.ExpectedTcpSequenceNumber);
            }
        }
        public bool SessionEstablished { get; private set; }
        public bool SessionClosed { get; private set; }
        public PacketParser.TcpDataStream ClientToServerTcpDataStream { get; private set; }
        public PacketParser.TcpDataStream ServerToClientTcpDataStream { get; private set; }
        public PacketParser.TcpDataStream RequiredNextTcpDataStream {
            get {
                if (this.requiredNextTcpDataStreamIsClientToServer == true)
                    return this.ClientToServerTcpDataStream;
                else if (this.requiredNextTcpDataStreamIsClientToServer == false)
                    return this.ServerToClientTcpDataStream;
                else
                    return null;
            }
            set {
                if (value == null)
                    this.requiredNextTcpDataStreamIsClientToServer = null;
            }
        }
        public ISessionProtocolFinder ProtocolFinder { get; set; }
        public NetworkFlow Flow { get; }

        private NetworkTcpSession(Func<DateTime, string> toCustomTimeZoneStringFunction) {
            this.toCustomTimeZoneStringFunction = toCustomTimeZoneStringFunction;
            this.sessionClosedHandlers = new List<EventHandler<Frame>>();
        }

        public NetworkTcpSession(TcpPacket tcpSynPacket, NetworkHost clientHost, NetworkHost serverHost, ISessionProtocolFinderFactory protocolFinderFactory, Func<DateTime, string> toCustomTimeZoneStringFunction) : this(toCustomTimeZoneStringFunction) {

            if (tcpSynPacket.FlagBits.Synchronize) {//It's normal to start the session with a SYN flag
                FiveTuple fiveTuple = new FiveTuple(clientHost, tcpSynPacket.SourcePort, serverHost, tcpSynPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpSynPacket.ParentFrame.Timestamp, tcpSynPacket.ParentFrame.Timestamp, 0, 0);

                this.SynPacketReceived = false;
                this.SynAckPacketReceived = false;
                this.finPacketReceived = false;
                this.clientToServerFinPacketSequenceNumber = uint.MaxValue;
                this.serverToClientFinPacketSequenceNumber = uint.MaxValue;
                this.SessionEstablished = false;
                this.SessionClosed = false;

                this.startFrameNumber = tcpSynPacket.ParentFrame.FrameNumber;

                this.ClientToServerTcpDataStream = null;
                this.ServerToClientTcpDataStream = null;


                this.ProtocolFinder = protocolFinderFactory.CreateProtocolFinder(this.Flow, this.startFrameNumber);
            }
            else
                throw new Exception("SYN flag not set on TCP packet");

        }
        /// <summary>
        /// Creates a truncated TCP session where the initial 3 way handshake is missing
        /// </summary>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="tcpPacket"></param>
        public NetworkTcpSession(NetworkHost sourceHost, NetworkHost destinationHost, TcpPacket tcpPacket, ISessionProtocolFinderFactory protocolFinderFactory, Func<DateTime, string> toCustomTimeZoneStringFunction) : this(toCustomTimeZoneStringFunction) {
            //this part is used to create a cropped (truncated) session where the beginning is missing!
            this.SynPacketReceived = true;
            this.SynAckPacketReceived = true;
            this.finPacketReceived = false;
            this.SessionEstablished = false;//I will change this one soon,...
            this.SessionClosed = false;

            this.startFrameNumber = tcpPacket.ParentFrame.FrameNumber;

            this.ClientToServerTcpDataStream = null;
            this.ServerToClientTcpDataStream = null;


            //now let's do a qualified guess of who is the server and who is client...

            FiveTuple fiveTuple;
            List<ApplicationLayerProtocol> sourcePortProtocols = new List<ApplicationLayerProtocol>(TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(tcpPacket.SourcePort));
            List<ApplicationLayerProtocol> destinationPortProtocols = new List<ApplicationLayerProtocol>(TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(tcpPacket.DestinationPort));
            if (sourcePortProtocols.Count > destinationPortProtocols.Count) { //packet is server -> client
                fiveTuple = new FiveTuple(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.AcknowledgmentNumber, tcpPacket.SequenceNumber);

            }
            else if (destinationPortProtocols.Count > 0) { //packet is client -> server
                fiveTuple = new FiveTuple(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
            }
            else if (tcpPacket.SourcePort < tcpPacket.DestinationPort) {//packet is server -> client
                fiveTuple = new FiveTuple(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.AcknowledgmentNumber, tcpPacket.SequenceNumber);
            }
            else {//packet is client -> server
                fiveTuple = new FiveTuple(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
            }

            this.ProtocolFinder = protocolFinderFactory.CreateProtocolFinder(this.Flow, this.startFrameNumber);
        }

        internal int MaxBufferedPacketForConfirmedProtocol() {
            int maxPacketFragments = 6;//this one is set low in order to get better performance
            var confirmedProtocol = this.ProtocolFinder.GetConfirmedApplicationLayerProtocol();
            if (confirmedProtocol == ApplicationLayerProtocol.SSL)
                maxPacketFragments = 15; //TLS records are max 16kB, each frame is about 1500 B, 15 frames should be enough (famous last words)
            else if (confirmedProtocol == ApplicationLayerProtocol.NetBiosSessionService)
                maxPacketFragments = 1024;//Changed 2011-04-25 to 50, changed 2020-08-14 to 1024
            else if (confirmedProtocol == ApplicationLayerProtocol.HTTP)
                maxPacketFragments = 32;//Changed 2011-10-12 to handle AOL webmail
            else if (confirmedProtocol == ApplicationLayerProtocol.SMTP)
                maxPacketFragments = 61;//Changed 2014-04-07to handle short manual SMTP emails, such as when sending via Telnet (Example: M57 net-2009-11-16-09:24.pcap)
            else if (confirmedProtocol == ApplicationLayerProtocol.HTTP2)
                maxPacketFragments = 22;//Most HTTP/2 sessions use chunks up to 16384 bytes
            else if (confirmedProtocol == ApplicationLayerProtocol.DNS)
                maxPacketFragments = 55;//Changed 2021-06-01 to handle large TXT records sent over DNS (1-dns.txt.pcap). Normally not more than 46 packets because dns.length is u16 => 46 packets on MTU 1400
            else if(confirmedProtocol == ApplicationLayerProtocol.FTP) {
                maxPacketFragments = 20;//FTP servers sometimes send multiline server ready banners using "220-"
            }
            return maxPacketFragments;
        }

        public string GetFlowID() {
            return this.ClientHost.IPAddress.ToString() + ":" + this.ClientTcpPort.ToString() + "-" + this.ServerHost.IPAddress.ToString() + ":" + this.ServerTcpPort.ToString();
        }

        public static int GetHashCode(NetworkHost clientHost, NetworkHost serverHost, ushort clientTcpPort, ushort serverTcpPort) {
            int cHash = clientHost.IPAddress.GetHashCode() ^ clientTcpPort;
            int sHash = serverHost.IPAddress.GetHashCode() ^ serverTcpPort;
            return cHash ^ sHash << 16 ^ sHash >> 16;//this should be enough in order to avoid collisions
        }

        public override int GetHashCode() {
            return GetHashCode(this.ClientHost, this.ServerHost, this.ClientTcpPort, this.ServerTcpPort);
        }
        public override string ToString() {
            long serverBytes = 0;
            long clientBytes = 0;
            if (this.ServerToClientTcpDataStream != null)
                serverBytes = this.ServerToClientTcpDataStream.TotalByteCount;
            if (this.ClientToServerTcpDataStream != null)
                clientBytes = this.ClientToServerTcpDataStream.TotalByteCount;

            string endTime, startTime;
            if (this.toCustomTimeZoneStringFunction != null) {
                startTime = this.toCustomTimeZoneStringFunction(this.Flow.StartTime);
                endTime = this.toCustomTimeZoneStringFunction(this.Flow.EndTime);
            }
            else {
                startTime = this.Flow.StartTime.ToString();
                endTime = this.Flow.EndTime.ToString();
            }

            return "Server: " + this.ServerHost.ToString(false) + " TCP " + this.ServerTcpPort + " (" + serverBytes + " data bytes sent), Client: " + this.ClientHost.ToString(false) + " TCP " + this.ClientTcpPort + " (" + clientBytes + " data bytes sent), Session start: " + startTime + ", Session end: " + endTime;
        }

        public bool TryAddPacket(TcpPacket tcpPacket, NetworkHost sourceHost, NetworkHost destinationHost) {
            if (this.SessionClosed)
                return false;

            //Make sure the hosts are correct
            if (sourceHost == this.ClientHost && tcpPacket.SourcePort == this.ClientTcpPort) {//client -> server
                if (destinationHost != this.ServerHost)
                    return false;
                if (tcpPacket.SourcePort != this.ClientTcpPort)
                    return false;
                if (tcpPacket.DestinationPort != this.ServerTcpPort)
                    return false;
            }
            else if (sourceHost == this.ServerHost && tcpPacket.SourcePort == this.ServerTcpPort) {//server -> client
                if (destinationHost != ClientHost)
                    return false;
                if (tcpPacket.SourcePort != ServerTcpPort)
                    return false;
                if (tcpPacket.DestinationPort != ClientTcpPort)
                    return false;
            }
            else//unknown direction
                return false;

            this.Flow.EndTime = tcpPacket.ParentFrame.Timestamp;

            //Check TCP handshake
            if (!this.SynPacketReceived) {//SYN (client->server)
                if (tcpPacket.FlagBits.Synchronize && sourceHost == this.ClientHost) {
                    this.SynPacketReceived = true;
                    this.handshakeTimestampSyn = tcpPacket.ParentFrame.Timestamp.ToUniversalTime();
                }
                else
                    return false;
            }
            else if (!this.SynAckPacketReceived) {//SYN+ACK (server->client)
                if (tcpPacket.FlagBits.Synchronize && tcpPacket.FlagBits.Acknowledgement && sourceHost == this.ServerHost) {
                    this.SynAckPacketReceived = true;
                    this.handshakeTimestampSynAck = tcpPacket.ParentFrame.Timestamp.ToUniversalTime();
                }
                else
                    return false;
            }
            else if (!this.SessionEstablished) {//ACK (client->server)
                if (tcpPacket.FlagBits.Acknowledgement && sourceHost == this.ClientHost) {
                    this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
                    this.handshakeTimestampAck = tcpPacket.ParentFrame.Timestamp.ToUniversalTime();
                }
                else
                    return false;
            }
            //FIN and RST are handled further down 


            //an established and not closed session!
            if (tcpPacket.PayloadDataLength > 0) {
                this.ProtocolFinder.AddPacket(tcpPacket, sourceHost, destinationHost);
                try {
                    //If we've come this far the packet should be allright for the networkSession
                    byte[] tcpSegmentData = tcpPacket.GetTcpPacketPayloadData();


                    //now add the data to the server to calculate service statistics for the open port
                    NetworkServiceMetadata networkServiceMetadata = null;
                    lock (this.ServerHost.NetworkServiceMetadataList) {
                        if (!this.ServerHost.NetworkServiceMetadataList.ContainsKey(this.ServerTcpPort)) {
                            networkServiceMetadata = new NetworkServiceMetadata(this.ServerHost, this.ServerTcpPort);
                            this.ServerHost.NetworkServiceMetadataList.Add(this.ServerTcpPort, networkServiceMetadata);
                        }
                        else
                            networkServiceMetadata = this.ServerHost.NetworkServiceMetadataList[this.ServerTcpPort];
                    }

                    //now, lets extract some data from the TCP packet!
                    if (sourceHost == this.ServerHost && tcpPacket.SourcePort == this.ServerTcpPort) {
                        networkServiceMetadata.OutgoingTraffic.AddTcpPayloadData(tcpSegmentData);
                        if (this.ServerToClientTcpDataStream == null) {
                            //this.ServerToClientTcpDataStream = new TcpDataStream(tcpPacket.SequenceNumber, false, this);
                            this.ServerToClientTcpDataStream = new PacketParser.TcpDataStream(tcpPacket.SequenceNumber, false, this.Flow, this.MaxBufferedPacketForConfirmedProtocol);
                        }
                        if (this.requiredNextTcpDataStreamIsClientToServer == null && this.ServerToClientTcpDataStream.TotalByteCount == 0)
                            this.requiredNextTcpDataStreamIsClientToServer = false;
                        this.ServerToClientTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData, tcpPacket.FlagBits);
                    }
                    else {
                        networkServiceMetadata.IncomingTraffic.AddTcpPayloadData(tcpSegmentData);
                        if (this.ClientToServerTcpDataStream == null) {
                            //this.ClientToServerTcpDataStream = new TcpDataStream(tcpPacket.SequenceNumber, true, this);
                            this.ClientToServerTcpDataStream = new PacketParser.TcpDataStream(tcpPacket.SequenceNumber, true, this.Flow, this.MaxBufferedPacketForConfirmedProtocol);
                        }
                        if (this.requiredNextTcpDataStreamIsClientToServer == null && this.ClientToServerTcpDataStream.TotalByteCount == 0)
                            this.requiredNextTcpDataStreamIsClientToServer = true;
                        this.ClientToServerTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData, tcpPacket.FlagBits);
                    }
                }
                catch (Exception ex) {
                    Logger.Log("Error parsing TCP session data in " + tcpPacket.ParentFrame.ToString() + ". " + ex.Message, Logger.EventLogEntryType.Warning);
                    if (!tcpPacket.ParentFrame.QuickParse)
                        tcpPacket.ParentFrame.Errors.Add(new Frame.Error(tcpPacket.ParentFrame, tcpPacket.PacketStartIndex, tcpPacket.PacketEndIndex, ex.Message));
                    return false;
                }
            }

            //se if stream should be closed
            if (tcpPacket.FlagBits.Reset) {//close no matter what
                this.Close(tcpPacket.ParentFrame);
            }
            else if (tcpPacket.FlagBits.Fin) {//close nicely
                if (!this.finPacketReceived) {
                    this.finPacketReceived = true;
                    if (sourceHost == this.ServerHost && tcpPacket.SourcePort == this.ServerTcpPort)
                        this.serverToClientFinPacketSequenceNumber = tcpPacket.SequenceNumber;
                    else
                        this.clientToServerFinPacketSequenceNumber = tcpPacket.SequenceNumber;
                }
                else if (tcpPacket.FlagBits.Acknowledgement)//fin+ack
                    this.Close(tcpPacket.ParentFrame);
            }
            return true;
        }

        internal void RemoveData(PacketParser.TcpDataStream.VirtualTcpData virtualTcpData, NetworkHost sourceHost, ushort sourceTcpPort) {
            this.RemoveData(virtualTcpData.FirstPacketSequenceNumber, virtualTcpData.ByteCount, sourceHost, sourceTcpPort);
        }

        internal void RemoveData(uint firstSequenceNumber, int bytesToRemove, NetworkHost sourceHost, ushort sourceTcpPort) {
            if (sourceHost == this.ServerHost && sourceTcpPort == this.ServerTcpPort)
                this.ServerToClientTcpDataStream.RemoveData(firstSequenceNumber, bytesToRemove);
            else if (sourceHost == this.ClientHost && sourceTcpPort == this.ClientTcpPort)
                this.ClientToServerTcpDataStream.RemoveData(firstSequenceNumber, bytesToRemove);
            else
                throw new Exception("NetworkHost is not part of the NetworkTcpSession");
        }

        private void SetEstablished(uint clientInitialSequenceNumber, uint serverInitialSequenceNumber) {
            this.SessionEstablished = true;
            if (this.ClientToServerTcpDataStream == null) {
                //this.ClientToServerTcpDataStream = new TcpDataStream(clientInitialSequenceNumber, true, this);
                this.ClientToServerTcpDataStream = new PacketParser.TcpDataStream(clientInitialSequenceNumber, true, this.Flow, this.MaxBufferedPacketForConfirmedProtocol);
            }
            else
                this.ClientToServerTcpDataStream.InitialTcpSequenceNumber = clientInitialSequenceNumber;
            if (this.ServerToClientTcpDataStream == null) {
                //this.ServerToClientTcpDataStream = new TcpDataStream(serverInitialSequenceNumber, false, this);
                this.ServerToClientTcpDataStream = new PacketParser.TcpDataStream(serverInitialSequenceNumber, false, this.Flow, this.MaxBufferedPacketForConfirmedProtocol);
            }
            else
                this.ServerToClientTcpDataStream.InitialTcpSequenceNumber = serverInitialSequenceNumber;
            lock (this.ServerHost.IncomingSessionList)
                this.ServerHost.IncomingSessionList.Add(this);
            lock (this.ClientHost.OutgoingSessionList)
                this.ClientHost.OutgoingSessionList.Add(this);
#if DEBUG
            if (this.ServerHost.IPAddress.AddressFamily != this.Flow.FiveTuple.ClientHost.IPAddress.AddressFamily || this.ClientHost.IPAddress.AddressFamily != this.Flow.FiveTuple.ServerEndPoint.AddressFamily)
                System.Diagnostics.Debugger.Break();
#endif

        }

        internal void Close(Frame lastFrame = null) {
            if (!this.SessionClosed) {
                this.SessionClosed = true;

                if (this.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.Unknown)
                    this.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Unknown, false);

                try {
                    foreach (var eh in this.sessionClosedHandlers) eh(this, lastFrame);
                }
                catch (Exception e) {
                    Logger.DebugLog("Error closing NetworkTcpSession: " + e);
                }
            }
        }


        #region IComparable Members

        public int CompareTo(NetworkTcpSession session) {
            if (this.ClientHost.CompareTo(session.ClientHost) != 0)
                return this.ClientHost.CompareTo(session.ClientHost);
            else if (this.ServerHost.CompareTo(session.ServerHost) != 0)
                return this.ServerHost.CompareTo(session.ServerHost);
            else if (this.ClientTcpPort != session.ClientTcpPort)
                return this.ClientTcpPort - session.ClientTcpPort;
            else if (this.ServerTcpPort != session.ServerTcpPort)
                return this.ServerTcpPort - session.ServerTcpPort;
            else if (this.StartTime.CompareTo(session.StartTime) != 0)
                return this.StartTime.CompareTo(session.StartTime);
            else
                return 0;
        }

        public int CompareTo(object obj) {
            NetworkTcpSession s = (NetworkTcpSession)obj;
            return this.CompareTo(s);
        }

        #endregion
        
    }
}
