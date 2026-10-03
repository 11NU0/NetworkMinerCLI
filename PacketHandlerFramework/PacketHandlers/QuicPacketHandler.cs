using PacketHandlerFramework.Fingerprints;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketHandlerFramework.PacketHandlers {
    public class QuicPacketHandler : AbstractTlsHandshakePacketHandler, IPacketHandler {
        public override Type[] ParsedTypes { get; } = { typeof(QuicPacket) };

        PacketParser.PopularityList<string, List<QuicPacket.InitialPacket>> streamInitials;

        public QuicPacketHandler(PacketHandler mainPacketHandler, Dictionary<string, IJa4Fingerprint> ja4Fingerprints)
            : base(mainPacketHandler, ja4Fingerprints, false) {
            //empty constructor
            this.streamInitials = new PacketParser.PopularityList<string, List<QuicPacket.InitialPacket>>(100);
        }

        [Obsolete]
        private string GetStreamIdentifier(QuicPacket.InitialPacket initial) {
            string s = PacketParser.Utils.ByteConverter.ToHexString(initial.SourceConnectionId, initial.SourceConnectionId.Length);
            string d = PacketParser.Utils.ByteConverter.ToHexString(initial.DestinationConnectionId, initial.DestinationConnectionId.Length);
            return s + "-" + d;
        }
        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
            
            if(base.TryGetPackets<QuicPacket>(packetList, out QuicPacket quicPacket, out ITransportLayerPacket transportLayerPacket, out _)) {
                if (quicPacket.TryGetTlsHandshakePacket(out var handshake)) {
                    this.ExtractHandshakeData(handshake, sourceHost, destinationHost, transportLayerPacket);
                }
                else if(quicPacket.Initial != null) {
                    //string streamID = this.GetStreamIdentifier(quicPacket.Initial);
                    string streamID = quicPacket.Initial.GetStreamIdentifier();
                    lock (this.streamInitials) {
                        if (!this.streamInitials.ContainsKey(streamID))
                            this.streamInitials.Add(streamID, new List<QuicPacket.InitialPacket>() { quicPacket.Initial });
                        else {
                            var initials = this.streamInitials[streamID];
                            initials.Add(quicPacket.Initial);
                            //see if separate fragments together contain a TLS handshake
                            if (QuicPacket.TryGetTlsHandshakePacket(quicPacket.ParentFrame, initials, out handshake)) {
                                this.ExtractHandshakeData(handshake, sourceHost, destinationHost, transportLayerPacket);
                                this.streamInitials.Remove(streamID);
                            }
                            else if (initials.Count > 10)
                                this.streamInitials.Remove(streamID);
                        }
                    }
                }
            }
        }

        private void ExtractHandshakeData(TlsRecordPacket.HandshakePacket handshake, NetworkHost sourceHost, NetworkHost destinationHost, ITransportLayerPacket transportLayerPacket, bool transferIsClientToServer = true) {
            FiveTuple fiveTuple;
            if (transportLayerPacket.DestinationPort == 443 || transportLayerPacket.DestinationPort < transportLayerPacket.SourcePort)
                fiveTuple = new FiveTuple(sourceHost, transportLayerPacket.SourcePort, destinationHost, transportLayerPacket.DestinationPort, (FiveTuple.TransportProtocol)transportLayerPacket.TransportProtocol);
            else
                fiveTuple = new FiveTuple(destinationHost, transportLayerPacket.DestinationPort, sourceHost, transportLayerPacket.SourcePort, (FiveTuple.TransportProtocol)transportLayerPacket.TransportProtocol);

            base.ExtractHandshakeData(transportLayerPacket, fiveTuple, transferIsClientToServer, handshake);

        }

        public void Reset() {
            lock(this.streamInitials)
                this.streamInitials.Clear();
        }
    }
}
