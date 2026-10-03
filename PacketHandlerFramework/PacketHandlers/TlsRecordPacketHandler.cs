//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketHandlerFramework.Fingerprints;
using PacketParser;
using PacketParser.Packets;
using System.Text.RegularExpressions;

namespace PacketHandlerFramework.PacketHandlers {
    class TlsRecordPacketHandler : AbstractTlsHandshakePacketHandler, ITcpSessionPacketHandler {

        /**
         * TLS records fragmentation, i.e. objects fragmented into multiple TLS records:
         * 
         * multiple client messages of the same ContentType MAY be coalesced
         * into a single TLSPlaintext record, or a single message MAY be
         * fragmented across several records
         * https://tools.ietf.org/html/rfc5246#section-6.2.1
         **/
        private PopularityList<FiveTuple, Tuple<List<TlsRecordPacket>, List<TlsRecordPacket>>> tlsRecordFragmentCache;


        public override Type[] ParsedTypes { get; } = { typeof(TlsRecordPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.SSL; }
        }

        

        public TlsRecordPacketHandler(PacketHandler mainPacketHandler, Dictionary<string, IJa4Fingerprint> ja4Fingerprints, bool verifyX509Certificates = false)
            : base(mainPacketHandler, ja4Fingerprints, verifyX509Certificates) {

            
            this.tlsRecordFragmentCache = new PopularityList<FiveTuple, Tuple<List<TlsRecordPacket>, List<TlsRecordPacket>>>(100);

        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            bool successfulExtraction = false;


            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList)
                if (p.GetType() == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
            int parsedBytes = 0;
            if (tcpPacket != null) {

                //there might be several TlsRecordPackets in an SSL packet
                foreach (AbstractPacket p in packetList) {
                    if (p is TlsRecordPacket tlsRecordPacket) {
                        if (tlsRecordPacket.TlsRecordIsComplete) {
                            //check for previous fragments (see RFC 5246 section 6.2.1)
                            List<TlsRecordPacket> recordList = null;
                            lock (this.tlsRecordFragmentCache) {
                                if (this.tlsRecordFragmentCache.ContainsKey(tcpSession.Flow.FiveTuple)) {
                                    if (transferIsClientToServer)
                                        recordList = this.tlsRecordFragmentCache[tcpSession.Flow.FiveTuple].Item1;
                                    else
                                        recordList = this.tlsRecordFragmentCache[tcpSession.Flow.FiveTuple].Item2;
                                    if (recordList != null && recordList.Count > 0 && recordList[0].ContentType != tlsRecordPacket.ContentType)
                                        recordList.Clear();
                                }
                                else {
                                    recordList = new List<TlsRecordPacket>();
                                    if (transferIsClientToServer)
                                        this.tlsRecordFragmentCache.Add(tcpSession.Flow.FiveTuple, new Tuple<List<TlsRecordPacket>, List<TlsRecordPacket>>(recordList, new List<TlsRecordPacket>()));
                                    else
                                        this.tlsRecordFragmentCache.Add(tcpSession.Flow.FiveTuple, new Tuple<List<TlsRecordPacket>, List<TlsRecordPacket>>(new List<TlsRecordPacket>(), recordList));
                                }
                                if (recordList != null) {
                                    recordList.Add(tlsRecordPacket);
                                }
                            }
                            if (recordList != null) {

                                if (tlsRecordPacket.ContentType == TlsRecordPacket.ContentTypes.Handshake) {
                                    int parsedHandshakesTotalLength = 0;

                                    foreach (TlsRecordPacket.HandshakePacket handshake in TlsRecordPacket.HandshakePacket.GetHandshakes(recordList)) {
                                        parsedHandshakesTotalLength += handshake.PacketLength;
                                        this.ExtractHandshakeData(tcpPacket, tcpSession.Flow.FiveTuple, transferIsClientToServer, handshake);
                                    }

                                    this.RemoveParsedTlsRecordsFromList(recordList, parsedHandshakesTotalLength, tcpPacket);
                                }
                                //TODO add handlers for other TLS record content types here...
                                else if (tlsRecordPacket.ContentType == TlsRecordPacket.ContentTypes.Application) {
                                    //encrypted application data

                                    recordList.Clear();//let's not store encrypted data in memory unless it can be decrypted
                                }
                                else if (recordList.Count > 3)//limit stored records of unparsed types in order to save memory
                                    recordList.Clear();
                            }
                            successfulExtraction = true;
                            parsedBytes += tlsRecordPacket.Length + 5;//Same as tlsRecordPacket.PacketLength
                        }
                        else if (tlsRecordPacket.Length > 16384) {//rfc5246 says records are max 0x4000 bytes, so just skip it... there is no point in reassembling it any more
                            successfulExtraction = true;
                            parsedBytes = tcpPacket.PayloadDataLength;
                        }
                    }
                }
            }

            if (successfulExtraction) {
                return parsedBytes;
                //return tcpPacket.PayloadDataLength;
            }
            else
                return 0;
        }

        private void RemoveParsedTlsRecordsFromList(List<TlsRecordPacket> recordList, int parsedBytes, TcpPacket tcpPacket) {
            if (parsedBytes > 0) {
                //remove the parsed TLS records from the recordList
                int accumulatedRecordLength = 0;
                for (int i = 0; i < recordList.Count; i++) {
                    accumulatedRecordLength += recordList[i].Length;
                    if (accumulatedRecordLength >= parsedBytes) {
                        if (accumulatedRecordLength > parsedBytes) {
                            SharedUtils.Logger.Log("TLS data boundary is not on a TLS record boundary in frame " + tcpPacket.ParentFrame.FrameNumber, SharedUtils.Logger.EventLogEntryType.Warning);
                        }
                        recordList.RemoveRange(0, i + 1);
                        break;
                    }
                }
            }
        }

        public void Reset() {
            //close all resources
            this.tlsRecordFragmentCache.Clear();
        }

        #endregion

    }
}
