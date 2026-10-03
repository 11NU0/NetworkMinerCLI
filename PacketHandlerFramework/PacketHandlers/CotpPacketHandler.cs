using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using PacketParser.Utils;
using static PacketParser.Packets.CotpPacket;

namespace PacketHandlerFramework.PacketHandlers {
    class CotpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private const string RDP_COOKIE_FIELD_HEADER = "Cookie: ";

        private Dictionary<NetworkTcpSession, List<byte>> cotpDataSegments;

        public override Type[] ParsedTypes { get; } = { typeof( CotpPacket) };

        public CotpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.cotpDataSegments = new Dictionary<NetworkTcpSession, List<byte>>();
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                throw new NotImplementedException();
            }
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {

            if (this.TryGetPacket(packetList, out CotpPacket cotpPacket)) {
                System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();

                if (!cotpPacket.EndOfTsdu) {
                    //cache whatever TSDU data we have in this segment
                    //call CotpPacket.TryGetTsduData()
                    if(cotpPacket.TryGetTsduData(out byte[] data)) {
                        if (data?.Length > 0) {
                            lock (this.cotpDataSegments) {
                                if (!this.cotpDataSegments.ContainsKey(tcpSession))
                                    this.cotpDataSegments.Add(tcpSession, new List<byte>());
                                this.cotpDataSegments[tcpSession].AddRange(data);
                            }
                        }
                    }
                }
                else if(cotpPacket.GetTpdu() == Tpdu.Data) {
                    lock (this.cotpDataSegments) {
                        if (this.cotpDataSegments.TryGetValue(tcpSession, out List<byte> data)) {

                            this.cotpDataSegments.Remove(tcpSession);//clear the cached segments for this session
                            if (cotpPacket.TryGetTsduData(out byte[] lastData)) {
                                data.AddRange(lastData);
                                //TODO make sense of this data!
                            }
                        }
                    }
                }

                string details = "TPKT/COTP data";
                if (cotpPacket.EncapsulatedProtocol == CotpPacket.PayloadProtocol.RDP) {
                    Tpdu tpdu = cotpPacket.GetTpdu();
                    if (tpdu == Tpdu.ConnectionRequest) {
                        if (cotpPacket.TryGetVariablePartIndex(out int cotpPayloadIndex)) {
                            if (this.TryGetRdpCookie(cotpPacket.ParentFrame.Data, cotpPayloadIndex, out string rdpCookie)) {
                                details = "RDP Cookie";
                                if (rdpCookie?.Length > 0 && !rdpCookie.Equals("mstshash="))//ignore emtpy cookie values
                                    this.MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "RDP Cookie", rdpCookie, "", cotpPacket.ParentFrame.Timestamp));
                                if (rdpCookie.Contains("=")) {
                                    string[] parts = rdpCookie.Split('=');
                                    if (parts.Length > 1) {
                                        string pn = parts[0].Trim();
                                        string pv = parts[1].Trim();
                                        if (pn.Length > 0 && pv.Length > 0)
                                            parms.Add(pn, pv);
                                    }
                                }
                            }
                        }
                    }
                    else if (tpdu == Tpdu.ConnectionConfirm) {
                        if (cotpPacket.TryGetVariablePartIndex(out int cotpPayloadIndex)) {
                            if (cotpPayloadIndex > 0 && cotpPayloadIndex < cotpPacket.ParentFrame.Data.Length) {
                                //first byte is RDP type
                                byte rdpType = cotpPacket.ParentFrame.Data[cotpPayloadIndex];
                                if (rdpType == 0x02)//RDP Negotiation Response
                                    tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.SSL, false);
                            }
                        }
                    }
                }
                else if (cotpPacket.EncapsulatedProtocol == CotpPacket.PayloadProtocol.S7Comm) {
                    if (cotpPacket.GetTpdu() == Tpdu.ConnectionRequest) {
                        //iterate through parameters
                        if (cotpPacket.TryGetVariablePartIndex(out int partIndex)) {
                            while (partIndex < cotpPacket.PacketEndIndex) {
                                byte parameterCode = cotpPacket.ParentFrame.Data[partIndex++];
                                byte parameterLength = cotpPacket.ParentFrame.Data[partIndex++];
                                if (parameterLength > 0) {
                                    if (parameterCode == (byte)CotpPacket.ParameterCode.SRC_TSAP) {
                                        //1100 0001 for  the  identifier  of  the Calling TSAP.
                                        string sTSAP = this.GetTsapString(cotpPacket.ParentFrame.Data, partIndex, parameterLength, out bool sTsapIsAscii);
                                        if (!string.IsNullOrEmpty(sTSAP)) {
                                            parms.Add("Source TSAP", sTSAP);
                                            if (transferIsClientToServer)
                                                tcpSession.ClientHost.AddNumberedExtraDetail("COTP TSAP", sTSAP);
                                            else
                                                tcpSession.ServerHost.AddNumberedExtraDetail("COTP TSAP", sTSAP);
                                        }
                                    }
                                    if (parameterCode == (byte)CotpPacket.ParameterCode.DST_TSAP) {
                                        //1100 0010 for  the  identifier  of  the Called TSAP
                                        string dTSAP = this.GetTsapString(cotpPacket.ParentFrame.Data, partIndex, parameterLength, out bool dTsapIsAscii);
                                        if (!string.IsNullOrEmpty(dTSAP)) {
                                            parms.Add("Destination TSAP", dTSAP);
                                            if (transferIsClientToServer)
                                                tcpSession.ServerHost.AddNumberedExtraDetail("COTP TSAP", dTSAP);
                                            else
                                                tcpSession.ClientHost.AddNumberedExtraDetail("COTP TSAP", dTSAP);
                                        }
                                    }
                                }
                                partIndex += parameterLength;
                            }
                        }
                    }
                }

                if (parms.Count > 0 && cotpPacket != null) {
                    var pe = Events.ParametersEventArgs.GetParametersEventArgs(cotpPacket.ParentFrame, tcpSession, transferIsClientToServer, parms, details);
                    this.MainPacketHandler.OnParametersDetected(pe);
                }
            }

            return 0;//these bytes should already have been accounted for by the generic handler for TPKT
        }

        private string GetTsapString(byte[] data, int index, int length, out bool tsapIsAsciiString) {
            tsapIsAsciiString = StringManglerUtil.TryGet7BitAsciiString(data, index, length, out string tsapString);
            if(tsapIsAsciiString)
                return tsapString;
            else
                return ByteConverter.ToHexString(data, length, index, false, ".");//for example "20.00" or "02.00"
        }

        private bool TryGetRdpCookie(byte[] data, int offset, out string rdpCookie) {
            //http://www.jasonfilley.com/rdpcookies.html
            //The format of the user cookie is: Cookie:[space]mstshash =[ANSI string][0x0d0a]
            rdpCookie = null;
            int index = offset;
            string line = PacketParser.Utils.ByteConverter.ReadLine(data, ref index);
            if (line?.Length > RDP_COOKIE_FIELD_HEADER.Length && line.StartsWith(RDP_COOKIE_FIELD_HEADER))
                rdpCookie = line.Substring(RDP_COOKIE_FIELD_HEADER.Length);
            return rdpCookie != null;
        }


        public void Reset() {
            this.cotpDataSegments.Clear();
        }
    }
}
