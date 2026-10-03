using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class NtlmSspPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        #region ITcpSessionPacketHandler Members

        private PopularityList<int, string> ntlmChallengeList;

        public override Type[] ParsedTypes { get; } = { typeof(NtlmSspPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.NetBiosSessionService; }
            //or should I set it to Unknown?
        }

        public NtlmSspPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {

            this.ntlmChallengeList = new PopularityList<int, string>(20);
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            NetworkHost sourceHost, destinationHost;
            ushort sourcePort, destinationPort;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
                sourcePort = tcpSession.Flow.FiveTuple.ClientPort;
                destinationPort = tcpSession.Flow.FiveTuple.ServerPort;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
                sourcePort = tcpSession.Flow.FiveTuple.ServerPort;
                destinationPort = tcpSession.Flow.FiveTuple.ClientPort;
            }
            //bool successfulExtraction=false;
            int successfullyExtractedBytes = 0;
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(NtlmSspPacket)) {
                    NtlmSspPacket ntlmPacket = (NtlmSspPacket)p;
                    NameValueCollection parameters = new NameValueCollection();
                    if (ntlmPacket.NtlmChallenge != null) {
                        if (ntlmChallengeList.ContainsKey(tcpSession.GetHashCode()))
                            ntlmChallengeList[tcpSession.GetHashCode()] = ntlmPacket.NtlmChallenge;
                        else
                            ntlmChallengeList.Add(tcpSession.GetHashCode(), ntlmPacket.NtlmChallenge);
                    }
                    if (ntlmPacket.DomainName != null) {
                        sourceHost.AddDomainName(ntlmPacket.DomainName);
                        parameters.Add("Target Domain", ntlmPacket.DomainName);
                    }
                    if (ntlmPacket.HostName != null) {
                        sourceHost.AddHostName(ntlmPacket.HostName, ntlmPacket.PacketTypeDescription);
                        parameters.Add("Target Host", ntlmPacket.HostName);
                    }
                    if (ntlmPacket.UserName != null) {
                        if (ntlmPacket.UserName.EndsWith("$")) sourceHost.AddHostName(ntlmPacket.UserName.TrimEnd(new[] { '$' }), ntlmPacket.PacketTypeDescription);
                        else {
                            sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.User, ntlmPacket.UserName);
                        }

                        string lanManagerHashInfo = null;
                        if (ntlmPacket.LanManagerResponse != null) {
                            lanManagerHashInfo = "LAN Manager Response: " + ntlmPacket.LanManagerResponse;
                            if (ntlmPacket.LanManagerResponse.Length >= 16) {
                                //$LM$a9c604d244c4e99d
                                string lmHash = ntlmPacket.LanManagerResponse.Substring(0, 16);
                                if (lmHash.Trim(new[] { '0' }).Length > 0)
                                    this.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.DomainName + "\\" + ntlmPacket.UserName, "$LM$" + lmHash, ntlmPacket.ParentFrame.Timestamp));
                            }
                        }
                        if (ntlmPacket.NtlmResponse != null) {
                            if (lanManagerHashInfo == null)
                                lanManagerHashInfo = "";
                            else
                                lanManagerHashInfo = lanManagerHashInfo + " - ";
                            lanManagerHashInfo = lanManagerHashInfo + "NTLM Response: " + ntlmPacket.NtlmResponse;
                        }
                        if (lanManagerHashInfo == null)
                            MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.UserName, ntlmPacket.ParentFrame.Timestamp));
                        else {
                            string ntlmChallenge = null;
                            if (ntlmChallengeList.ContainsKey(tcpSession.GetHashCode())) {
                                ntlmChallenge = ntlmChallengeList[tcpSession.GetHashCode()];
                                lanManagerHashInfo = "NTLM Challenge: " + ntlmChallenge + " - " + lanManagerHashInfo;

                            }
                            if (ntlmPacket.DomainName == null)
                                this.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.UserName, lanManagerHashInfo, ntlmPacket.ParentFrame.Timestamp));
                            else
                                this.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.DomainName + "\\" + ntlmPacket.UserName, lanManagerHashInfo, ntlmPacket.ParentFrame.Timestamp));

                            if (ntlmChallenge != null && ntlmPacket.NtlmResponse != null) {
                                string johnHash = null;
                                if (ntlmPacket.NtlmResponse.Length == 48)                                     //example: $NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233
                                    johnHash = "$NETNTLM$" + ntlmChallenge + "$" + ntlmPacket.NtlmResponse;
                                else if (ntlmPacket.NtlmResponse.Length > 48) {//NTLMv2
                                    //example: $NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000
                                    StringBuilder johnHashSB = new StringBuilder("$NETNTLMv2$");
                                    if (ntlmPacket.DomainName != null)
                                        johnHashSB.Append(ntlmPacket.DomainName);
                                    johnHashSB.Append("$");
                                    johnHashSB.Append(ntlmChallenge);
                                    johnHashSB.Append("$");
                                    johnHashSB.Append(ntlmPacket.NtlmResponse.Substring(0, 32));//NTProofStr
                                    johnHashSB.Append("$");
                                    johnHashSB.Append(ntlmPacket.NtlmResponse.Substring(32));//NTLMv2 response, minus NTProofStr
                                    johnHash = johnHashSB.ToString();
                                }
                                if (johnHash != null) MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "NTLMSSP", ntlmPacket.DomainName + "\\" + ntlmPacket.UserName, johnHash, ntlmPacket.ParentFrame.Timestamp));
                            }
                        }
                    }
                    if (parameters.Count > 0) {
                        //add message type as well
                        //NtlmMessageTypes
                        if(Enum.IsDefined(typeof(NtlmSspPacket.NtlmMessageTypes), ntlmPacket.MessageType)) {
                            NtlmSspPacket.NtlmMessageTypes messageType = (NtlmSspPacket.NtlmMessageTypes)ntlmPacket.MessageType;
                            parameters.Add("NTLM Message Type", messageType.ToString());
                        }
                        this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(ntlmPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, tcpSession.Flow.FiveTuple.Transport, sourcePort, destinationPort, parameters, ntlmPacket.ParentFrame.Timestamp, "NTLMSSP"));
                    }
                    successfullyExtractedBytes += ntlmPacket.ParentFrame.Data.Length;//it's OK to return a larger value that what was parsed
                }
            }
            
            return successfullyExtractedBytes;
        }

        public void Reset() {
            //throw new Exception("The method or operation is not implemented.");
        }

        #endregion
    }
}
