using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace PacketHandlerFramework.PacketHandlers {
    internal class McNmfPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private const McNmfPacket.Encoding DEFAULT_ENCODING = McNmfPacket.Encoding.SOAP_1_2_MC_NBFSE;//Binary with in-band dictionary

        private static readonly Type[] mcNmfPacketType = new Type[] { typeof(McNmfPacket) };

        private PopularityList<NetworkTcpSession, McNmfPacket.Encoding> sessionEncodings;
        private PopularityList<NetworkTcpSession, string> protocolUpgradeRequests;

        public McNmfPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.sessionEncodings = new PopularityList<NetworkTcpSession, McNmfPacket.Encoding>(100);
            this.protocolUpgradeRequests = new PopularityList<NetworkTcpSession, string>(100);
        }

        public ApplicationLayerProtocol HandledProtocol => ApplicationLayerProtocol.MC_NMF;

        public override Type[] ParsedTypes => mcNmfPacketType;

        //public override Type[] ParsedTypes => { typeof(McNmfPacket) };
        //public override Type[] ParsedTypes { get; } = { typeof(McNmfPacket) };

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {

            if (base.TryGetPacket(packetList, out McNmfPacket mcNmfPacket)) {

                NetworkHost sourceHost, destinationHost;
                ushort sourcePort, destinationPort;
                if (transferIsClientToServer) {
                    sourceHost = tcpSession.ClientHost;
                    sourcePort = tcpSession.ClientTcpPort;
                    destinationHost = tcpSession.ServerHost;
                    destinationPort = tcpSession.ServerTcpPort;
                }
                else {
                    sourceHost = tcpSession.ServerHost;
                    sourcePort = tcpSession.ServerTcpPort;
                    destinationHost = tcpSession.ClientHost;
                    destinationPort = tcpSession.ClientTcpPort;
                }

                NameValueCollection parameters = new NameValueCollection();
                foreach (var record in mcNmfPacket.Records.Where(r => !string.IsNullOrEmpty(r.RecordStringValue))) {
                    parameters.Add("MC-NMF " + record.RecordType.ToString(), record.RecordStringValue);
                    if(record.RecordType == McNmfPacket.RecordType.KnownEncoding) {
                        if(Enum.TryParse<McNmfPacket.Encoding>(record.RecordStringValue, out McNmfPacket.Encoding encoding)) {
                            sessionEncodings[tcpSession] = encoding;
                        }
                    }
                    else if(record.RecordType == McNmfPacket.RecordType.Via) {
                        if(Uri.TryCreate(record.RecordStringValue, UriKind.RelativeOrAbsolute, out Uri netTcpBindingUri)) {
                            if (netTcpBindingUri.HostNameType == UriHostNameType.Dns) {
                                destinationHost.AddHostName(netTcpBindingUri.Host, "MC-NMF");
                            }
                        }
                    }
                    else if(record.RecordType == McNmfPacket.RecordType.UpgradeRequest) {
                        this.protocolUpgradeRequests[tcpSession] = record.RecordStringValue;
                    }
                }
                foreach (McNmfPacket.Record dataRecord in mcNmfPacket.Records.Where(r => r.RecordType == McNmfPacket.RecordType.SizedEnvelope)) {
                    if (dataRecord.Data?.Length > 0) {

                        if(this.TryCreateActiveFileAssembler(mcNmfPacket, tcpSession, transferIsClientToServer, (uint)dataRecord.Data.Length, out var assembler))
                            assembler.AddData(dataRecord.Data, (ushort)mcNmfPacket.ParentFrame.FrameNumber);

                    }
                }
                if(mcNmfPacket.TrailingData.HasValue) {
                    (int trailingOffset, uint trailingLength) = mcNmfPacket.TrailingData.Value;
                    if (this.TryCreateActiveFileAssembler(mcNmfPacket, tcpSession, transferIsClientToServer, trailingLength, out var assembler)) {
                        //no need to add data here. The assembler will handle that...
                    }
                }
                if (parameters.Count > 0) {
                    Events.ParametersEventArgs parametersEA = new Events.ParametersEventArgs(mcNmfPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, tcpSession.Flow.FiveTuple.Transport, sourcePort, destinationPort, parameters, mcNmfPacket.ParentFrame.Timestamp, "MC-NMF Record");
                    this.MainPacketHandler.OnParametersDetected(parametersEA);
                }
                if (mcNmfPacket.Records.Any(r => r.RecordType == McNmfPacket.RecordType.UpgradeResponse)) {
                    ApplicationLayerProtocol nextProtocol = ApplicationLayerProtocol.Unknown;
                    if (this.protocolUpgradeRequests.TryGetValue(tcpSession, out string upgradeProtocol)) {
                        if (upgradeProtocol == "application/ssl-tls")
                            nextProtocol = ApplicationLayerProtocol.SSL;
                        //TODO add support for "application/negotiate", which leads to MC-NNS and GSS-API/SPNEGO
                        //GSS-API and SPNEGO is currently implemented in SmbPacket.SecurityBlob


                        //This behaviour might be legitimate (*.servicebus.windows.net)
                        //or a sign of MetaStealer (Suricata SID 2054404 or 8001933)
                        //https://community.emergingthreats.net/t/metastealer-v-5-tls/1800
                    }
                    tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(nextProtocol, false);
                }
                return mcNmfPacket.PacketLength;
            }
            else
                return 0;
        }

        private bool TryCreateActiveFileAssembler(McNmfPacket mcNmfPacket, NetworkTcpSession tcpSession, bool transferIsClientToServer, uint fileSize, out FileStreamAssembler assembler) {

            McNmfPacket.Encoding sessionEncoding = DEFAULT_ENCODING;
            if (sessionEncodings.ContainsKey(tcpSession))
                sessionEncoding = sessionEncodings[tcpSession];

            //TODO parse contents based on encoding before saving to file
            //NBFSE = XmlDictionaryReader.CreateBinaryReader
            //Redline uses nettcpbinding with channelfactory / icontextchannel
            //https://medium.com/s2wblog/deep-analysis-of-redline-stealer-leaked-credential-with-wcf-7b31901da904
            //https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer


            string extension = sessionEncoding.ToString().Split('_').Last().ToLower();
            if (string.IsNullOrEmpty(extension))
                extension = sessionEncoding.ToString().ToLower();
            string filename = "MC-NMF." + mcNmfPacket.ParentFrame.Timestamp.ToUniversalTime().ToString("yyMMddhhmmssffff") + "." + extension;
            string fileDetails = "MC-NMF";
            assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.MC_NMF, filename, "/", fileDetails, mcNmfPacket.ParentFrame.FrameNumber, mcNmfPacket.ParentFrame.Timestamp);
            assembler.FileContentLength = fileSize;
            assembler.FileSegmentRemainingBytes = fileSize;
            if (assembler.TryActivate()) {
                this.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                return true;
            }
            else
                return false;
        }

        public void Reset() {
            this.sessionEncodings.Clear();
        }
    }
}
