using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.FileTransfer;
using PacketParser.Packets;
using SharedUtils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
#if NETFRAMEWORK
using System.Drawing;
using System.Drawing.Imaging;
#endif
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static PacketHandlerFramework.PacketHandlers.RfbPacketHandler;
//using System.Web.ModelBinding;
//using System.Web.UI.WebControls.WebParts;

namespace PacketHandlerFramework.PacketHandlers {

#if !OMIT_MALWARE_PROTOCOLS
    internal class NjRatPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        //There isn't any good publibly available protocol spec for njRAT, but here's some info:
        //https://github.com/csieteco/njRatActiveDefense/blob/master/njdetector.py
        //https://cybergeeks.tech/just-another-analysis-of-the-njrat-malware-a-step-by-step-approach/
        //https://faculty.cc.gatech.edu/~pearce/papers/rats_usenix_2018.pdf
        //Approach of an Active Defense Protocol to Deal with RAT Malware - A Colombian Case Study Against njRAT Campaigns (Quinterno et al)
        //Command Handler: https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Modules/Class7.vb
        //File Manager?: https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Forms/Manager.vb
        //Great analysis of the "old" protocol (no length fields) published in June 28, 2013!! https://web.archive.org/web/20180710040949/http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered-1.pdf
        //njRAT decoder for Zeek (Spicy) https://github.com/keithjjones/zeek-njrat-detector
        //https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/


        private static readonly System.Text.RegularExpressions.Regex IMAGE_TRANSFORM_INFO_REGEX = new System.Text.RegularExpressions.Regex("^[0-9]+,[0-9]+-[0-9]+-[0-9]+,[0-9]+");//[w],[h]-[sprite-h]-[x1],[y1]

        public override Type[] ParsedTypes { get; } = { typeof(NjRatPacket) };

        private PopularityList<IPEndPoint, C2ServerInfo> c2ServerInfo;

        

        private readonly PopularityList<FiveTuple, VictimDesktop> victimDesktops;

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.njRAT;
            }
        }

        public NjRatPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.c2ServerInfo = new PopularityList<IPEndPoint, C2ServerInfo>(100);
            this.victimDesktops = new PopularityList<FiveTuple, VictimDesktop>(100);
            this.victimDesktops.PopularityLost += (_, desktop) => desktop?.Dispose();
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            NjRatPacket njRatPacket = null;
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                Type pType = p.GetType();
                if (pType == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
                else if (pType == typeof(NjRatPacket))
                    njRatPacket = (NjRatPacket)p;
            }
            if (njRatPacket != null) {
                NameValueCollection parms = new NameValueCollection();
                int parsedBytes = njRatPacket.ParsedBytesCount;

                if (!string.IsNullOrEmpty(njRatPacket.CommandString)) {
                    if (transferIsClientToServer)
                        parms.Add("njRAT bot command", njRatPacket.CommandString);
                    else
                        parms.Add("njRAT server command", njRatPacket.CommandString);
                }
                IPEndPoint serverEndPoint = new IPEndPoint(tcpSession.ServerHost.IPAddress, tcpSession.ServerTcpPort);
                if (!this.c2ServerInfo.ContainsKey(serverEndPoint)) this.c2ServerInfo.Add(serverEndPoint, new C2ServerInfo(serverEndPoint));
                C2ServerInfo c2ServerInfo = this.c2ServerInfo[serverEndPoint];
                c2ServerInfo.TryAddSplitterCandidate(njRatPacket.SplitterCandidate);

                string splitter = null;
                if (njRatPacket.MessageLength > 4000 && njRatPacket.ParsedBytesCount == 0) {
                    //reassemble data after last splitter to disk

                    string filename = "njRAT-UNKNOWN";
                    string fileDetails = "njRAT";
                    if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                        filename = "njRAT-" + njRatPacket.CommandString;
                    filename += "-" + njRatPacket.ParentFrame.Timestamp.ToUniversalTime().ToString("yyMMddHHmmss");

                    splitter = c2ServerInfo.GetLikelySplitter();
                    byte[] splitterBytes = Encoding.ASCII.GetBytes(splitter);
                    int lastDataFieldOffset = PacketParser.Utils.BoyerMoore.LastIndexOf(njRatPacket.ParentFrame.Data, splitterBytes, njRatPacket.MessageStartIndex) + splitterBytes.Length;

                    string njRatImageTransformString = null;

                    if (lastDataFieldOffset > 0 && !string.IsNullOrEmpty(splitter)) {
                        try {
                            string s = Encoding.ASCII.GetString(njRatPacket.ParentFrame.Data, njRatPacket.MessageStartIndex, lastDataFieldOffset - njRatPacket.MessageStartIndex);
                            string[] sa = s.Split(new string[] { splitter }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (string p in sa) {
                                if (p.Length < 20)
                                    fileDetails += " " + p;
                            }
                            
                            if(sa.Length > 2 && !string.IsNullOrEmpty(sa[2]) && IMAGE_TRANSFORM_INFO_REGEX.IsMatch(sa[2])) {
                                njRatImageTransformString = sa[2];
                                parms.Add("Image transform info", njRatImageTransformString);
                                lock(this.victimDesktops) {
                                    VictimDesktop desktop;
                                    if (this.victimDesktops.ContainsKey(tcpSession.Flow.FiveTuple)) {
                                        desktop = this.victimDesktops[tcpSession.Flow.FiveTuple];
                                        desktop.SetNextTransform(njRatImageTransformString);
                                    }
                                    else {
                                        desktop = new VictimDesktop(njRatImageTransformString);
                                        this.victimDesktops.Add(tcpSession.Flow.FiveTuple, desktop);
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                    int fileSize = njRatPacket.MessageStartIndex + njRatPacket.MessageLength - lastDataFieldOffset;
                    if (fileSize > 1) {
                        FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);
                        if (assembler.TryActivate()) {
                            this.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                            assembler.FileContentLength = fileSize;
                            assembler.FileSegmentRemainingBytes = fileSize;
                            assembler.AddData(njRatPacket.ParentFrame.Data.Skip(lastDataFieldOffset).ToArray(), tcpPacket.SequenceNumber);
                            assembler.FileReconstructed += this.Assembler_FileReconstructed;
                            if (njRatPacket.PacketLength > parsedBytes)
                                parsedBytes = njRatPacket.PacketLength;
                        }
                    }
                }
                else if (C2Message.TryParse(njRatPacket, transferIsClientToServer, c2ServerInfo, out C2Message c2Message)) {
                    splitter = c2Message.SplitterCandidate;
                    foreach ((string name, string value) in c2Message.KnownFields) {
                        parms.Add(name, value);
                        if (name == NjRatPacket.HOSTNAME)
                            tcpSession.ClientHost.AddHostName(value, "njRAT");
                        else if (name == NjRatPacket.OS)
                            tcpSession.ClientHost.AddNumberedExtraDetail(name, value);
                        else if (name == NjRatPacket.USER)
                            tcpSession.ClientHost.AddNumberedExtraDetail(name, value);
                        else if (name == NjRatPacket.BOTNET_BOTID) {
                            tcpSession.ClientHost.AddNumberedExtraDetail("njRAT bot ID", value);
                            if (value.Contains('_'))
                                tcpSession.ServerHost.AddNumberedExtraDetail("njRAT botnet", value.Split('_').First());
                        }
                        else if (name == NjRatPacket.VERSION)
                            tcpSession.ServerHost.AddNumberedExtraDetail("njRAT version", value);
                        else if (name == NjRatPacket.INSTALL_DATE)
                            tcpSession.ClientHost.AddNumberedExtraDetail("njRAT install date", value);
                    }
                    foreach ((string username, string password, string site) in c2Message.Credentials) {
                        NetworkCredential networkCredential = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, site, username, password, njRatPacket.ParentFrame.Timestamp);
                        MainPacketHandler.AddCredential(networkCredential);
                    }

                    if (c2Message.MessageTypeBot == NjRatPacket.BotMessageType.post) {
                        string filename = c2Message.KnownFields.Where(f => f.name == NjRatPacket.FILENAME)?.First().value;
                        string lengthString = c2Message.KnownFields.Where(f => f.name == NjRatPacket.SIZE)?.First().value;
                        if (!string.IsNullOrEmpty(filename) && !string.IsNullOrEmpty(lengthString) && int.TryParse(lengthString, out int fileSize)) {
                            if (fileSize > 1) {
                                string fileDetails = "njRAT post " + filename;
                                FileStreamAssembler assembler = new FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);

                                if (assembler.TryActivate()) {
                                    MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                    assembler.FileContentLength = fileSize;
                                    assembler.FileSegmentRemainingBytes = fileSize;
                                }
                            }
                        }
                    }
                    else if (c2Message.MessageTypeBot == NjRatPacket.BotMessageType.get) {
                        string filename = c2Message.KnownFields.Where(f => f.name == NjRatPacket.FILENAME)?.First().value;
                        //string ipColonPort = c2Message.KnownFields.Where(f => f.name == C2Message.IP_COLON_PORT)?.First().value;
                        if (c2ServerInfo.requestedFileSizes.ContainsKey(filename)) {
                            int fileSize = c2ServerInfo.requestedFileSizes[filename];
                            if (!string.IsNullOrEmpty(filename) && fileSize > 1) {
                                string fileDetails = "njRAT get " + filename;
                                FileStreamAssembler assembler = new FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, !transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);

                                if (assembler.TryActivate()) {
                                    MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                    assembler.FileContentLength = fileSize;
                                    assembler.FileSegmentRemainingBytes = fileSize;
                                }
                            }
                        }
                    }
                    else if (c2Message.MessageTypeBot == NjRatPacket.BotMessageType.kl) {
                        //KeyLog data
                        string fileDetails = "njRAT";
                        if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                            fileDetails += " " + njRatPacket.CommandString;

                        byte[] splitterBytes = Encoding.ASCII.GetBytes(splitter);
                        int lastDataFieldOffset = PacketParser.Utils.BoyerMoore.LastIndexOf(njRatPacket.ParentFrame.Data, splitterBytes, njRatPacket.MessageStartIndex) + splitterBytes.Length;

                        if (lastDataFieldOffset > 0 && !string.IsNullOrEmpty(splitter)) {

                            int fileSize = njRatPacket.MessageStartIndex + njRatPacket.MessageLength - lastDataFieldOffset;
                            if (fileSize > 1) {
                                string filename = "njRAT-" + njRatPacket.CommandString + "-" + njRatPacket.ParentFrame.Timestamp.ToUniversalTime().ToString("yyMMddHHmmss") + ".keylog";
                                FileStreamAssembler assembler = new FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);
                                assembler.ContentEncoding = HttpPacket.ContentEncodings.Base64;

                                if (assembler.TryActivate()) {
                                    this.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                    assembler.FileContentLength = fileSize;
                                    assembler.FileSegmentRemainingBytes = fileSize;
                                    assembler.AddData(njRatPacket.ParentFrame.Data.Skip(lastDataFieldOffset).ToArray(), tcpPacket.SequenceNumber);
                                    if (njRatPacket.PacketLength > parsedBytes)
                                        parsedBytes = njRatPacket.PacketLength;
                                }
                            }
                        }
                    }
                    else if (c2Message.RawFieldData?.Length > 0 && c2Message.RawFieldDataTotalLength > 1) {
                        //write raw data to disk

                        string fileDetails = "njRAT";
                        if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                            fileDetails += " " + njRatPacket.CommandString;
                        fileDetails += string.Join(" ", c2Message.KnownFields.Where(f => f.value.Length < 20).Select(f => f.value));
                        string filename = "njRAT-" + njRatPacket.CommandString + "-" + njRatPacket.ParentFrame.Timestamp.ToUniversalTime().ToString("yyMMddHHmmss");
                        FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);
                        if (assembler.TryActivate()) {
                            this.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                            assembler.FileContentLength = c2Message.RawFieldDataTotalLength;
                            assembler.FileSegmentRemainingBytes = c2Message.RawFieldDataTotalLength;
                            assembler.AddData(c2Message.RawFieldData, tcpPacket.SequenceNumber);
                            if (njRatPacket.PacketLength > parsedBytes)
                                parsedBytes = njRatPacket.PacketLength;
                        }

                    }
                }

                if (!string.IsNullOrEmpty(splitter)) tcpSession.ServerHost.AddNumberedExtraDetail("njRAT splitter", splitter);


                if (parms.Count > 0) {
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

                    string details = "njRAT";
                    if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                        details += " " + njRatPacket.CommandString;
                    Events.ParametersEventArgs parametersEA = new Events.ParametersEventArgs(njRatPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, tcpSession.Flow.FiveTuple.Transport, sourcePort, destinationPort, parms, njRatPacket.ParentFrame.Timestamp, details);
                    this.MainPacketHandler.OnParametersDetected(parametersEA);
                }
                return parsedBytes;
            }
            else
                return 0;
        }

        private void Assembler_FileReconstructed(string extendedFileId, ReconstructedFile file) {
#if NETFRAMEWORK
            if(file.IsImage()) {
                var fiveTuple = file.FiveTuple;
                //var startFrame = file.InitialFrameNumber;
                lock (this.victimDesktops) {
                    if (this.victimDesktops.ContainsKey(fiveTuple)) {
                        VictimDesktop desktop = this.victimDesktops[fiveTuple];
                        using (Bitmap bm = new Bitmap(file.FilePath)) {
                            desktop.UpdateDesktop(bm);
                        }
                        //bool transferIsClientToServer = desktop.ServerIP.Equals(session.ClientHost.IPAddress);

                        string filename = "njRAT_Desktop_" + file.Timestamp.ToUniversalTime().ToString("yyMMddHHmmss") + ".jpg";
                        FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, file.FiveTuple, file.TransferIsClientToServer, FileStreamTypes.njRAT, filename, "", file.Details, file.InitialFrameNumber, file.Timestamp);
                        if (assembler.TryActivate()) {
                            byte[] jpg = desktop.GetScreenshot(file.Timestamp);
                            assembler.FileSegmentRemainingBytes = jpg.Length;
                            assembler.SetRemainingBytesInFile(jpg.Length);
                            assembler.AddData(jpg, 0);
                        }
                    }
                }
            }
            else
#endif
            if(file.ExtensionFromHeader == "gz") {
                byte[] md5Hash = null;
                using (System.IO.FileStream fs = new FileStream(file.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    using(GZipStream gz = new GZipStream(fs, CompressionMode.Decompress, false)) {
                        using (MD5 md5 = new MD5CryptoServiceProvider()) {
                            md5Hash = md5.ComputeHash(gz);
                        }
                    }
                }
                if(md5Hash?.Length > 0) {
                    string md5String = PacketParser.Utils.ByteConverter.ToHexString(md5Hash, md5Hash.Length, true, false);
                    string uncompressedFilename = file.Filename;
                    if (uncompressedFilename.EndsWith(".gz"))
                        uncompressedFilename = uncompressedFilename.Substring(0, uncompressedFilename.Length - 3);
                    NameValueCollection parameters = new NameValueCollection() {
                        {  uncompressedFilename + " MD5", md5String },
                    };
                    var hp = new Events.ParametersEventArgs(file.InitialFrameNumber, file.SourceHost, file.DestinationHost, file.FiveTuple.Transport, file.SourcePort, file.DestinationPort, parameters, file.Timestamp, "Hash of gz compressed njRAT file " + file.Filename);
                    this.MainPacketHandler.OnParametersDetected(hp);
                }
            }
        }

        public void Reset() {
            this.c2ServerInfo.Clear();
        }

        internal class C2Message {


            //internal List<string> DecodedFieldValues { get; }
            internal List<(string name, string value)> KnownFields { get; }
            internal List<(string username, string password, string site)> Credentials { get; }
            internal string SplitterCandidate { get; private set; }
            internal NjRatPacket.ServerMessageType? MessageTypeServer { get; }
            internal NjRatPacket.BotMessageType? MessageTypeBot { get; }

            internal byte[] RawFieldData { get; private set; } = null;
            internal int RawFieldDataTotalLength = 0;

            private C2ServerInfo c2ServerInfo;

            internal static bool TryParse(NjRatPacket njRatPacket, bool clientToServer, C2ServerInfo c2ServerInfo, out C2Message c2Message) {

                if (!string.IsNullOrEmpty(njRatPacket.CommandString)) {
                    if (clientToServer) {
                        if (NjRatPacket.BotMsgDict.ContainsKey(njRatPacket.CommandString)) {
                            c2Message = new C2Message(njRatPacket, NjRatPacket.BotMsgDict[njRatPacket.CommandString], c2ServerInfo);
                            return true;

                        }

                    }
                    else {//server -> client
                        if (NjRatPacket.ServerMsgDict.ContainsKey(njRatPacket.CommandString)) {
                            NjRatPacket.ServerMessageType? msgOrNull = NjRatPacket.ServerMsgDict[njRatPacket.CommandString];
                            if (msgOrNull != null) {
                                c2Message = new C2Message(njRatPacket, msgOrNull.Value, c2ServerInfo);
                                return true;
                            }

                        }
                    }
                }
                c2Message = null;
                return false;
            }


            //client->server
            internal C2Message(NjRatPacket njRatPacket, NjRatPacket.BotMessageType messageTypeBot, C2ServerInfo c2ServerInfo) : this(c2ServerInfo) {
                this.MessageTypeBot = messageTypeBot;
                this.MessageTypeServer = null;

                if (NjRatPacket.BotMessageFieldInfo.ContainsKey(messageTypeBot)) {
                    (string name, NjRatPacket.FieldEncoding encoding)[] fieldInfo = NjRatPacket.BotMessageFieldInfo[messageTypeBot];
                    this.ParseFields(njRatPacket, fieldInfo);
                }
                else if (messageTypeBot == NjRatPacket.BotMessageType.ret) {
                    //retrieve credentials
                    string[] retArgs = this.GetFields(njRatPacket).ToArray();
                    if (retArgs.Length >= 2) {
                        char[] credentialSeparators = new char[] { ' ', '*', '\n', '\r' };
                        if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(retArgs[1], out string credentials)) {
                            string[] creds = credentials.Split(credentialSeparators).Where(c => c.Trim().Length > 0).ToArray();
                            for (int i = 0; i < creds.Length; i++) {
                                if (creds[i].Contains(':')) {
                                    string[] credParts = creds[i].Split(':');
                                    if (credParts.Length == 3) {
                                        string credNumber = " " + (i + 1);
                                        if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(credParts[0], out string site))
                                            this.KnownFields.Add(("Site" + credNumber, site));
                                        if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(credParts[1], out string user)) {
                                            this.KnownFields.Add((NjRatPacket.USER + credNumber, user));
                                            if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(credParts[2], out string pass)) {
                                                this.KnownFields.Add(("Password" + credNumber, pass));
                                                this.Credentials.Add((user, pass, site));
                                            }
                                        }
                                        else
                                            this.KnownFields.Add((NjRatPacket.USER + credNumber, credParts[0]));
                                    }

                                }
                                else
                                    this.KnownFields.Add(("Credential " + (i + 1), creds[i]));
                            }
                        }
                    }
                }
            }

            //server->client
            internal C2Message(NjRatPacket njRatPacket, NjRatPacket.ServerMessageType messageTypeServer, C2ServerInfo c2ServerInfo) : this(c2ServerInfo) {
                this.MessageTypeBot = null;
                this.MessageTypeServer = messageTypeServer;

                if (NjRatPacket.ServerMessageFieldInfo.ContainsKey(messageTypeServer)) {
                    (string name, NjRatPacket.FieldEncoding encoding)[] fieldInfo = NjRatPacket.ServerMessageFieldInfo[messageTypeServer];
                    this.ParseFields(njRatPacket, fieldInfo);
                }
                else if (messageTypeServer == NjRatPacket.ServerMessageType.Ex) {
                    string[] exArgs = this.GetFields(njRatPacket).ToArray();
                    if (exArgs.Length > 0 && Enum.TryParse(exArgs[0], out NjRatPacket.Plugins plugin)) {
                        this.KnownFields.Add(("Ex Plugin", exArgs[0]));
                        if (plugin == NjRatPacket.Plugins.rs) {
                            if (exArgs.Length == 3 && exArgs[1] == "!") {
                                //base64 decode remote shell command
                                this.KnownFields.Add(("Type", exArgs[1]));
                                if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string decodedCommand))
                                    this.KnownFields.Add(("Command", decodedCommand));
                            }
                            else
                                this.AddUnknownFields(exArgs.Skip(1));
                        }
                        else if (plugin == NjRatPacket.Plugins.fm) {
                            if (exArgs.Length > 2 && Enum.TryParse(exArgs[1], out NjRatPacket.FileManagerActions action)) {
                                this.KnownFields.Add(("File Manager Action", exArgs[1]));

                                if (action == NjRatPacket.FileManagerActions.dw && exArgs.Length == 4) {
                                    //download
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string downloadFile))
                                        this.KnownFields.Add(("Download File", downloadFile));
                                }
                                else if (action == NjRatPacket.FileManagerActions.up && exArgs.Length == 5) {
                                    //upload
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out string uploadFile)) {
                                        this.KnownFields.Add(("Upload File", uploadFile));
                                        if (int.TryParse(exArgs[4], out int size)) {
                                            this.KnownFields.Add((NjRatPacket.SIZE, exArgs[4]));
                                            c2ServerInfo?.requestedFileSizes.Add(uploadFile, size);
                                        }
                                    }
                                }
                                else if (action == NjRatPacket.FileManagerActions.fl && exArgs.Length == 4) {
                                    //run from link
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string source))
                                        this.KnownFields.Add(("Source", source));
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out string destination))
                                        this.KnownFields.Add(("Destination", destination));
                                }
                                else if (action == NjRatPacket.FileManagerActions.rn && exArgs.Length == 3) {
                                    //Run
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string runFile))
                                        this.KnownFields.Add(("Run", runFile));
                                }
                                else if (action == NjRatPacket.FileManagerActions.cp && exArgs.Length == 4) {
                                    //copy
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string source))
                                        this.KnownFields.Add(("Source", source));
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out string destination))
                                        this.KnownFields.Add(("Destination", destination));
                                }

                                else if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string actionParam)) {
                                    this.KnownFields.Add(("File Manager Value", actionParam));
                                }
                                else if (exArgs.Length > 3 && PacketParser.Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out actionParam)) {
                                    this.KnownFields.Add(("File Manager Value", actionParam));
                                }
                            }
                            else
                                this.AddUnknownFields(exArgs.Skip(1), true);
                        }
                        else
                            this.AddUnknownFields(exArgs.Skip(1));

                    }
                }
            }

            private void AddUnknownFields(IEnumerable<string> fieldValues, bool base64DecodeValues = false) {
                foreach (string v in fieldValues) {
                    if (base64DecodeValues && PacketParser.Utils.StringManglerUtil.TryReadFromBase64(v, out string decodedValue))
                        this.KnownFields.Add(("?", decodedValue));
                    else
                        this.KnownFields.Add(("?", v));
                }
            }

            private C2Message(C2ServerInfo c2ServerInfo) {
                this.KnownFields = new List<(string name, string value)>();
                this.Credentials = new List<(string username, string password, string site)>();
                this.c2ServerInfo = c2ServerInfo;
                this.SplitterCandidate = this.c2ServerInfo.GetLikelySplitter();
            }

            private void ParseFields(NjRatPacket njRatPacket, (string name, NjRatPacket.FieldEncoding encoding)[] fieldInfo) {
                foreach (var knownFieldInfo in this.ExtractKnownFields(njRatPacket, fieldInfo)) {
                    if(knownFieldInfo.fieldName != NjRatPacket.UNKNOWN_FIELD || !string.IsNullOrEmpty(knownFieldInfo.fieldValue))
                        this.KnownFields.Add(knownFieldInfo);
                }
                if (fieldInfo.Any(f => f.encoding == NjRatPacket.FieldEncoding.raw)) {
                    //int rawFieldIndex = Array.FindIndex(fieldInfo, fi => fi.encoding == FieldEncoding.raw);
                    //byte[] splitterBytes = ASCIIEncoding.ASCII.GetBytes(this.SplitterCandidate);


                    this.RawFieldData = this.ExtractRawData(njRatPacket, fieldInfo, out int rawFieldOffsetInMessage);
                    this.RawFieldDataTotalLength = njRatPacket.MessageLength - rawFieldOffsetInMessage;
                }
            }


            private byte[] ExtractRawData(NjRatPacket njRatPacket, (string name, NjRatPacket.FieldEncoding encoding)[] fieldInfo, out int rawFieldOffsetInMessage) {
                //byte[] data = njRatPacket.GetPacketData();
                int availableDataBytes = njRatPacket.MessageLength;
                if (njRatPacket.MessageStartIndex + njRatPacket.MessageLength > njRatPacket.PacketStartIndex + njRatPacket.PacketLength)
                    availableDataBytes = njRatPacket.PacketStartIndex + njRatPacket.PacketLength - njRatPacket.MessageStartIndex;
                byte[] data = new byte[availableDataBytes];
                Array.Copy(njRatPacket.ParentFrame.Data, njRatPacket.MessageStartIndex, data, 0, data.Length);

                byte[] delimiterBytes = Encoding.ASCII.GetBytes(this.SplitterCandidate);
                int offset = PacketParser.Utils.BoyerMoore.IndexOf(data, delimiterBytes, 0) + delimiterBytes.Length;
                rawFieldOffsetInMessage = -1;
                for (int i = 0; i < fieldInfo.Length; i++) {
                    if (offset < 1)
                        return null;
                    if (offset >= data.Length)
                        return null;
                    if (fieldInfo[i].encoding == NjRatPacket.FieldEncoding.raw) {
                        rawFieldOffsetInMessage = offset;
                        return data.Skip(offset).ToArray();
                    }
                    else {
                        //move ahead past next delimiter
                        offset = PacketParser.Utils.BoyerMoore.IndexOf(data, delimiterBytes, offset) + delimiterBytes.Length;
                    }
                }
                return null;
            }

            private IEnumerable<string> GetFields(NjRatPacket njRatPacket) {
                string fieldMessage = Encoding.ASCII.GetString(njRatPacket.ParentFrame.Data, njRatPacket.SplitterIndex, Math.Min(njRatPacket.PacketEndIndex - njRatPacket.SplitterIndex + 1, njRatPacket.MessageLength - njRatPacket.CommandString.Length));
                return fieldMessage.Split(new string[] { this.SplitterCandidate }, StringSplitOptions.None).Skip(1);
            }

            private IEnumerable<(string fieldName, string fieldValue)> ExtractKnownFields(NjRatPacket njRatPacket, (string name, NjRatPacket.FieldEncoding encoding)[] fieldInfo) {
                if (fieldInfo.Length > 0 && !fieldInfo.Any(f => f.encoding == NjRatPacket.FieldEncoding.raw)) {
                    if (njRatPacket.SplitterIndex > 0) {
                        //verify delimiter using fieldInfo count
                        string fieldMessage = Encoding.ASCII.GetString(njRatPacket.ParentFrame.Data, njRatPacket.SplitterIndex, Math.Min(njRatPacket.PacketEndIndex - njRatPacket.SplitterIndex + 1, njRatPacket.MessageLength - njRatPacket.CommandString.Length));
                        //all fields are text or base64
                        string bestSplitterCandidate = this.SplitterCandidate;
                        if (njRatPacket.PacketEndIndex + 1 >= njRatPacket.MessageStartIndex + njRatPacket.MessageLength) {
                            for (int i = this.SplitterCandidate.Length; i > 1; i--) {
                                string[] delims = new string[] { this.SplitterCandidate.Substring(0, i) };
                                string[] _fields = fieldMessage.Split(delims, StringSplitOptions.None);
                                if (_fields.Length == fieldInfo.Length + 1) {
                                    bestSplitterCandidate = delims[0];
                                    break;
                                }
                                else if (fieldInfo.Length > 4 && _fields.Length >= fieldInfo.Length && _fields.Length <= fieldInfo.Length + 2) {
                                    //allow +-1 diff
                                    bestSplitterCandidate = delims[0];
                                    break;
                                }
                                else if (fieldInfo.Length > 10 && _fields.Length + 1 >= fieldInfo.Length && _fields.Length <= fieldInfo.Length + 3) {
                                    //allow +-2 diff
                                    bestSplitterCandidate = delims[0];
                                    break;
                                }
                            }
                        }
                        if (!string.IsNullOrEmpty(bestSplitterCandidate)) {
                            this.c2ServerInfo.TryAddSplitterCandidate(bestSplitterCandidate);
                            this.SplitterCandidate = this.c2ServerInfo.GetLikelySplitter();
                        }

                        //extract known fields
                        string[] fields = this.GetFields(njRatPacket).ToArray();
                        bool knownFields = fields.Length == fieldInfo.Length;
                        for (int i = 0; i < fields.Length; i++) {
                            if(knownFields) {
                                if (fieldInfo[i].encoding == NjRatPacket.FieldEncoding.plaintext)
                                    yield return (fieldInfo[i].name, fields[i]);
                                else if (fieldInfo[i].encoding == NjRatPacket.FieldEncoding.base64) {
                                    string fieldName = fieldInfo[i].name;
                                    string fieldValue = fields[i];
                                    if (PacketParser.Utils.StringManglerUtil.TryReadFromBase64(fields[i], out string decodedString))
                                        fieldValue = decodedString.TrimEnd('\0').Trim();
                                    else {
                                        knownFields = false;
                                        fieldName = "param" + i;
                                    }
                                    yield return (fieldName, fieldValue);

                                }
                                else
                                    yield return (fieldInfo[i].name, "[data]");
                            }
                            else {
                                yield return ("param" + i, fields[i]);
                            }
                        }

                    }
                }
            }

        }

        internal class C2ServerInfo {
            private List<string> splitterCandidates = new List<string>();
            private string likelySplitter = null;

            internal IPAddress ServerIP { get; }
            internal int ServerPort { get; }

            internal PopularityList<string, int> requestedFileSizes;

            internal C2ServerInfo(IPEndPoint endPoint) {
                this.ServerIP = endPoint.Address;
                this.ServerPort = endPoint.Port;
                this.requestedFileSizes = new PopularityList<string, int>(10);
            }

            public bool TryAddSplitterCandidate(string candidate) {
                if (!string.IsNullOrEmpty(candidate))
                    if (!this.splitterCandidates.Contains(candidate)) {
                        //verify that it is an OK candidate by checking that the first character is the same as all the others
                        if (this.splitterCandidates.All(old => old[0] == candidate[0])) {
                            //an extra check just to be sure the new candidate is not a truncated splitter
                            string previousLikelySplitter = this.GetLikelySplitter();
                            if (previousLikelySplitter == null || this.splitterCandidates.Count < 3 || candidate.Length > 4 || candidate.Length > previousLikelySplitter.Length / 2) {
                                this.splitterCandidates.Add(candidate);
                                this.likelySplitter = null;
                                return true;
                            }
                        }
                    }
                return false;
            }

            public string GetLikelySplitter() {
                if (this.likelySplitter == null) {
                    foreach (string d in this.splitterCandidates) {
                        if (this.likelySplitter == null)
                            this.likelySplitter = d;
                        else if (this.likelySplitter.Length < d.Length && this.likelySplitter.Equals(d.Substring(0, this.likelySplitter.Length))) {
                            //do nothing, we already have the best possible likely delimiter
                        }
                        else {
                            StringBuilder newSplitter = new StringBuilder();
                            for (int i = 0; i < Math.Min(d.Length, this.likelySplitter.Length); i++) {
                                if (this.likelySplitter[i] == d[i])
                                    newSplitter.Append(d[i]);
                                else
                                    break;
                            }
                            this.likelySplitter = newSplitter.ToString();
                        }

                    }
                }
                return this.likelySplitter;
            }
        }

        internal class VictimDesktop : IDisposable {
            //similar to RfbPacketHandler.VncDesktop
            //private System.Drawing.Imaging.PixelFormat pixelFormat;
            private (int spriteHeight, List<(int x, int y)> spritePositions) nextTransform;
#if NETFRAMEWORK
            private Bitmap _desktopBitmap = null;//lazy initialization
#endif


            internal (int Width, int Height) Resolution { get; }
            
            internal VictimDesktop(string imageTransformInfo) {
                this.nextTransform = this.GetImageTransform(imageTransformInfo, out int w, out int h);
                this.Resolution = (w, h);
            }

            internal void SetNextTransform(string imageTransformInfo) {
                this.nextTransform = this.GetImageTransform(imageTransformInfo, out _, out _);
            }


            private (int spriteHeight, List<(int x, int y)> spritePositions) GetImageTransform(string imageTransformInfo, out int desktopWidth, out int desktopHeight) {
                desktopWidth = 0;
                desktopHeight = 0;

                string[] ti = imageTransformInfo.Split('-');
                if (ti.Length > 2) {
                    string[] wh = ti[0].Split(',');
                    if (wh.Length == 2) {
                        if (int.TryParse(wh[0], out desktopWidth) && int.TryParse(wh[1], out desktopHeight)) {
                            if (int.TryParse(ti[1], out int spriteHeight)) {
                                if (spriteHeight > 0) {
                                    List<(int x, int y)> spritePositions = new List<(int x, int y)>();
                                    foreach (string xyString in ti.Skip(2)) {
                                        var xy = xyString.Split(',');
                                        int spriteX = int.Parse(xy[0]);
                                        int spriteY = int.Parse(xy[1]);
                                        spritePositions.Add((spriteX, spriteY));
                                    }
                                    return (spriteHeight, spritePositions);
                                }
                            }
                        }
                    }
                }
                return (0, new List<(int x, int y)>());
            }

            

            internal byte[] GetScreenshot(DateTime timestamp) {
#if NETFRAMEWORK
                //this.pixelsAddedOnLastScreenshot = this.PixelsAddedTotal;
                //this.LastScreenshotTimestamp = timestamp;
                if (this.TryGetDesktopBitmap(out Bitmap bitmap)) {
                    using (MemoryStream ms = new MemoryStream()) {
                        bitmap.Save(ms, ImageFormat.Jpeg);
                        byte[] imageBytes = new byte[ms.Length];
                        ms.Position = 0;
                        ms.Read(imageBytes, 0, imageBytes.Length);
                        return imageBytes;
                    }
                }
                else
                    return null;
#else
                return null;
#endif
            }


#if NETFRAMEWORK
            private bool TryGetDesktopBitmap(out Bitmap bitmap) {
                if (this.Resolution.Width < 1 || this.Resolution.Height < 1) {
                    bitmap = null;
                    return false;
                }
                if (this._desktopBitmap == null)
                    this._desktopBitmap = new Bitmap(this.Resolution.Width, this.Resolution.Height);
                bitmap = this._desktopBitmap;
                return true;
            }
#endif


#if NETFRAMEWORK
            internal void UpdateDesktop(Bitmap sourceBitmap) {
                if (this.nextTransform.spriteHeight > 0 && this.nextTransform.spritePositions.Count > 0) {
                    var spritePositions = this.nextTransform.spritePositions;
                    int spriteHeight = this.nextTransform.spriteHeight;
                    int spriteWidth = sourceBitmap.Width;

                    if (spriteHeight > 0 && spriteWidth > 0) {
                        //read sprites and place them on desktop
                        //int _sourceX = 0;
                        int sourceY = 0;
                        foreach ((int spriteX, int spriteY) in spritePositions) {
                            for (int y = 0; y < spriteHeight; y++) {
                                for (int x = 0; x < spriteWidth; x++) {
                                    Color c = sourceBitmap.GetPixel(x, sourceY + y);
                                    this.SetDesktopPixel(spriteX + x, spriteY + y, c);
                                }
                            }
                            sourceY += spriteHeight;
                        }
                    }
                }
            }
#endif

#if NETFRAMEWORK
            private void SetDesktopPixel(int x, int y, Color color) {

                if (this.TryGetDesktopBitmap(out Bitmap bitmap))
                    bitmap.SetPixel(x, y, color);
            }
#endif

            public void Dispose() {
#if NETFRAMEWORK
                try {
                    this._desktopBitmap?.Dispose();
                }
                catch {
                    Logger.Log("Unable to dispose njRAT desktop", Logger.EventLogEntryType.Error);
                }
#endif
            }
        }
    }
#endif
}
