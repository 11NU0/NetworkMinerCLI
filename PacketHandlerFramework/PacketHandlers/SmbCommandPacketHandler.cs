//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class SmbCommandPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private PopularityList<string, SmbSession> smbSessionPopularityList;

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.NetBiosSessionService; }
        }

        public override Type[] ParsedTypes { get; } = typeof(SmbPacket).GetNestedTypes().Append(typeof(SmbPacket)).ToArray();


        public SmbCommandPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.smbSessionPopularityList = new PopularityList<string, SmbSession>(100);
        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            /*
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }*/
            bool successfulExtraction = false;




            TcpPacket tcpPacket = null;

            List<AbstractPacket> packets = new List<AbstractPacket>(packetList);
            foreach (AbstractPacket p in packets) {
                if (p.GetType() == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
            }
            //there can be multiple SMB2 commands in the same NetBiosSessionServicePacket
            foreach (AbstractPacket p in packets) {
                if (p.GetType().IsSubclassOf(typeof(SmbPacket.AbstractSmbCommand)))
                    ExtractSmbData(tcpSession, transferIsClientToServer, tcpPacket, (SmbPacket.AbstractSmbCommand)p, MainPacketHandler);

            }
            return 0;//NetBiosSessionServicePacketHandler will return the # parsed bytes anyway.
        }

        public void Reset() {
            this.smbSessionPopularityList.Clear();
        }

        #endregion

        private void ExtractSmbData(NetworkTcpSession tcpSession, bool transferIsClientToServer, TcpPacket tcpPacket, SmbPacket.AbstractSmbCommand smbCommandPacket, PacketHandler mainPacketHandler) {
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }
            string smbSessionId;
            if (smbCommandPacket.ParentCifsPacket.FlagsResponse)
                smbSessionId = SmbSession.GetSmbSessionId(sourceHost.IPAddress, tcpPacket.SourcePort, destinationHost.IPAddress, tcpPacket.DestinationPort);
            else
                smbSessionId = SmbSession.GetSmbSessionId(destinationHost.IPAddress, tcpPacket.DestinationPort, sourceHost.IPAddress, tcpPacket.SourcePort);


            if (smbCommandPacket.GetType() == typeof(SmbPacket.NegotiateProtocolRequest)) {
                SmbPacket.NegotiateProtocolRequest request = (SmbPacket.NegotiateProtocolRequest)smbCommandPacket;
                sourceHost.AcceptedSmbDialectsList = request.DialectList;
            }
            else if (smbCommandPacket.GetType() == typeof(SmbPacket.NegotiateProtocolResponse)) {
                SmbPacket.NegotiateProtocolResponse reply = (SmbPacket.NegotiateProtocolResponse)smbCommandPacket;
                if (destinationHost.AcceptedSmbDialectsList != null && destinationHost.AcceptedSmbDialectsList.Count > reply.DialectIndex)
                    sourceHost.PreferredSmbDialect = destinationHost.AcceptedSmbDialectsList[reply.DialectIndex];
            }
            else if (smbCommandPacket.GetType() == typeof(SmbPacket.TreeConnectAndXRequest)) {
                SmbPacket.TreeConnectAndXRequest request = (SmbPacket.TreeConnectAndXRequest)smbCommandPacket;
                if (request.ShareName != null && request.ShareName.Length > 0) {
                    destinationHost.AddNumberedExtraDetail("SMB File Share", request.ShareName);

                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    parameters.Add("SMB Tree Connect AndX Request " + request.ParentCifsPacket.MultiplexId.ToString(), request.ShareName);
                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(smbCommandPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, smbCommandPacket.ParentFrame.Timestamp, "SMB Tree Connect AndX Request"));

                    SmbSession smbSession;
                    if (this.smbSessionPopularityList.ContainsKey(smbSessionId)) smbSession = this.smbSessionPopularityList[smbSessionId];
                    else {
                        smbSession = new SmbSession(destinationHost.IPAddress, tcpPacket.DestinationPort, sourceHost.IPAddress, tcpPacket.SourcePort);
                        this.smbSessionPopularityList.Add(smbSessionId, smbSession);
                    }
                    smbSession.AddTreeConnectAndXRequestPath(smbCommandPacket.ParentCifsPacket.UserId, smbCommandPacket.ParentCifsPacket.MultiplexId, request.ShareName);
                }
            }
            else if (smbCommandPacket.GetType() == typeof(SmbPacket.TreeConnectAndXResponse)) {
                SmbSession smbSession;
                if (this.smbSessionPopularityList.ContainsKey(smbSessionId)) smbSession = this.smbSessionPopularityList[smbSessionId];
                else {
                    smbSession = new SmbSession(sourceHost.IPAddress, tcpPacket.SourcePort, destinationHost.IPAddress, tcpPacket.DestinationPort);
                    this.smbSessionPopularityList.Add(smbSessionId, smbSession);
                }
                smbSession.StoreTreeConnectAndXRequestPathForTree(smbCommandPacket.ParentCifsPacket.UserId, smbCommandPacket.ParentCifsPacket.MultiplexId, smbCommandPacket.ParentCifsPacket.TreeId);
            }
            else if (smbCommandPacket.GetType() == typeof(SmbPacket.SetupAndXRequest)) {
                SmbPacket.SetupAndXRequest request = (SmbPacket.SetupAndXRequest)smbCommandPacket;
                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                if (request.NativeLanManager != null && request.NativeLanManager.Length > 0) {
                    sourceHost.AddNumberedExtraDetail("SMB Native LAN Manager", request.NativeLanManager);
                    parameters.Add("SMB Native LAN Manager", request.NativeLanManager);
                }

                if (request.NativeOs != null && request.NativeOs.Length > 0) {
                    sourceHost.AddNumberedExtraDetail("SMB Native OS", request.NativeOs);
                    parameters.Add("SMB Native OS", request.NativeOs);
                }

                if (request.PrimaryDomain != null && request.PrimaryDomain.Length > 0) {
                    sourceHost.AddDomainName(request.PrimaryDomain);
                    parameters.Add("SMB Primary Domain", request.PrimaryDomain);
                }
                if (request.AccountName != null && request.AccountName.Length > 0) {
                    NetworkCredential nCredential = new NetworkCredential(sourceHost, destinationHost, smbCommandPacket.PacketTypeDescription, request.AccountName, request.ParentFrame.Timestamp);
                    if (request.AccountPassword != null && request.AccountPassword.Length > 0)
                        nCredential.Password = request.AccountPassword;
                    mainPacketHandler.AddCredential(nCredential);
                    parameters.Add("SMB Account Name", request.AccountName);
                }
                if (parameters.Count > 0)
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(request.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, request.ParentFrame.Timestamp, "SMB SetupAndXRequest"));
            }
            else if (smbCommandPacket.GetType() == typeof(SmbPacket.SetupAndXResponse)) {

                SmbPacket.SetupAndXResponse response = (SmbPacket.SetupAndXResponse)smbCommandPacket;
                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                if (response.NativeLanManager != null && response.NativeLanManager.Length > 0) {
                    sourceHost.AddNumberedExtraDetail("SMB Native LAN Manager", response.NativeLanManager);
                    parameters.Add("SMB Native LAN Manager", response.NativeLanManager);
                }

                if (response.NativeOs != null && response.NativeOs.Length > 0) {
                    sourceHost.AddNumberedExtraDetail("SMB Native OS", response.NativeOs);
                    parameters.Add("SMB Native OS", response.NativeOs);
                }
                if (parameters.Count > 0)
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(response.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, response.ParentFrame.Timestamp, "SMB SetupAndXResponse"));
            }
            else if (smbCommandPacket.GetType() == typeof(SmbPacket.NTCreateAndXRequest)) {
                SmbPacket.NTCreateAndXRequest request = (SmbPacket.NTCreateAndXRequest)smbCommandPacket;
                string filename, filePath;

                if (request.Filename.EndsWith("\0"))
                    filename = request.Filename.Remove(request.Filename.Length - 1);
                else
                    filename = request.Filename;

                //print raw filename on parameters tab
                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                parameters.Add("SMB NT Create AndX Request " + request.ParentCifsPacket.MultiplexId.ToString(), filename);
                this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(request.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, request.ParentFrame.Timestamp, "SMB NTCreateAndXRequest"));

                SmbSession smbSession;
                if (this.smbSessionPopularityList.ContainsKey(smbSessionId)) smbSession = this.smbSessionPopularityList[smbSessionId];
                else {
                    smbSession = new SmbSession(destinationHost.IPAddress, tcpPacket.DestinationPort, sourceHost.IPAddress, tcpPacket.SourcePort);
                    this.smbSessionPopularityList.Add(smbSessionId, smbSession);
                }

                string treePath = smbSession.GetPathForTree(smbCommandPacket.ParentCifsPacket.TreeId);
                if (treePath == null)
                    filePath = "";
                else
                    filePath = treePath + System.IO.Path.DirectorySeparatorChar;

                if (System.IO.Path.DirectorySeparatorChar != '\\' && filename.Contains("\\"))
                    filename.Replace('\\', System.IO.Path.DirectorySeparatorChar);

                if (filename.Contains(System.IO.Path.DirectorySeparatorChar.ToString())) {
                    filePath += filename.Substring(0, filename.LastIndexOf(System.IO.Path.DirectorySeparatorChar.ToString()) + 1);
                    filename = filename.Substring(filename.LastIndexOf(System.IO.Path.DirectorySeparatorChar.ToString()) + 1);
                }
                else
                    filePath += System.IO.Path.DirectorySeparatorChar.ToString();

                try {

                    FileStreamAssembler assembler = new FileStreamAssembler(mainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, !transferIsClientToServer, FileStreamTypes.SMB, filename, filePath, filePath + filename, smbCommandPacket.ParentFrame.FrameNumber, smbCommandPacket.ParentFrame.Timestamp);
                    smbSession.AddFileStreamAssembler(assembler, request.ParentCifsPacket.TreeId, request.ParentCifsPacket.MultiplexId, request.ParentCifsPacket.ProcessId);

                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error creating assembler for SMB file transfer: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
#if DEBUG
                    throw;
#endif

                }
            }
            else if (!smbCommandPacket.ParentCifsPacket.FlagsResponse && this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                //Request
                if (smbCommandPacket.GetType() == typeof(SmbPacket.CloseRequest) && smbSessionPopularityList.ContainsKey(smbSessionId)) {

                    SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];
                    SmbPacket.CloseRequest closeRequest = (SmbPacket.CloseRequest)smbCommandPacket;
                    ushort fileId = closeRequest.FileId;
                    if (smbSession.ContainsFileId(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId)) {
                        FileStreamAssembler assemblerToClose = smbSession.GetFileStreamAssembler(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId);
                        if (assemblerToClose != null && assemblerToClose.AssembledByteCount >= assemblerToClose.FileContentLength)
                            assemblerToClose.FinishAssembling();
                        FileSegmentAssembler segmentAssemblerToClose = smbSession.GetFileSegmentAssembler(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId);
                        if (segmentAssemblerToClose != null)
                            segmentAssemblerToClose.AssembleAndClose();

                        smbSession.RemoveFileStreamAssembler(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId, false);

                        if (mainPacketHandler.FileStreamAssemblerList.ContainsAssembler(assemblerToClose))
                            mainPacketHandler.FileStreamAssemblerList.Remove(assemblerToClose, true);
                        else
                            assemblerToClose.Clear();
                    }




                }
                else if (smbCommandPacket.GetType() == typeof(SmbPacket.ReadAndXRequest) && smbSessionPopularityList.ContainsKey(smbSessionId)) {
                    SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];
                    SmbPacket.ReadAndXRequest readRequest = (SmbPacket.ReadAndXRequest)smbCommandPacket;
                    ushort fileId = readRequest.FileId;
                    smbSession.Touch(readRequest.ParentCifsPacket.TreeId, readRequest.ParentCifsPacket.MultiplexId, readRequest.ParentCifsPacket.ProcessId, fileId);
                }
                else if (smbCommandPacket.GetType() == typeof(SmbPacket.WriteAndXRequest)) {
                    SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];
                    SmbPacket.WriteAndXRequest request = (SmbPacket.WriteAndXRequest)smbCommandPacket;
                    FileSegmentAssembler segmentAssembler = smbSession.GetFileSegmentAssembler(request.ParentCifsPacket.TreeId, request.ParentCifsPacket.MultiplexId, request.ParentCifsPacket.ProcessId, request.FileId);
                    if (segmentAssembler == null) {
                        string outputDir = System.IO.Path.GetDirectoryName(mainPacketHandler.OutputDirectory);
                        FileStreamAssembler tmpAssembler = smbSession.GetFileStreamAssembler(request.ParentCifsPacket.TreeId, request.ParentCifsPacket.MultiplexId, request.ParentCifsPacket.ProcessId, request.FileId);
                        if (tmpAssembler != null) {
                            string filePath = tmpAssembler.FileLocation;
                            if (filePath.Length == 0 || filePath.EndsWith("/"))
                                filePath += tmpAssembler.Filename;
                            else
                                filePath += "/" + tmpAssembler.Filename;

                            segmentAssembler = new FileSegmentAssembler(outputDir, tcpSession, transferIsClientToServer, filePath, tcpSession.ToString() + "SMB" + request.FileId.ToString(), mainPacketHandler.FileStreamAssemblerList, null, FileStreamTypes.SMB, "SMB Write " + tmpAssembler.Details, null);
                            smbSession.AddFileSegmentAssembler(segmentAssembler, request.FileId);
                        }
                    }

                    if (segmentAssembler != null) segmentAssembler.AddData(request.WriteOffset, request.GetFileData(), request.ParentFrame);

                }
                else if (smbCommandPacket.GetType() == typeof(SmbPacket.OpenAndXRequest)) {
                    SmbPacket.OpenAndXRequest request = (SmbPacket.OpenAndXRequest)smbCommandPacket;
                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    parameters.Add("SMB Open AndX Request " + request.ParentCifsPacket.MultiplexId.ToString(), request.FileName);
                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(smbCommandPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, smbCommandPacket.ParentFrame.Timestamp, "Open AndX Request"));

                }


            }
            else if (smbCommandPacket.ParentCifsPacket.FlagsResponse && this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                //Response
                SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];

                if (smbCommandPacket.GetType() == typeof(SmbPacket.NTCreateAndXResponse)) {
                    SmbPacket.NTCreateAndXResponse response = (SmbPacket.NTCreateAndXResponse)smbCommandPacket;
                    ushort fileId = response.FileId;
                    int fileLength = (int)response.EndOfFile;//yes, I know I will not be able to store big files now... but an int as length is really enough!

                    //tag the requested file with the fileId
                    FileStreamAssembler assembler = smbSession.GetLastReferencedFileStreamAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);
                    smbSession.RemoveLastReferencedAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);



                    if (assembler != null) {
                        //Add file ID as extended ID in order to differentiate between parallell file transfers on disk cache
                        assembler.ExtendedFileId = "Id" + fileId.ToString("X4"); //2011-04-18

                        smbSession.AddFileStreamAssembler(assembler, response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId, response.FileId);

                        assembler.FileContentLength = fileLength;
                    }


                }
                else if (smbCommandPacket.GetType() == typeof(SmbPacket.ReadAndXResponse)) {
                    SmbPacket.ReadAndXResponse response = (SmbPacket.ReadAndXResponse)smbCommandPacket;
                    //move the assembler to the real FileStreamAssemblerList!
                    FileStreamAssembler assembler = smbSession.GetLastReferencedFileStreamAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);
                    if (assembler == null)
                        SharedUtils.Logger.Log("Unable to find assembler for frame " + smbCommandPacket.ParentFrame.FrameNumber + " : " + smbCommandPacket.ToString(), SharedUtils.Logger.EventLogEntryType.Error);
                    else if (assembler != null) {
                        assembler.FileSegmentRemainingBytes += response.DataLength;//setting this one so that it can receive more bytes
                        if (!assembler.IsActive) {
                            System.Diagnostics.Debug.Assert(assembler.ExtendedFileId != null && assembler.ExtendedFileId != "", "No FileID set for SMB file transfer!");

                            if (!assembler.TryActivate()) {
                                if (!response.ParentCifsPacket.ParentFrame.QuickParse)
                                    response.ParentCifsPacket.ParentFrame.Errors.Add(new Frame.Error(response.ParentCifsPacket.ParentFrame, response.PacketStartIndex, response.PacketEndIndex, "Unable to activate file stream assembler for " + assembler.FileLocation + "/" + assembler.Filename));
                            }
                            else if (assembler.IsActive)
                                assembler.AddData(response.GetFileData(), tcpPacket.SequenceNumber);

                        }
                    }
                }

            }
        }


        internal class SmbSession {
            private System.Net.IPAddress serverIP, clientIP;
            private ushort serverTcpPort, clientTcpPort;

            //treeId|multiplexId
            private SortedList<uint, ushort> lastReferencedFileIdPerTreeMux;

            //processId|multiplexId (like Wireshark do in smb_saved_info_equal_unmatched of packet-smb.c)
            private SortedList<uint, ushort> lastReferencedFileIdPerPidMux;
            //private ushort lastReferencedFileId;

            //private System.Collections.Generic.SortedList<ushort, FileTransfer.FileStreamAssembler> fileIdAssemblerList;
            private PopularityList<ushort, FileStreamAssembler> fileIdAssemblerList;
            private PopularityList<ushort, FileSegmentAssembler> fileIdSegmentAssemblerList;

            private PopularityList<int, string> lastTreeConnectAndXRequestPathPerUserMux;
            private PopularityList<ushort, string> treePathList;

            //internal PopularityList<ushort, FileTransfer.FileStreamAssembler> FileIdAssemblerList { get { return this.fileIdAssemblerList; } }

            internal static string GetSmbSessionId(System.Net.IPAddress serverIP, ushort serverTcpPort, System.Net.IPAddress clientIP, ushort clientTcpPort) {
                return serverIP.ToString() + ":" + serverTcpPort.ToString("X4") + "-" + clientIP.ToString() + ":" + clientTcpPort.ToString("X4");
            }

            internal SmbSession(System.Net.IPAddress serverIP, ushort serverTcpPort, System.Net.IPAddress clientIP, ushort clientTcpPort) {
                this.serverIP = serverIP;
                this.serverTcpPort = serverTcpPort;
                this.clientIP = clientIP;
                this.clientTcpPort = clientTcpPort;

                this.lastReferencedFileIdPerTreeMux = new SortedList<uint, ushort>();
                this.lastReferencedFileIdPerPidMux = new SortedList<uint, ushort>();


                this.fileIdAssemblerList = new PopularityList<ushort, FileStreamAssembler>(100);
                this.fileIdAssemblerList.PopularityLost += FileIdAssemblerList_PopularityLost;
                this.fileIdSegmentAssemblerList = new PopularityList<ushort, FileSegmentAssembler>(100);
                this.fileIdSegmentAssemblerList.PopularityLost += FileIdSegmentAssemblerList_PopularityLost;

                this.lastTreeConnectAndXRequestPathPerUserMux = new PopularityList<int, string>(100);
                this.treePathList = new PopularityList<ushort, string>(100);
            }

            private void FileIdAssemblerList_PopularityLost(ushort key, FileStreamAssembler value) {
                value.Clear();
            }

            private void FileIdSegmentAssemblerList_PopularityLost(ushort key, FileSegmentAssembler value) {
                value.AssembleAndClose();
            }

            internal string GetId() {
                return GetSmbSessionId(this.serverIP, serverTcpPort, clientIP, clientTcpPort);
            }

            internal bool ContainsFileId(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                this.Touch(treeId, muxId, processId, fileId);
                return this.fileIdAssemblerList.ContainsKey(fileId);
            }

            internal void AddFileStreamAssembler(FileStreamAssembler assembler, ushort treeId, ushort muxId, ushort processId) {
                this.AddFileStreamAssembler(assembler, treeId, muxId, processId, 0);
            }
            internal void AddFileStreamAssembler(FileStreamAssembler assembler, ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                this.lastReferencedFileIdPerTreeMux[PacketParser.Utils.ByteConverter.ToUInt32(treeId, muxId)] = fileId;
                this.lastReferencedFileIdPerPidMux[PacketParser.Utils.ByteConverter.ToUInt32(processId, muxId)] = fileId;
                if (this.fileIdAssemblerList.ContainsKey(fileId))
                    this.fileIdAssemblerList.Remove(fileId);
                this.fileIdAssemblerList.Add(fileId, assembler);
            }
            internal void AddFileSegmentAssembler(FileSegmentAssembler assembler, ushort fileId) {
                this.fileIdSegmentAssemblerList.Add(fileId, assembler);
            }


            internal void RemoveLastReferencedAssembler(ushort treeId, ushort muxId, ushort processId) {
                ushort lastReferencedFileId;
                if (lastReferencedFileIdPerPidMux.ContainsKey(PacketParser.Utils.ByteConverter.ToUInt32(processId, muxId)))
                    lastReferencedFileId = lastReferencedFileIdPerPidMux[PacketParser.Utils.ByteConverter.ToUInt32(processId, muxId)];
                else if (lastReferencedFileIdPerTreeMux.ContainsKey(PacketParser.Utils.ByteConverter.ToUInt32(treeId, muxId)))
                    lastReferencedFileId = lastReferencedFileIdPerTreeMux[PacketParser.Utils.ByteConverter.ToUInt32(treeId, muxId)];
                else
                    lastReferencedFileId = 0;

                if (this.fileIdAssemblerList.ContainsKey(lastReferencedFileId))
                    this.RemoveFileStreamAssembler(treeId, muxId, processId, lastReferencedFileId);
            }
            internal void RemoveFileStreamAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                RemoveFileStreamAssembler(treeId, muxId, processId, fileId, false);
            }
            internal void RemoveFileStreamAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId, bool closeAssembler) {
                //this.Touch(treeId, muxId, fileId);
                if (this.fileIdAssemblerList.ContainsKey(fileId)) {
                    FileStreamAssembler assembler = GetFileStreamAssembler(treeId, muxId, processId, fileId);
                    this.fileIdAssemblerList.Remove(fileId);
                    if (closeAssembler)
                        assembler.Clear();
                }
            }
            internal FileStreamAssembler GetLastReferencedFileStreamAssembler(ushort treeId, ushort muxId, ushort processId) {
                if (lastReferencedFileIdPerPidMux.ContainsKey(PacketParser.Utils.ByteConverter.ToUInt32(processId, muxId)))
                    return GetFileStreamAssembler(treeId, muxId, processId, lastReferencedFileIdPerPidMux[PacketParser.Utils.ByteConverter.ToUInt32(processId, muxId)]);
                else if (lastReferencedFileIdPerTreeMux.ContainsKey(PacketParser.Utils.ByteConverter.ToUInt32(treeId, muxId)))
                    return GetFileStreamAssembler(treeId, muxId, processId, lastReferencedFileIdPerTreeMux[PacketParser.Utils.ByteConverter.ToUInt32(treeId, muxId)]);
                else
                    return null;
                //return GetFileStreamAssembler(lastReferencedFileId);
            }
            internal FileStreamAssembler GetFileStreamAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                //this.lastReferencedFileId=fileId;
                this.Touch(treeId, muxId, processId, fileId);

                if (this.fileIdAssemblerList.ContainsKey(fileId))
                    return this.fileIdAssemblerList[fileId];
                else
                    return null;
            }
            internal FileSegmentAssembler GetFileSegmentAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                //this.lastReferencedFileId=fileId;
                this.Touch(treeId, muxId, processId, fileId);

                if (this.fileIdSegmentAssemblerList.ContainsKey(fileId))
                    return this.fileIdSegmentAssemblerList[fileId];
                else
                    return null;
            }

            /// <summary>
            /// Updates the fileId so that it will be referenced as "LastReferencedFile"
            /// </summary>
            /// <param name="fileId"></param>
            internal void Touch(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                //System.Diagnostics.Debug.Assert(this.fileIdAssemblerList.ContainsKey(fileId), "treeID="+treeId.ToString("X4")+" muxID="+muxId.ToString("X4")+" fileID="+fileId.ToString("X4"));
                if (this.fileIdAssemblerList.ContainsKey(fileId)) {
                    this.lastReferencedFileIdPerTreeMux[PacketParser.Utils.ByteConverter.ToUInt32(treeId, muxId)] = fileId;
                    this.lastReferencedFileIdPerPidMux[PacketParser.Utils.ByteConverter.ToUInt32(processId, muxId)] = fileId;
                }
            }

            internal void AddTreeConnectAndXRequestPath(ushort userID, ushort muxID, string path) {
                int key = userID << 16 & muxID;
                if (this.lastTreeConnectAndXRequestPathPerUserMux.ContainsKey(key))
                    this.lastTreeConnectAndXRequestPathPerUserMux[userID << 16 & muxID] = path;
                else
                    this.lastTreeConnectAndXRequestPathPerUserMux.Add(key, path);
            }

            internal void StoreTreeConnectAndXRequestPathForTree(ushort userID, ushort muxID, ushort treeId) {
                int key = userID << 16 & muxID;
                if (this.lastTreeConnectAndXRequestPathPerUserMux.ContainsKey(key)) {
                    string path = this.lastTreeConnectAndXRequestPathPerUserMux[key];
                    if (this.treePathList.ContainsKey(treeId))
                        this.treePathList.Remove(treeId);
                    this.treePathList.Add(treeId, path);
                }
            }

            internal string GetPathForTree(ushort treeId) {
                if (this.treePathList.ContainsKey(treeId))
                    return this.treePathList[treeId];
                else
                    return null;
            }
        }
    }
}
