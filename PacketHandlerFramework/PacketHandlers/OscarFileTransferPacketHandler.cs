using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class OscarFileTransferPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public OscarFileTransferPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region ITcpSessionPacketHandler Members

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.OscarFileTransfer; }
        }

        public override Type[] ParsedTypes { get; } = { typeof(OscarFileTransferPacket) };

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
            OscarFileTransferPacket oscarFileTransferPacket = null;
            TcpPacket tcpPacket = null;
            int parsedByteCount = 0;
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(OscarFileTransferPacket))
                    oscarFileTransferPacket = (OscarFileTransferPacket)p;
                else if (p.GetType() == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
            }
            if (oscarFileTransferPacket != null && tcpPacket != null) {
                parsedByteCount = oscarFileTransferPacket.ParsedBytesCount;

                if (oscarFileTransferPacket.Type == PacketParser.Packets.OscarFileTransferPacket.CommandType.SendRequest) {
                    //see if there is an old assembler that needs to be removed
                    if (MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer)) {
                        FileStreamAssembler oldAssembler = MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer);
                        MainPacketHandler.FileStreamAssemblerList.Remove(oldAssembler, true);
                    }
                    FileStreamAssembler assembler = new FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.OscarFileTransfer, oscarFileTransferPacket.FileName, "", (int)oscarFileTransferPacket.TotalFileSize, (int)oscarFileTransferPacket.TotalFileSize, oscarFileTransferPacket.FileName, "", oscarFileTransferPacket.ParentFrame.FrameNumber, oscarFileTransferPacket.ParentFrame.Timestamp, FileStreamAssembler.FileAssemblyRootLocation.source);
                    //assembler.SetRemainingBytesInFile((int)oscarFileTransferPacket.TotalFileSize);
                    MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                }
                else if (oscarFileTransferPacket.Type == PacketParser.Packets.OscarFileTransferPacket.CommandType.ReceiveAccept) {
                    //reverse the order here!
                    if (MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer)) {
                        FileStreamAssembler assembler = MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer);
                        if (assembler != null)
                            assembler.TryActivate();
                    }

                }
                else if (oscarFileTransferPacket.Type == PacketParser.Packets.OscarFileTransferPacket.CommandType.TransferComplete) {
                    //remove assembler from destination to client
                    if (MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer)) {
                        FileStreamAssembler oldAssembler = MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, !transferIsClientToServer);
                        MainPacketHandler.FileStreamAssemblerList.Remove(oldAssembler, true);
                    }
                }


            }
            return parsedByteCount;
        }



        public void Reset() {
            //do nothing
        }

        #endregion
    }
}
