using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.Packets;

namespace PacketHandlerFramework.PacketHandlers {

#if !OMIT_MALWARE_PROTOCOLS
    class MeterpreterPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public override Type[] ParsedTypes { get; } = { typeof(MeterpreterPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.Meterpreter;
            }
        }

        private readonly PopularityList<FiveTuple, FileStreamAssembler> fileStreamAssemblers;

        public MeterpreterPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.fileStreamAssemblers = new PopularityList<FiveTuple, FileStreamAssembler>(100);
        }



        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            int bytesHandled = 0;
            foreach (MeterpreterPacket p in packetList.OfType<MeterpreterPacket>()) {
                bytesHandled += p.ParsedBytesCount;

                if (p.PayloadLength > 0) {
                    FileStreamAssembler assembler = new FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.Meterpreter, "meterpreter.payload", string.Empty, "PAYLOAD=reverse_tcp LPORT=" + tcpSession.ServerTcpPort, p.ParentFrame.FrameNumber, p.ParentFrame.Timestamp);
                    assembler.FileContentLength = p.PayloadLength;
                    assembler.FileSegmentRemainingBytes = p.PayloadLength;
                    lock (this.fileStreamAssemblers)
                        this.fileStreamAssemblers.Add(tcpSession.Flow.FiveTuple, assembler);
                    MainPacketHandler.FileStreamAssemblerList.AddOrEnqueue(assembler);
                    //assembler.TryActivate();
                }
                else if (p.HasMZHeader) {
                    if (this.fileStreamAssemblers.ContainsKey(tcpSession.Flow.FiveTuple)) {
                        //var assembler = base.MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer);
                        lock (this.fileStreamAssemblers) {
                            var assembler = this.fileStreamAssemblers[tcpSession.Flow.FiveTuple];
                            if (assembler != null && !assembler.IsActive) {
                                assembler.Filename = "meterpreter.dll";
                                assembler.TryActivate();
                            }
                        }
                    }

                }
            }
            return bytesHandled;
        }

        public void Reset() {
            //throw new NotImplementedException();
        }
    }
#endif
}
