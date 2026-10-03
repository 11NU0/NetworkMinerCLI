using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketParser {
    public interface ITcpFlowInfo {
        //FiveTuple FiveTuple { get; }
        //DateTime StartTime { get; }
        //DateTime EndTime { get; set; }
        //IPAddress ClientIP { get; }
        //IPAddress ServerIP { get; }
        ushort ClientPort { get; }
        ushort ServerPort { get; }
        long BytesSentClient { get; set; }
        long BytesSentServer { get; set; }

    }
}
