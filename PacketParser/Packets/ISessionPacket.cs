using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public interface ISessionPacket{
        bool PacketHeaderIsComplete { get;}
        int ParsedBytesCount { get;}
    }
}
