using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.Fingerprints {
    interface ITtlDistanceCalculator {
        bool TryGetTtlDistance(out byte ttlDistance, IEnumerable<PacketParser.Packets.AbstractPacket> packetList);
        byte GetTtlDistance(byte ipTimeToLive);
    }
}
