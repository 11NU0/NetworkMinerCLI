using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.Fingerprints {
    abstract class AbstractTtlDistanceCalculator : ITtlDistanceCalculator {


        #region ITtlDistanceCalculator Members

        //some default behaviour that can be overridden by other classes
        public virtual bool TryGetTtlDistance(out byte ttlDistance, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            foreach (PacketParser.Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(PacketParser.Packets.IPv4Packet)) {
                    ttlDistance = GetTtlDistance(((PacketParser.Packets.IPv4Packet)p).TimeToLive);
                    return true;
                }
            }
            ttlDistance = 0;
            return false;
        }

        public virtual byte GetTtlDistance(byte ipTimeToLive) {
            return (byte)(GetOriginalTimeToLive(ipTimeToLive) - ipTimeToLive);
        }

        #endregion

        public virtual byte GetOriginalTimeToLive(byte ipTimeToLive) {
            if (ipTimeToLive > 128)
                return 255;
            else if (ipTimeToLive > 64)
                return 128;
            else if (ipTimeToLive > 32)
                return 64;
            /*else if (ipTimeToLive == 30)//Siemens SIMATIC PLC's
                return (byte)30;*/
            else
                return 32;
        }
    }
}
