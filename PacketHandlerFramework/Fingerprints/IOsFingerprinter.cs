using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.Fingerprints {

    public interface IOsFingerprinterInfo : IComparable, IComparable<IOsFingerprinterInfo> {
        double Confidence { get; }

        string Name { get; }
    }
    public interface IOsFingerprinter : IOsFingerprinterInfo {

        bool TryGetOperatingSystems(out IList<DeviceFingerprint> osList, IEnumerable<PacketParser.Packets.AbstractPacket> packetList);

        //double Confidence { get; }

        //string Name { get; }
    }
}
