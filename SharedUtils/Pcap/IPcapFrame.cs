using System;

namespace SharedUtils.Pcap {
    public interface IPcapFrame {
        byte[] Data { get; }

        int DataLength { get; }
        PcapFrame.DataLinkTypeEnum DataLinkType { get; }
        object Tag { get; set; }
        DateTime Timestamp { get; }
    }
}