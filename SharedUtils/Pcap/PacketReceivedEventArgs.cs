//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils.Pcap {
    public class PacketReceivedEventArgs : EventArgs {

        public enum PacketTypes {
            NullLoopback,
            Ethernet2Packet,
            IPv4Packet,
            IPv6Packet,
            IEEE_802_11Packet,
            IEEE_802_11RadiotapPacket,
            CiscoHDLC,
            LinuxCookedCapture,
            LinuxCookedCapture2,
            PrismCaptureHeader,
            TZSP,
        };


        public static bool TryGetPacketType(uint dataLinkType, out PacketTypes basePacketType) {
            if (Enum.IsDefined(typeof(PcapFrame.DataLinkTypeEnum), dataLinkType)) {
                return TryGetPacketType((PcapFrame.DataLinkTypeEnum)dataLinkType, out basePacketType);
            }
            else {
                basePacketType = PacketTypes.NullLoopback;
                return false;
            }
        }

        public static bool TryGetPacketType(PcapFrame.DataLinkTypeEnum dlt, out PacketTypes basePacketType) {
            if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11)
                basePacketType = PacketReceivedEventArgs.PacketTypes.IEEE_802_11Packet;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET)
                basePacketType = PacketReceivedEventArgs.PacketTypes.Ethernet2Packet;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP)
                basePacketType = PacketReceivedEventArgs.PacketTypes.IEEE_802_11RadiotapPacket;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP)
                basePacketType = PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_2)
                basePacketType = PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_3)
                basePacketType = PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_CHDLC)
                basePacketType = PacketReceivedEventArgs.PacketTypes.CiscoHDLC;
            else if (dlt == PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_SLL)
                basePacketType = PacketReceivedEventArgs.PacketTypes.LinuxCookedCapture;
            else {
                basePacketType = PacketTypes.NullLoopback;
                return false;
            }
            return true;
        }

        public DateTime Timestamp { get; }
        public byte[] Data { get; }
        public PacketTypes PacketType { get; }

        public PacketReceivedEventArgs(byte[] data, DateTime timestamp, PacketTypes packetType) {
            this.Data = data;
            this.Timestamp = timestamp.ToUniversalTime();
            this.PacketType = packetType;
        }

    }

    public delegate void PacketReceivedHandler(object sender, PacketReceivedEventArgs e);

}
