//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {
    class NetBiosNameServicePacketHandler : AbstractPacketHandler, IPacketHandler {


        public override Type[] ParsedTypes { get; } = { typeof(NetBiosNameServicePacket) };

        public NetBiosNameServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //do nothing more
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {

            ITransportLayerPacket transportLayerPacket = null;

            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(NetBiosNameServicePacket))
                    ExtractData((NetBiosNameServicePacket)p, sourceHost, destinationHost, transportLayerPacket);

                else if (p is ITransportLayerPacket tlp)
                    transportLayerPacket = tlp;
            }
        }

        private void ExtractData(NetBiosNameServicePacket netBiosNameServicePacket, NetworkHost sourceHost, NetworkHost destinationHost, ITransportLayerPacket transportLayerPacket) {
            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
            if (netBiosNameServicePacket.QueriedNetBiosName != null) {
                sourceHost.AddQueriedNetBiosName(netBiosNameServicePacket.QueriedNetBiosName);
                parameters.Add("NetBIOS Query", netBiosNameServicePacket.QueriedNetBiosName);
            }

            foreach (NetBiosNameServicePacket.ResourceRecord answer in netBiosNameServicePacket.AnswerResourceRecords) {
                ushort flags = PacketParser.Utils.ByteConverter.ToUInt16(answer.Data.Array, answer.Data.Offset);
                if (answer.Type == 32 && answer.Class == 1) {
                    //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
                    //unique name with IP
                    byte[] ipBytes = new byte[4];//IP4...
                    Array.Copy(answer.Data.Array, answer.Data.Offset + 2, ipBytes, 0, ipBytes.Length);
                    System.Net.IPAddress answeredIpAddress = new System.Net.IPAddress(ipBytes);

                    parameters.Add(answer.Name, answeredIpAddress.ToString());
                    if (MainPacketHandler.NetworkHostList.ContainsIP(answeredIpAddress))
                        MainPacketHandler.NetworkHostList.GetNetworkHost(answeredIpAddress).AddHostName(answer.NameTrimmed, netBiosNameServicePacket.PacketTypeDescription);
                }
                else if (answer.Type == 33) {//NBTSTAT
                    //TODO
                    /*
                    var array = answer.Data.ToArray();
                    */
                }
            }
            foreach (NetBiosNameServicePacket.ResourceRecord additional in netBiosNameServicePacket.AdditionalResourceRecords) {
                ushort flags = PacketParser.Utils.ByteConverter.ToUInt16(additional.Data.Array, additional.Data.Offset);
                if (additional.Type == 32 && additional.Class == 1 && (flags & 0x8000) == 0 && (additional.Name.EndsWith("<00>") || additional.Name.EndsWith("<20>"))) {
                    //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
                    //unique name with IP
                    byte[] ipBytes = new byte[4];//IP4...
                    Array.Copy(additional.Data.Array, additional.Data.Offset + 2, ipBytes, 0, ipBytes.Length);
                    System.Net.IPAddress answeredIpAddress = new System.Net.IPAddress(ipBytes);

                    parameters.Add(additional.Name, answeredIpAddress.ToString());
                    if (MainPacketHandler.NetworkHostList.ContainsIP(answeredIpAddress))
                        MainPacketHandler.NetworkHostList.GetNetworkHost(answeredIpAddress).AddHostName(additional.NameTrimmed, netBiosNameServicePacket.PacketTypeDescription);
                }


            }
            if (parameters.Count > 0 && transportLayerPacket != null) {
                if (netBiosNameServicePacket.Flags.Response)
                    MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Response"));
                else if (netBiosNameServicePacket.Flags.OperationCode == (byte)NetBiosNameServicePacket.HeaderFlags.OperationCodes.registration)
                    MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Registration"));
                else if (netBiosNameServicePacket.Flags.OperationCode == (byte)NetBiosNameServicePacket.HeaderFlags.OperationCodes.query)
                    MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Query"));
                else
                    MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Message"));
            }
        }

        public void Reset() {
            //empty
        }

        #endregion
    }
}
