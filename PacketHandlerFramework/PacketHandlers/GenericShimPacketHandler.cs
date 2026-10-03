using System;
using System.Collections.Generic;
using System.Text;
using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;

namespace PacketHandlerFramework.PacketHandlers {

    /// <summary>
    /// This class was initially created to handle the OpenFlowPacket since I primarily just wanna
    /// parse the encapsulated protocols rather than the OpenFlow packet itself.
    /// 
    /// This is pretty mych the same thing as UnusedTcpSessionProtocolsHandler, the difference is that this one returns shimPacket.ParsedBytesCount rather than the Frame length
    /// </summary>
    /// <typeparam name="T"></typeparam>
    class GenericShimPacketHandler<T> : AbstractPacketHandler, ITcpSessionPacketHandler where T : AbstractPacket, ISessionPacket {


        public override Type[] ParsedTypes { get; } = { typeof(T) };
        private ApplicationLayerProtocol handledProtocol;

        public GenericShimPacketHandler(PacketHandler mainPacketHandler, ApplicationLayerProtocol handledProtocol) : base(mainPacketHandler) {
            this.handledProtocol = handledProtocol;
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return this.handledProtocol;
            }
        }

        // public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {

            T shimPacket = null;
            Frame originalFrame = null;
            SortedList<int, AbstractPacket> sortedPacketList = new SortedList<int, AbstractPacket>();
            foreach (AbstractPacket p in packetList) {
                if (shimPacket != null)
                    sortedPacketList.Add(p.PacketStartIndex, p);

                if (originalFrame == null)
                    originalFrame = p.ParentFrame;
                if (p.GetType() == typeof(T))
                    shimPacket = (T)p;
            }
            if (shimPacket != null && originalFrame != null) {
                if (sortedPacketList.Count > 0) {
                    Frame innerFrame = originalFrame.CloneWithPacketList(sortedPacketList);
                    MainPacketHandler.ParseFrame(innerFrame);
                }
                return shimPacket.ParsedBytesCount;
            }
            else
                return 0;
        }

        public void Reset() {
            //do nothing, we're holding no state here
        }
    }
}
