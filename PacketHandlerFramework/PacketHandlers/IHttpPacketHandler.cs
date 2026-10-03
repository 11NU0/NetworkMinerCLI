using PacketHandlerFramework;
using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketHandlerFramework.PacketHandlers {
    public interface IHttpPacketHandler {

        /// <summary>
        /// 
        /// </summary>
        /// <param name="httpPacket"></param>
        /// <param name="tcpPacket"></param>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="mainPacketHandler"></param>
        /// <returns>True if the data was successfully parsed. False if the data need to be parsed again with more data</returns>
        bool ExtractHttpData(HttpPacket httpPacket, TcpPacket tcpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, PacketHandler mainPacketHandler);
        bool ExtractHttpData(Http2Packet http2Packet, Dictionary<string, string> headers, TcpPacket tcpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, PacketHandler mainPacketHandler);
        void Reset();//resets all captured data
    }
}
