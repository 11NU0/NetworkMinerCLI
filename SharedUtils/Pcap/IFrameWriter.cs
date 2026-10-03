using System;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils.Pcap {
    public interface IFrameWriter : IDisposable {

        bool IsOpen { get; }
        string Filename { get; }
        bool OutputIsPcapNg { get; }

        void WriteFrame(IPcapFrame frame);
        void WriteFrame(IPcapFrame frame, bool flush);
        void WriteFrame(byte[] rawFrameHeaderBytes, byte[] rawFrameDataBytes, bool littleEndian);
        
        void Close();
    }
}
