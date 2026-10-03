using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
#if NETFRAMEWORK
using System.Runtime.InteropServices;
#endif

using SharedUtils.Pcap;
using PacketParser;

namespace PacketHandlerFramework {

#if NETFRAMEWORK
    [Guid("BBB92AA6-718C-4123-8187-F407D18600C0")]
#endif
    public interface ISimpleParser {

#if NETFRAMEWORK
        [DispId(1)]
#endif
        void Parse(string pcapFileName);
    }

#if NETFRAMEWORK
    [ComVisible(true)]
    [Guid("4544709D-BB0E-4f24-96F4-7A762996ACFA"), ClassInterface(ClassInterfaceType.AutoDual)]
#endif
    public class SimpleParser : ISimpleParser {



        public void Parse(string pcapFileName) {
            using (PcapFileReader pcapReader = new PcapFileReader(pcapFileName)) {
                ThreadStart threadStart = new ThreadStart(pcapReader.ThreadStart);
                Thread pcapReaderThread = new Thread(threadStart);
                string executablePath = System.IO.Path.GetFullPath(System.Reflection.Assembly.GetEntryAssembly().Location);
                PacketHandler packetHandler = new PacketHandler(executablePath, Environment.CurrentDirectory, null, true, new Func<DateTime, string>((dateTime) => { return dateTime.ToUniversalTime().ToString("u"); }), false, false, 1, null);
                packetHandler.StartBackgroundThreads();

                int readFrames = 0;
                foreach (PcapFrame packet in pcapReader.PacketEnumerator()) {
                    Frame frame = packetHandler.GetFrame(packet.Timestamp, packet.Data, packet.DataLinkType);
                    packetHandler.AddFrameToFrameParsingQueue(frame);
                    readFrames++;
                }
            }
        }
    }
}
