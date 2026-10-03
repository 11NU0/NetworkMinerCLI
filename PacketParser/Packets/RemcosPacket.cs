using SharedUtils;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.Packets.IrcPacket;

namespace PacketParser.Packets
{

#if !OMIT_MALWARE_PROTOCOLS
    public class RemcosPacket : AbstractPacket, ISessionPacket {
        //https://www.fortinet.com/blog/threat-research/latest-remcos-rat-phishing
        //This implementation only supports the unencrypted variant of Remcos that start with 24 04 ff 00
        //Other variants use TLS encryption.
        //There are also old versions (1.9.9-2.4.7) that encrypt C2 with RC4 (with key reuse). Transmission starts with "[DataStart]", then length, command and data. Data delimiter is "|"
        //https://www.fortinet.com/blog/threat-research/new-remcos-rat-variant-is-spreading-by-exploiting-cve-2017-11882
        //https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/documents-with-irm-password-protection-lead-to-remcos-rat/

        //C2 traffic is sometimes encrypted
        //https://blog.talosintelligence.com/picking-apart-remcos/
        //private static readonly byte[] REMCOS_MAGIC = { 0x24, 0x04, 0xff, 0x00 };
        private static readonly byte[] REMCOS_MAGIC = Utils.ByteConverter.ToByteArray((uint)0x2404FF00, false);


        //public static readonly byte[] DELIMITER = { 0x7C, 0x1E, 0x1E, 0x1F, 0x7C };
        public static readonly byte[] DELIMITER = Utils.ByteConverter.ToByteArray((long)0x7C1E1E1F7C, false).Skip(3).ToArray();

        public enum RemcosCommand : uint {
            
            HeartBeat = 0x01,// HeartBeat packet.
            InstalledPrograms = 0x03, //List all installed software.
            SendNamedFile = 0x05, //not listed by Fortinet
            ProcessManager = 0x06, //Manager running process.
            WindowManager = 0x08, //Open a Task Manager similar interface.
            ExecuteCommand = 0x0D, //Execute a command in the victim’s device, like Notepad.
            CommandLine = 0x0E, //Start a shell(cmd.exe) with command.
            OpenWebpage = 0x0F,// Open a URL with the victim’s default browser.
            ScreenCapture = 0x10, // Control the victim’s device in a remote desktop.
            GeoIP = 0x11,
            Keylogger = 0x13, //Start Keylogger.
            ClearBrowser = 0x18, //Clear browser’s history, logins and cookies
            Webcam = 0x1B, // Control victim’s camera to work
            Microphone = 0x1D, //Turn on the victim’s audio input device, like Microphone.
            //0x1f is unknown, sent before download with a big number as argument
            Close = 0x21, //Kill currently running Remcos.
            Uninstall = 0x22, //Uninstall Remcos from the victim’s device.
            Restart = 0x23, //Restart Remcos.
            Update = 0x24, //Update Remcos.
            MessageBox = 0x26, //Pop up a message to the victim.
            PowerManager = 0x27, //Elevate Remcos’ privileges or Log off, Sleep, Hibernate, Shut down, and Restart.
            LoadDLL = 0x2C, //Execute a Dll module on the victim’s device.
            RegistryEditor = 0x2F, //View, Edit victim’s system registry.
            ClipboardManager = 0x28, //View, Set, and Empty victim’s system clipboard.
            RemoteScripting = 0x2E, //Execute JS, VBS, and Batch on the victim’s device.
            Chat = 0x30, //Pop up a chatting box to chat with the victim.
            Proxy = 0x32, //Set proxy to victim’s device.
            ServiceManager = 0x34, //Manager victim’s system service.
            SendAndExecute = 0x44, //not listed by Fortinet
            //data sent from client
            SystemInfoFull = 0x4b,//not listed by Fortinet
            SystemInfoUpdate = 0x4c,//not listed by Fortinet
            ScreenCaptureData = 0x4d,//not listed by Fortinet

            DownloadRequest = 0x68, //not listed by Fortinet, probably a download request resulting in 0x44
            //0x6a is unknown, seems to exfiltrate info about browser, username and password

            //these values will only be parsed from server because theyu are larger than initial number (4b)
            SetWallpaper = 0x92, //Set the victim’s desktop wallpaper with a picture.
            HostnameAndUser = 0x95,//not listed by Fortinet
            ActiveWindowUpdate = 0x96,//not listed by Fortinet
            FileManager = 0x98, //Manager file system on victim’s device.
            PlaySound = 0xA3, //Play an audio sound to the victim.
            DownloadStart = 0xB2, //Download and execute a file on the victim’s device.
            DownloadComplete = 0xB3, //not listed by Fortinet
            FileSearch = 0x8F, //Search file on victim’s device.

            UNDEFINED = 0xffffffff,
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out RemcosPacket remcos) {
            if (packetEndIndex - packetStartIndex > 10) {
                if(parentFrame.Data.Skip(packetStartIndex).Take(4).SequenceEqual(REMCOS_MAGIC)) {
                    uint length = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 4, true);
                    if(length < 100*1024*1024) {//Must be less than 100 MB
                        try {
                            remcos = new RemcosPacket(parentFrame, packetStartIndex, packetEndIndex);
                            return true;
                        }
                        catch (Exception ex) {
                            Logger.Log("Error parsing Remcos packet in frame " + parentFrame.FrameNumber + ": " + ex.Message, Logger.EventLogEntryType.Error);
                        }
                    }

                }
            }
            remcos = null;
            return false;

        }



        public uint RemcosPayloadLength { get; }
        public uint CommandNumber { get; }
        
        private RemcosPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "Remcos") {
            if (packetEndIndex - packetStartIndex > 10) {
                if (parentFrame.Data.Skip(packetStartIndex).Take(4).SequenceEqual(REMCOS_MAGIC)) {
                    this.RemcosPayloadLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 4, true);
                    if (this.PacketEndIndex >= this.PacketStartIndex + 8 + this.RemcosPayloadLength)
                        this.PacketEndIndex = (int)(this.PacketStartIndex + 7 + this.RemcosPayloadLength);

                    this.CommandNumber = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8, 4, true);
                }
            }
        }

        public bool PacketHeaderIsComplete {
            get {
                return this.PacketLength >= this.RemcosPayloadLength + 8;
            }
        }

        public int 
            ParsedBytesCount {
            get {
                if (this.PacketHeaderIsComplete)
                    return (int)(this.RemcosPayloadLength + 8);
                else
                    return 0;
            }
        }

        public bool TryGetCommand(out RemcosCommand command) {
            if (Enum.IsDefined(typeof(RemcosCommand), this.CommandNumber)) {
                command = (RemcosCommand)this.CommandNumber;
                return true;
            }
            command = RemcosCommand.UNDEFINED;
            return false;
        }

        public IEnumerable<byte[]> GetFields(bool skipEmpty, bool requireCompletePacketHeader = true) {
            if(this.PacketHeaderIsComplete || !requireCompletePacketHeader) {
                int index = this.PacketStartIndex + 12;
                while(index <= this.PacketEndIndex) {
                    int delimiterIndex = Utils.BoyerMoore.IndexOf(this.ParentFrame.Data, DELIMITER, index);
                    if(delimiterIndex == index) {
                        if(!skipEmpty)
                            yield return Array.Empty<byte>();
                    }
                    else if(delimiterIndex < index) {
                        yield return this.ParentFrame.Data.Skip(index).Take((int)(this.PacketStartIndex + 8 + this.RemcosPayloadLength - index)).ToArray();
                        break;
                    }
                    else if(delimiterIndex > index) {
                        if(delimiterIndex > this.PacketEndIndex)//read to end
                            yield return this.ParentFrame.Data.Skip(index).Take(this.PacketEndIndex + 1 - index).ToArray();
                        else
                            yield return this.ParentFrame.Data.Skip(index).Take(delimiterIndex - index).ToArray();
                    }
                    index = delimiterIndex + DELIMITER.Length;
                }
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
        }
    }
#endif
}
