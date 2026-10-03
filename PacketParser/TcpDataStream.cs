using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser {
    public class TcpDataStream {

        private readonly SortedList<uint, byte[]> dataList;
        private bool dataListIsTruncated = false;

        private VirtualTcpData virtualTcpData;
        //private readonly NetworkTcpSession session;//needed to query GetConfirmedApplicationLayerProtocol to known how many unparsed frames to buffer in maxPacketFragments
        private readonly ITcpFlowInfo networkFlow;//needed to calculate bytes sent, source and destination port for this direction
        private readonly bool streamIsClientToServer;

        private Func<int> getMaxPacketBufferSize;

        public long TotalByteCount {
            get {
                if (this.streamIsClientToServer)
                    return this.networkFlow.BytesSentClient;
                else
                    return this.networkFlow.BytesSentServer;
            }
            set {
                if (this.streamIsClientToServer)
                    this.networkFlow.BytesSentClient = value;
                else
                    this.networkFlow.BytesSentServer = value;
            }
        }
        public int DataSegmentBufferCount { get { return this.dataList.Count; } }
        public int DataSegmentBufferMaxSize { get; }

        public uint InitialTcpSequenceNumber { get; set; }
        public uint ExpectedTcpSequenceNumber { get; private set; }


        public TcpDataStream(uint initialTcpSequenceNumber, bool streamIsClientToServer, ITcpFlowInfo tcpFlowInfo, Func<int> getPacketBufferSizeFunc = null) {
            this.InitialTcpSequenceNumber = initialTcpSequenceNumber;
            this.ExpectedTcpSequenceNumber = initialTcpSequenceNumber;
            this.dataList = new SortedList<uint, byte[]>();
            this.DataSegmentBufferMaxSize = 1024;//Increased buffer size 2020-08-14 in order to support network traffic from poor quality links with lots of retransmissions

            this.virtualTcpData = null;
            //this.session = session;
            this.getMaxPacketBufferSize = getPacketBufferSizeFunc;//allows the max packet buffer size to change over time, for example if a particular protocol is detected
            this.networkFlow = tcpFlowInfo;
            this.streamIsClientToServer = streamIsClientToServer;
        }

        [Obsolete]
        internal bool HasMissingSegments() {
            return this.TotalByteCount < this.ExpectedTcpSequenceNumber - this.InitialTcpSequenceNumber;
        }

        public void Clear() {
            this.dataList.Clear();
        }

        public void AddTcpData(uint tcpSequenceNumber, byte[] tcpSegmentData, TcpPacket.Flags tcpFlags) {

            if (tcpSegmentData.Length > 0) {//It is VERY important that no 0 length data arrays are added! There is otherwise a big risk for getting stuck in forever-loops etc.

                //ensure that only new data is written to the dataList
                //partially overlapping resent frames are handled here
                if ((int)(this.ExpectedTcpSequenceNumber - tcpSequenceNumber) > 0 && ExpectedTcpSequenceNumber - tcpSequenceNumber < tcpSegmentData.Length) {
                    //remove the stuff that has already been parsed
                    uint bytesToSkip = this.ExpectedTcpSequenceNumber - tcpSequenceNumber;
                    byte[] newSegmentData = new byte[tcpSegmentData.Length - bytesToSkip];
                    Array.Copy(tcpSegmentData, bytesToSkip, newSegmentData, 0, newSegmentData.Length);
                    tcpSegmentData = newSegmentData;
                    tcpSequenceNumber += bytesToSkip;
                }
                //see if we've missed part of the handshake and are now seeing the first data with lower sequence number
                if (this.TotalByteCount == 0 && this.InitialTcpSequenceNumber == this.ExpectedTcpSequenceNumber && (int)(ExpectedTcpSequenceNumber - tcpSequenceNumber) > 0 && (int)(tcpSequenceNumber - ExpectedTcpSequenceNumber) < 12345) {
                    this.InitialTcpSequenceNumber = tcpSequenceNumber;
                    this.ExpectedTcpSequenceNumber = tcpSequenceNumber;
                }
                //A check that the tcpSequenceNumber is a reasonable one, i.e. not smaller than expected and not too large
                if ((int)(this.ExpectedTcpSequenceNumber - tcpSequenceNumber) <= 0 && tcpSequenceNumber - ExpectedTcpSequenceNumber < 1234567) {



                    if (!this.dataList.ContainsKey(tcpSequenceNumber)) {

                        //handle partially overlapping TCP segments that have arrived previously
                        IList<uint> tcpSequenceNumbers = this.dataList.Keys;
                        //we wanna know if we already have an already stored sequence nr. where: new tcpSeqNr < stored tcpSeqNr < new tcpSeqNr + new tcpSeqData.Length


                        for (int i = tcpSequenceNumbers.Count - 1; i >= 0; i--) {
                            if (tcpSequenceNumbers[i] < tcpSequenceNumber)
                                break;
                            else if (tcpSequenceNumbers[i] < tcpSequenceNumber + tcpSegmentData.Length) {
                                //we need to truncate the data since parts of it has already been received
                                uint bytesToKeep = tcpSequenceNumbers[i] - tcpSequenceNumber;
                                byte[] newSegmentData = new byte[bytesToKeep];
                                Array.Copy(tcpSegmentData, 0, newSegmentData, 0, bytesToKeep);
                                tcpSegmentData = newSegmentData;
                            }
                        }
                        //A keepalive contains 0 or 1 bytes of data and has a sequence nr that is next_expected-1, never SYN/FIN/RST
                        //Avoid adding TCP data for TCP-keepalives with "fake" one-byte L7 data (null value)
                        if (tcpSegmentData.Length > 1 || tcpSegmentData[0] != 0 || this.TotalByteCount > 0 || tcpFlags.Push) {
                            this.dataList.Add(tcpSequenceNumber, tcpSegmentData);
                            this.TotalByteCount += tcpSegmentData.Length;//this is how the byte counts in NetworkFlow get updated/increased
                        }
#if DEBUG
                        else if (tcpSegmentData.Length == 1 && tcpSegmentData[0] == 0) {
                            //likely TCP keepalive packet here
                        }
#endif

                        if (this.ExpectedTcpSequenceNumber == tcpSequenceNumber) {
                            this.ExpectedTcpSequenceNumber += (uint)tcpSegmentData.Length;
                            //check if there are other packets that arrived too early that follows this packet
                            while (this.dataList.ContainsKey(this.ExpectedTcpSequenceNumber))
                                this.ExpectedTcpSequenceNumber += (uint)this.dataList[ExpectedTcpSequenceNumber].Length;
                        }

                        while (this.dataList.Count > this.DataSegmentBufferMaxSize) {
                            if (!this.dataListIsTruncated) {
                                SharedUtils.Logger.Log("Too many unparsed queued packets, queue will be truncated in TCP session from " + this.networkFlow.ClientPort + " to " + this.networkFlow.ServerPort, SharedUtils.Logger.EventLogEntryType.Warning);
#if DEBUG
                                if (!debugHasBreaked) {
                                    System.Diagnostics.Debugger.Break();
                                    debugHasBreaked = true;
                                }
#endif
                            }
                            this.dataList.RemoveAt(0);//remove the oldest TCP data
                            this.dataListIsTruncated = true;
                            this.virtualTcpData = null;//this one has to be reset so that the virtualPacket still will work
                        }
                    }
                    else {//let's replace the old TCP packet with the new one
                          //Or maybe just skip it!
                    }
                }
            }
        }

#if DEBUG
        static bool debugHasBreaked = false;
#endif


        /// <summary>
        /// Counts the number of bytes which are ready for reading (that is are in the correct order).
        /// Time complexity = O(1)
        /// </summary>
        /// <returns></returns>
        public int CountBytesToRead() {
            if (dataList.Count < 1)
                return 0;
            else return (int)this.ExpectedTcpSequenceNumber - (int)this.dataList.Keys[0];
        }

        /// <summary>
        /// Counts the number of packets from the start that are in one complete sequence
        /// Time complexity = O(nPacketsInSequence)
        /// </summary>
        /// <returns></returns>
        public int CountPacketsToRead() {
            //this method does not always return dataList.Count since some packets in the dataList might be out of order or missing

            if (dataList.Count == 0)
                return 0;
            else {
                int nPackets = 0;
                uint nextSequenceNumber = dataList.Keys[0];
                foreach (KeyValuePair<uint, byte[]> pair in this.dataList) {
                    if (pair.Key == nextSequenceNumber) {
                        nPackets++;
                        nextSequenceNumber += (uint)pair.Value.Length;
                    }
                    else
                        break;
                }
                return nPackets;
            }
        }

        public VirtualTcpData GetAllAvailableTcpData() {
            this.GetNextVirtualTcpData();
            this.virtualTcpData.AppendAllAvailablePackets();
            return this.virtualTcpData;
        }

        public VirtualTcpData GetNextVirtualTcpData() {
            if (this.virtualTcpData == null) {
                if (this.dataList.Count > 0 && this.CountBytesToRead() > 0 && this.CountPacketsToRead() > 0) {
                    if (this.streamIsClientToServer)
                        this.virtualTcpData = new VirtualTcpData(this, this.networkFlow.ClientPort, this.networkFlow.ServerPort);
                    else
                        this.virtualTcpData = new VirtualTcpData(this, this.networkFlow.ServerPort, this.networkFlow.ClientPort);
                    return virtualTcpData;
                }
                else
                    return null;
            }
            else if (this.virtualTcpData.TryAppendNextPacket())
                return this.virtualTcpData;
            else
                return null;
        }

        /// <summary>
        /// Removes sequenced data from the beginning
        /// </summary>
        /// <param name="bytesToRemove"></param>
        public void RemoveData(int bytesToRemove) {
            if (this.dataList.Count > 0)
                this.RemoveData(this.dataList.Keys[0], bytesToRemove);
        }

        public void RemoveData(VirtualTcpData data) {
            this.RemoveData(data.FirstPacketSequenceNumber, data.ByteCount);
        }

        public void RemoveData(uint firstSequenceNumber, int bytesToRemove) {
            if (this.dataList.Keys[0] != firstSequenceNumber)
                throw new Exception("The data (first data sequence number: " + this.dataList.Keys[0] + ") is not equal to " + firstSequenceNumber);
            else {
                while (this.dataList.Count > 0 && this.dataList.Keys[0] + this.dataList.Values[0].Length <= firstSequenceNumber + bytesToRemove)
                    this.dataList.RemoveAt(0);
                //see if we need to do a partial removal of a tcp packet
                if (this.dataList.Count > 0 && this.dataList.Keys[0] < firstSequenceNumber + bytesToRemove) {
                    uint newFirstSequenceNumber = firstSequenceNumber + (uint)bytesToRemove;
                    byte[] oldData = this.dataList.Values[0];
                    byte[] truncatedData = new byte[this.dataList.Keys[0] + oldData.Length - newFirstSequenceNumber];
                    Array.Copy(oldData, oldData.Length - truncatedData.Length, truncatedData, 0, truncatedData.Length);
                    this.dataList.RemoveAt(0);
                    this.dataList.Add(newFirstSequenceNumber, truncatedData);
                }
                this.virtualTcpData = null;
            }
        }

        /// <summary>
        /// Enumerates all segments (that are in a complete sequence) and removes them from the NetworkTcpSession.TcpDataStream object
        /// </summary>
        /// <returns></returns>
        public IEnumerable<byte[]> GetSegments() {
            if (dataList.Count < 1)
                yield break;
            else {
                for (uint nextSegmentSequenceNumber = dataList.Keys[0]; nextSegmentSequenceNumber < this.ExpectedTcpSequenceNumber; nextSegmentSequenceNumber = dataList.Keys[0]) {
                    byte[] segment;
                    if (dataList.TryGetValue(nextSegmentSequenceNumber, out segment)) {
                        dataList.Remove(dataList.Keys[0]);
                        yield return segment;
                        if (dataList.Count == 0)
                            break;
                    }
                    else {
                        yield break;
                        //break;//this line might not be needed...
                    }
                }
            }
        }

        public class VirtualTcpData {
            private readonly TcpDataStream tcpDataStream;
            private readonly ushort sourcePort;
            private readonly ushort destinationPort;

            public int PacketCount { get; private set; }
            public int ByteCount {
                get {
                    return (int)(this.tcpDataStream.dataList.Keys[this.PacketCount - 1] + (uint)this.tcpDataStream.dataList.Values[this.PacketCount - 1].Length - tcpDataStream.dataList.Keys[0]);
                }
            }
            public uint FirstPacketSequenceNumber { get { return this.tcpDataStream.dataList.Keys[0]; } }


            internal VirtualTcpData(TcpDataStream tcpDataStream, ushort sourcePort, ushort destinationPort) {
                this.tcpDataStream = tcpDataStream;
                this.sourcePort = sourcePort;
                this.destinationPort = destinationPort;
                this.PacketCount = 1;
            }

            internal bool TryAppendNextPacket() {
                int maxPacketFragments = 6;//this one is set low in order to get better performance

                if (this.tcpDataStream.getMaxPacketBufferSize != null) {
                    maxPacketFragments = this.tcpDataStream.getMaxPacketBufferSize();
                }

                if (this.tcpDataStream.CountBytesToRead() > this.ByteCount && this.tcpDataStream.CountPacketsToRead() > this.PacketCount && this.PacketCount < maxPacketFragments) {
                    this.PacketCount++;
                    return true;//everything went just fine
                }
                else
                    return false;//important data might have been ignored (dropped)
            }

            internal void AppendAllAvailablePackets() {
                while (this.tcpDataStream.CountBytesToRead() > this.ByteCount && this.tcpDataStream.CountPacketsToRead() > this.PacketCount) this.PacketCount++;
            }

            private byte[] GetTcpHeader() {
                byte[] tcpHeader = new byte[20];
                PacketParser.Utils.ByteConverter.ToByteArray(sourcePort, tcpHeader, 0);
                PacketParser.Utils.ByteConverter.ToByteArray(destinationPort, tcpHeader, 2);
                PacketParser.Utils.ByteConverter.ToByteArray(tcpDataStream.dataList.Keys[0], tcpHeader, 4);
                //skip ack.nr.
                tcpHeader[12] = 0x50;//5 words (5x4=20 bytes) TCP header
                tcpHeader[13] = 0x18;//flags: ACK+PSH
                tcpHeader[14] = 0xff;//window size 1
                tcpHeader[15] = 0xff;//window size 2
                                     //calculate TCP checksum!
                                     //i'll skip the checksum since I don't have an IP packet (IP source and destination is needed to calculate the checksum

                //skip urgent pointer
                return tcpHeader;
            }

            public byte[] GetBytes(bool prependTcpHeader) {
                List<byte> dataByteList;
                if (prependTcpHeader)
                    dataByteList = new List<byte>(GetTcpHeader());
                else
                    dataByteList = new List<byte>();
                int tcpHeaderBytes = dataByteList.Count;
                int packetsInByteList = 0;
#if DEBUG

                if (this.tcpDataStream.dataList.Count == 0)
                    System.Diagnostics.Debugger.Break();
#endif
                if (this.tcpDataStream != null && this.tcpDataStream.dataList.Count > 0)
                    for (uint sequenceNumber = this.tcpDataStream.dataList.Keys[0]; packetsInByteList < this.PacketCount; sequenceNumber = this.tcpDataStream.dataList.Keys[0] + (uint)dataByteList.Count - (uint)tcpHeaderBytes) {
                        dataByteList.AddRange(this.tcpDataStream.dataList[sequenceNumber]);//this one will generate an Exception if the sequence number isn't in the list; just as I want it to behave
                        packetsInByteList++;
                    }

                return dataByteList.ToArray();
            }

        }
    }
}
