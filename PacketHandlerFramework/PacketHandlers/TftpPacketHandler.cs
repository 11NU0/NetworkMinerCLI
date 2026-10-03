//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.PacketHandlers {

    class TftpPacketHandler : AbstractPacketHandler, IPacketHandler {

        private PopularityList<string, ushort> tftpSessionBlksizeList;

        public override Type[] ParsedTypes { get; } = { typeof(TftpPacket) };
        public override bool CanParse(HashSet<Type> packetTypeSet) {
            return base.CanParse(packetTypeSet) || packetTypeSet.Contains(typeof(UdpPacket));
        }

        public TftpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.tftpSessionBlksizeList = new PopularityList<string, ushort>(100);
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
            UdpPacket udpPacket = null;
            TftpPacket tftpPacket = null;

            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(UdpPacket))
                    udpPacket = (UdpPacket)p;
                else if (p.GetType() == typeof(TftpPacket))
                    tftpPacket = (TftpPacket)p;
            }

            if (udpPacket != null) {
                if (this.TryGetTftpFileStreamAssembler(out FileStreamAssembler assembler, MainPacketHandler.FileStreamAssemblerList, sourceHost, udpPacket.SourcePort, destinationHost, udpPacket.DestinationPort) || tftpPacket != null && TryCreateNewAssembler(out assembler, MainPacketHandler.FileStreamAssemblerList, tftpPacket, sourceHost, udpPacket.SourcePort, destinationHost)) {
                    //we have an assembler!
                    string sessionId = this.GetTftpSessionId(sourceHost, udpPacket.SourcePort, destinationHost, udpPacket.DestinationPort);
                    ushort blksize = 512;//default
                    if (this.tftpSessionBlksizeList.ContainsKey(sessionId))
                        blksize = this.tftpSessionBlksizeList[sessionId];
                    //but we might not have a TFTP packet since it is likely to run over a random port
                    if (tftpPacket == null || tftpPacket.Blksize != blksize) {
                        try {
                            tftpPacket = new TftpPacket(udpPacket.ParentFrame, udpPacket.PacketStartIndex + 8, udpPacket.PacketEndIndex, blksize);//this is not very pretty since the UDP header length is hardcoded to be 8.
                            if (tftpPacket.Blksize != blksize) {
                                if (this.tftpSessionBlksizeList.ContainsKey(sessionId))
                                    this.tftpSessionBlksizeList[sessionId] = tftpPacket.Blksize;
                                else
                                    this.tftpSessionBlksizeList.Add(sessionId, tftpPacket.Blksize);
                            }
                        }
                        catch (Exception e) {
                            if (assembler != null) {
                                SharedUtils.Logger.Log("Error parsing TFTP packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                            }
                        }
                    }
                    //see if we have an tftp pakcet and parse its file data
                    if (tftpPacket != null)
                        this.ExtractFileData(assembler, this.MainPacketHandler.FileStreamAssemblerList, sourceHost, udpPacket.SourcePort, destinationHost, udpPacket.DestinationPort, tftpPacket);
                }

            }//end if udpPacket
        }

        public void Reset() {
            this.tftpSessionBlksizeList.Clear();
        }

        #endregion

        private bool TryGetTftpFileStreamAssembler(out FileStreamAssembler assembler, FileStreamAssemblerList fileStreamAssemblerList, NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort) {
            FiveTuple tmpFiveTuple = new FiveTuple(sourceHost, sourcePort, destinationHost, destinationPort, FiveTuple.TransportProtocol.UDP);
            if (fileStreamAssemblerList.ContainsAssembler(tmpFiveTuple, true)) {
                //already activated read or write request data
                assembler = fileStreamAssemblerList.GetAssembler(tmpFiveTuple, true);
                if (assembler.FileStreamType == FileStreamTypes.TFTP)
                    return true;
                else
                    assembler = null;
            }
            tmpFiveTuple = new FiveTuple(sourceHost, TftpPacket.DefaultUdpPortNumber, destinationHost, destinationPort, FiveTuple.TransportProtocol.UDP);
            if (fileStreamAssemblerList.ContainsAssembler(tmpFiveTuple, true)) {
                //first read request data
                assembler = fileStreamAssemblerList.GetAssembler(tmpFiveTuple, true);
                if (assembler.FileStreamType == FileStreamTypes.TFTP)
                    return true;
                else
                    assembler = null;
            }
            tmpFiveTuple = new FiveTuple(sourceHost, sourcePort, destinationHost, TftpPacket.DefaultUdpPortNumber, FiveTuple.TransportProtocol.UDP);
            if (fileStreamAssemblerList.ContainsAssembler(tmpFiveTuple, true)) {
                //check for write request data
                assembler = fileStreamAssemblerList.GetAssembler(tmpFiveTuple, true);
                if (assembler.FileStreamType == FileStreamTypes.TFTP)
                    return true;
                else
                    assembler = null;
            }
            assembler = null;
            return false;//no assembler found...
        }

        private bool TryCreateNewAssembler(out FileStreamAssembler assembler, FileStreamAssemblerList fileStreamAssemblerList, TftpPacket tftpPacket, NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost) {//destinationPort is not needed
            assembler = null;

            //create new assembler if it is a RRQ or WRQ
            if (tftpPacket.OpCode == TftpPacket.OpCodes.ReadRequest) {
                try {
                    FiveTuple tmpFiveTuple = new FiveTuple(destinationHost, TftpPacket.DefaultUdpPortNumber, sourceHost, sourcePort, FiveTuple.TransportProtocol.UDP);
                    assembler = new FileStreamAssembler(fileStreamAssemblerList, tmpFiveTuple, true, FileStreamTypes.TFTP, tftpPacket.Filename, "", tftpPacket.OpCode.ToString() + " " + tftpPacket.Mode.ToString() + " " + tftpPacket.Filename, tftpPacket.ParentFrame.FrameNumber, tftpPacket.ParentFrame.Timestamp);
                    fileStreamAssemblerList.Add(assembler);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error creating assembler for TFTP file transfer in " + tftpPacket.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                    if (assembler != null) {
                        assembler.Clear();
                        assembler = null;
                    }
                    return false;
                }
                return true;
            }
            else if (tftpPacket.OpCode == TftpPacket.OpCodes.WriteRequest) {
                try {
                    FiveTuple tmpFiveTuple = new FiveTuple(sourceHost, sourcePort, destinationHost, TftpPacket.DefaultUdpPortNumber, FiveTuple.TransportProtocol.UDP);
                    assembler = new FileStreamAssembler(fileStreamAssemblerList, tmpFiveTuple, true, FileStreamTypes.TFTP, tftpPacket.Filename, "", tftpPacket.OpCode.ToString() + " " + tftpPacket.Mode.ToString() + " " + tftpPacket.Filename, tftpPacket.ParentFrame.FrameNumber, tftpPacket.ParentFrame.Timestamp);
                    fileStreamAssemblerList.Add(assembler);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error creating assembler for TFTP file transfer in " + tftpPacket.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                    if (assembler != null) {
                        assembler.Clear();
                        assembler = null;
                    }
                    return false;
                }
                return true;
            }
            else {
                assembler = null;
                return false;
            }
        }

        private string GetTftpSessionId(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort) {
            string sourceString = sourceHost.IPAddress.ToString() + "\t" + sourcePort.ToString();
            string destinationString = destinationHost.IPAddress.ToString() + "\t" + destinationPort.ToString();
            if (sourceString.CompareTo(destinationString) > 0)
                return sourceString + "\t" + destinationString;
            else
                return destinationString + "\t" + sourceString;
        }

        private void ExtractFileData(FileStreamAssembler assembler, FileStreamAssemblerList fileStreamAssemblerList, NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, TftpPacket tftpPacket) {
            if (tftpPacket.OpCode == TftpPacket.OpCodes.Data) {
                if (!assembler.IsActive) {
                    //create a new active assembler if ports need to be changed!
                    if (assembler.SourcePort != sourcePort || assembler.DestinationPort != destinationPort) {
                        fileStreamAssemblerList.Remove(assembler, true);
                        //now change the port number in the AssemblerPool
                        FiveTuple tmpFiveTuple = new FiveTuple(sourceHost, sourcePort, destinationHost, destinationPort, FiveTuple.TransportProtocol.UDP);
                        assembler = new FileStreamAssembler(fileStreamAssemblerList, tmpFiveTuple, true, FileStreamTypes.TFTP, assembler.Filename, assembler.FileLocation, assembler.Details, tftpPacket.ParentFrame.FrameNumber, tftpPacket.ParentFrame.Timestamp);
                        fileStreamAssemblerList.Add(assembler);
                    }
                    //activate the assembler
                    assembler.TryActivate();
                }

                if (assembler.SourceHost == sourceHost && assembler.SourcePort == sourcePort && assembler.DestinationHost == destinationHost && assembler.DestinationPort == destinationPort) {
                    //TODO, check if the tftpPacket.DataBlockNumber has wrapped around to 0 again.
                    assembler.AddData(tftpPacket.DataBlock, tftpPacket.DataBlockNumber);
                    if (tftpPacket.DataBlockIsLast)
                        assembler.FinishAssembling();//we now have the complete file
                }
            }
        }



    }
}
