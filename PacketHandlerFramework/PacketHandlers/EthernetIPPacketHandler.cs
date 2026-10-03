using PacketParser;
using PacketParser.Packets;
using SharedUtils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using static PacketParser.Packets.CipPacket;
using static PacketParser.Packets.EtherNetIPPacket;
using static PacketParser.Utils.HuffmanDecoder;
using static System.Net.WebRequestMethods;

namespace PacketHandlerFramework.PacketHandlers {
    internal class EthernetIPPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        internal abstract class AbstractPccc {
            //https://www.rockwellautomation.com/content/dam/rockwell-automation/sites/downloads/pdf/CIPandPCCC_v1_1.pdf
            //http://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1770-rm516_-en-p.pdf
            //https://scholarworks.uno.edu/cgi/viewcontent.cgi?article=3500&context=td
            //https://dfrws.org/wp-content/uploads/2019/06/paper_scada_network_forensics_of_the_pccc_protocol.pdf

            internal readonly static HashSet<char> BulletinChars;

            static AbstractPccc() {
                BulletinChars = new HashSet<char>();
                for (char c = '0'; c <= '9'; c++)
                    BulletinChars.Add(c);
                for (char c = 'a'; c <= 'z'; c++)
                    BulletinChars.Add(c);
                for (char c = 'A'; c <= 'Z'; c++)
                    BulletinChars.Add(c);
                BulletinChars.Add('-');
            }

            //TODO: Add more PCCC commands like:
            //Unprotected Read 
            //Protected Write 
            //Unprotected Write 
            //Protected Bit Write
            //Unprotected Bit Write
            //Read Modify Write
            //Read Modify Write N 
            //Typed Read 
            //Typed Write 
            //Word Range Read
            //Word Range Write
            //Bit Write
            internal readonly static Dictionary<(byte command, byte? function), string> FunctionNames = new Dictionary<(byte command, byte? function), string> {
                //https://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1770-rm516_-en-p.pdf
                //page 89
                {(0x0f, 0x8f), "Apply port configuration" },
                {(0x0f, 0x02), "Bit write" },
                {(0x0f, 0x3a), "Change mode" },
                {(0x0f, 0x80), "Change mode" },
                {(0x0f, 0x82), "Close file" },
                {(0x06, 0x03), "Diagnostic status" },
                {(0x0f, 0x41), "Disable forces" },
                {(0x07, 0x00), "Disable outputs" },
                {(0x0f, 0x50), "Download all requests" },
                {(0x0f, 0x52), "Download completed" },
                {(0x0f, 0x05), "Download request" },
                {(0x06, 0x00), "Echo" },
                {(0x07, 0x01), "Enable outputs" },
                {(0x07, 0x03), "Enable PLC scanning" },
                {(0x07, 0x04), "Enter download mode" },
                {(0x07, 0x06), "Enter upload mode" },
                {(0x07, 0x05), "Exit download/upload mode" },
                {(0x0f, 0x04), "File read" },
                {(0x0f, 0x03), "File write" },
                {(0x0f, 0x11), "Get edit resource" },
                {(0x0f, 0x57), "Initialize memory" },
                {(0x0f, 0x5e), "Modify PLC-2 compatibility file" },
                {(0x0f, 0x81), "Open file" },
                {(0x04, null), "Physical read" },//This command has no FNC byte.
                {(0x0f, 0x09), "Physical read" },
                {(0x0f, 0x08), "Physical write" },
                {(0x02, null), "Protected bit write" },
                {(0x0f, 0xa7), "Protected typed file read" },
                //https://dfrws.org/wp-content/uploads/2019/06/paper_scada_network_forensics_of_the_pccc_protocol.pdf
                //https://scholarworks.uno.edu/cgi/viewcontent.cgi?article=3500&context=td
                //{(0x0f, 0x80), "Change Mode" },
                {(0x0f, 0xaa), "Protected typed logical write with three address fields" },
                {(0x0f, 0xa2), "Protected typed logical read with three address fields" },
                //{(0x06, 0x03), "Diagnostic Status" },
                //{(0x0f, 0x52), "Download Completed" },
                //{(0x06, 0x00), "Echo" },
                //{(0x0f, 0x11), "Get edit resource" },
                {(0x0f, 0x12), "Return edit resource" },
            };

            internal abstract bool IsRequest { get; }
            /*
            private readonly byte[] data;
            private readonly int startIndex;
            */
            internal readonly int Length;
            
            //requestor ID
            internal readonly byte RequestorIDLength;
            internal readonly ushort RequestorCipVendorID;
            internal readonly uint RequestorCipSerialNumber;
            //request/response
            private protected readonly byte commandOrResponseCode;
            internal readonly byte Status;//0x00 in commands, 0x00 i success in replies
            internal readonly ushort TransactionID;
            //general
            internal abstract int DataOffset { get; }

            internal AbstractPccc(byte[] data, int startIndex, int length) {
                /*
                this.data = data;
                this.startIndex = startIndex;
                */
                this.Length = length;
                
                this.RequestorIDLength = data[startIndex];
                this.RequestorCipVendorID = PacketParser.Utils.ByteConverter.ToUInt16(data, startIndex + 1, true);
                this.RequestorCipSerialNumber = PacketParser.Utils.ByteConverter.ToUInt32(data, startIndex + 3, 4, true);

                this.commandOrResponseCode = data[startIndex + this.RequestorIDLength];
                this.Status = data[startIndex + this.RequestorIDLength + 1];
                this.TransactionID = PacketParser.Utils.ByteConverter.ToUInt16(data, startIndex + this.RequestorIDLength + 2, true);


            }

        }

        internal class PcccRequest : AbstractPccc {
            internal override bool IsRequest => true;

            internal byte Command => this.commandOrResponseCode;

            internal override int DataOffset => this.RequestorIDLength + 5;

            internal byte? FunctionCode;//not included in some PLC2 commands

            public PcccRequest(byte[] data, int startIndex, int length) : base(data, startIndex, length) {
                if(length > this.RequestorIDLength + 4)
                    this.FunctionCode = data[startIndex + this.RequestorIDLength + 4];
                else
                    this.FunctionCode = null;
            }
        }

        internal class PcccResponse : AbstractPccc {

            

            internal byte ResponseCode => this.commandOrResponseCode;
            internal override bool IsRequest => false;
            internal override int DataOffset => this.RequestorIDLength + 4;


            public PcccResponse(byte[] data, int startIndex, int length) : base(data, startIndex, length) {
            }
        }

        private const string EXTRA_DETAIL_SERIAL_NUMBER_LABEL = "CIP Serial number";

        private readonly PopularityList<(uint handle, ulong context, byte service), CipPacket> recentCipRequests;

        private readonly PopularityList<(uint handle, ulong context, ushort transactionID), PcccRequest> recentPcccRequests;

        public override Type[] ParsedTypes { get; } = { typeof(EtherNetIPPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.EtherNetIP;
            }
        }

        public EthernetIPPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.recentCipRequests = new PopularityList<(uint handle, ulong context, byte service), CipPacket>(100);
            this.recentPcccRequests = new PopularityList<(uint handle, ulong context, ushort transactionID), PcccRequest>(100);
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            int parsedBytes = 0;
            foreach (AbstractPacket p in packetList) {
                if (p is EtherNetIPPacket etherNetIPPacket)
                    parsedBytes = this.ExtractData(tcpSession, transferIsClientToServer, etherNetIPPacket);
            }

            return parsedBytes;
        }

        private (uint handle, ulong context, byte service) GetKey(EtherNetIPPacket etherNetIPPacket, CipPacket cipPacket) {
            return (etherNetIPPacket.SessionHandle, etherNetIPPacket.SenderContext, cipPacket.ServiceRaw);
        }

        private bool TryGetRequest(EtherNetIPPacket etherNetIPPacket, CipPacket cipResponse, out CipPacket cipRequest) {
            var key = GetKey(etherNetIPPacket, cipResponse);
            lock (this.recentCipRequests) {
                if (this.recentCipRequests.ContainsKey(key)) {
                    cipRequest = this.recentCipRequests[key];
                    return true;
                }
            }
            cipRequest = null;
            return false;
        }

        private int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, EtherNetIPPacket etherNetIPPacket) {

            NetworkHost sourceHost;
            if (transferIsClientToServer)
                sourceHost = tcpSession.ClientHost;
            else
                sourceHost = tcpSession.ServerHost;

            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();

            foreach (AbstractPacket p in etherNetIPPacket.GetSubPackets(false)) {
                if (p is CipPacket cipPacket) {
                    //log cip packet details
                    {
                        string cipDetails;
                        if (cipPacket.TryGetService(out var service))
                            cipDetails = service.ToString();
                        else
                            cipDetails = "0x" + cipPacket.ServiceRaw.ToString("X2");
                        if (cipPacket.IsRequest)
                            cipDetails += " Request";
                        else
                            cipDetails += " Response";
                        parameters.Add("CIP Service", cipDetails);

                        if (cipPacket.IsRequest) {
                            List<string> list = new List<string>();
                            if (cipPacket.LogicalPathSegments != null) {
                                foreach (var ps in cipPacket.LogicalPathSegments)
                                    list.Add(ps.ToString());
                                
                            }
                            if(cipPacket.DataPathSegments != null) {
                                foreach (string dp in cipPacket.DataPathSegments)
                                    list.Add(dp);
                            }
                            if (list.Count > 0) {
                                parameters.Add("CIP Path", string.Join(".", list));
                            }
                        }
                    }

                    if (cipPacket.IsRequest) {
                        var key = this.GetKey(etherNetIPPacket, cipPacket);
                        lock(this.recentCipRequests)
                            this.recentCipRequests[key] = cipPacket;

                        
                        if (cipPacket.PathMatches(CipClass.PCCC, 0x01)) {
                            if (cipPacket.ContentIndex < cipPacket.PacketEndIndex) {
                                PcccRequest pcccRequest = new PcccRequest(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, cipPacket.PacketLength - cipPacket.ContentOffset);
                                lock(this.recentPcccRequests) {
                                    var pcccKey = (etherNetIPPacket.SessionHandle, etherNetIPPacket.SenderContext, pcccRequest.TransactionID);
                                    this.recentPcccRequests[pcccKey] = pcccRequest;
                                }
                                if (PcccRequest.FunctionNames.TryGetValue((pcccRequest.Command, pcccRequest.FunctionCode), out string funcName)) {
                                    parameters.Add("PCCC Function", funcName);
                                }

                                parameters.Add(EXTRA_DETAIL_SERIAL_NUMBER_LABEL, "0x" + pcccRequest.RequestorCipSerialNumber.ToString("X8"));
                                this.AddSerialNumber(sourceHost, pcccRequest.RequestorCipSerialNumber);
                                if (CipPacket.TryGetVendorString(pcccRequest.RequestorCipVendorID, out string vendorString)) {
                                    parameters.Add("PCCC Vendor", vendorString);
                                    sourceHost.AddNumberedExtraDetail("PCCC Vendor", vendorString);
                                }
                            }

                        }

                        if (cipPacket.DataPathSegments?.Length > 0) {
                            //Check for rockwell custom services: cip.sc in { 0x4c, 0x52, 0x4d, 0x53, 0x4e, 0x55 }
                            //https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

                            

                            if (Enum.IsDefined(typeof(RockwellService), cipPacket.ServiceRaw)) {
                                RockwellService rockwellService = (RockwellService)cipPacket.ServiceRaw;

                                if (rockwellService == RockwellService.Read_Tag) {//0x4C
                                    ushort numberOfElements = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, true);
                                }
                                else if(rockwellService == RockwellService.Write_Tag) {//0x4D

                                    
                                    ushort tagValueType = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, true);
                                    ushort numberOfElementsToWrite = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, cipPacket.ContentIndex + 2, true);

                                    int index = cipPacket.ContentIndex + 4;
                                    for (int i = 0; i < numberOfElementsToWrite; i++) {
                                        if(this.TryGetRockwellTagValue(cipPacket, tagValueType, ref index, out string valueString)) {
                                            parameters.Add("Rockwell Write Tag " + cipPacket.DataPathSegments[0], valueString);
                                        }
                                    }
                                }
                                else if(rockwellService == RockwellService.Read_Modify_Write) {//0x4e
                                    ushort sizeOfMask = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, true);
                                    //Only 1,2,4,8,12 accepted 
                                    byte[] orMask = new byte[sizeOfMask];
                                    byte[] andMask = new byte[sizeOfMask];
                                    Array.Copy(cipPacket.ParentFrame.Data, cipPacket.ContentIndex + 2, orMask, 0, sizeOfMask);
                                    Array.Copy(cipPacket.ParentFrame.Data, cipPacket.ContentIndex + 2 + sizeOfMask, andMask, 0, sizeOfMask);
                                    string orString = PacketParser.Utils.ByteConverter.ToHexString(orMask, sizeOfMask);
                                    string andString = PacketParser.Utils.ByteConverter.ToHexString(andMask, sizeOfMask);
                                    parameters.Add("Rockwell Read Modify Write Tag " + cipPacket.DataPathSegments[0], "OR=" + orString + ", AND=" + andString);
                                }
                            }
                        }
                    }
                    else if (this.TryGetRequest(etherNetIPPacket, cipPacket, out CipPacket cipRequest)) {
                        var requestPaths = cipRequest.LogicalPathSegments;


                        if (cipRequest.TryGetService(out ConnectionManagerService requestService)) {

                            if (requestService == ConnectionManagerService.Get_Attribute_All) {
                                //3-7.4.1 Get_Attributes_All Response
                                /**
                                 * The Get_Attributes_All response for the class attributes shall concatenate attributes 1, 2, 3, 8 
                                 * and 9 in that order.  If class attribute 1 (Revision) is not supported, then a default value of one 
                                 * (1) shall be returned.  The Get_Attribute_All response for the instance attributes shall 
                                 * concatenate attributes 1, 2, 3,4 and 7 in that order.
                                 **/

                                /**
                                 *CLASS_ATTRIBUTE_1_NAME  "Revision"
                                 *CLASS_ATTRIBUTE_2_NAME  "Max Instance"
                                 *CLASS_ATTRIBUTE_3_NAME  "Number of Instances"
                                 *CLASS_ATTRIBUTE_4_NAME  "Optional Attribute List"
                                 *CLASS_ATTRIBUTE_5_NAME  "Optional Service List"
                                 *CLASS_ATTRIBUTE_6_NAME  "Maximum ID Number Class Attributes"
                                 *CLASS_ATTRIBUTE_7_NAME  "Maximum ID Number Instance Attributes"
*/

                                //check if class is identity and instance = 0x01
                                if (cipRequest.PathMatches(CipClass.Identity, 0x01)) {
                                    int index = cipPacket.ContentIndex;
                                    for (uint attributeID = 1; attributeID < 8; attributeID++) {
                                        if (index > cipPacket.PacketEndIndex)
                                            break;
                                        index += this.ExtractCipIdentityInstanceAttribute(cipPacket, attributeID, index, parameters, sourceHost);
                                    }

                                }
                                else if (cipRequest.PathMatches(CipClass.TCP_IP_Interface, 0x01)) {
                                    
                                    int index = cipPacket.ContentIndex;
                                    for (uint attributeID = 1; attributeID < 7; attributeID++) {
                                        if (index > cipPacket.PacketEndIndex)
                                            break;
                                        index += this.ExtractCipTcpIpInterfaceInstanceAttribute(cipPacket, attributeID, index, parameters, sourceHost);
                                    }
                                }
                            }
                            else if(requestService == ConnectionManagerService.Get_Attribute_Single) {
                                var attributeIDs = cipRequest.GetPathAttributeIDs();
                                if(attributeIDs.Length > 0) {
                                    uint attributeID = attributeIDs[0];
                                    if (cipRequest.PathMatches(CipClass.Identity, 0x01))
                                        this.ExtractCipIdentityInstanceAttribute(cipPacket, attributeID, cipPacket.ContentIndex, parameters, sourceHost);
                                    else if (cipRequest.PathMatches(CipClass.TCP_IP_Interface, 0x01))
                                        this.ExtractCipTcpIpInterfaceInstanceAttribute(cipPacket, attributeID, cipPacket.ContentIndex, parameters, sourceHost);
                                }
                            }
                            else if(requestService == ConnectionManagerService.Get_Attribute_List) {
                                //it doesn't really matter what was requested here, we only care about the response, which contains a list ot attributes
                                ushort numberOfAttributes = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, true);
                                //TODO: 5-46.30.1 Get Axis Attribute List
                            }
                        }


                        if (cipRequest.PathMatches(CipClass.PCCC, 0x01)) {
                            if (cipPacket.ContentIndex < cipPacket.PacketEndIndex) {
                                PcccResponse response = new PcccResponse(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, cipPacket.PacketLength - cipPacket.ContentOffset);
                                PcccRequest request = null;
                                lock (this.recentPcccRequests) {
                                    var key = (etherNetIPPacket.SessionHandle, etherNetIPPacket.SenderContext, response.TransactionID);
                                    if (this.recentPcccRequests.ContainsKey(key))
                                        request = this.recentPcccRequests[key];
                                    else
                                        request = new PcccRequest(cipRequest.ParentFrame.Data, cipRequest.ContentIndex, cipRequest.PacketLength - cipRequest.ContentOffset);
                                }
                                
                                if (request.TransactionID == response.TransactionID) {
                                    parameters.Add(EXTRA_DETAIL_SERIAL_NUMBER_LABEL, "0x" + response.RequestorCipSerialNumber.ToString("X8"));
                                    if (CipPacket.TryGetVendorString(response.RequestorCipVendorID, out string vendorString)) {
                                        parameters.Add("PCCC Vendor", vendorString);
                                        //sourceHost.AddNumberedExtraDetail("PCCC Vendor", vendorString);
                                    }
                                    if (request.Command == 0x06 && request.FunctionCode == 0x03 && response.Status == 0x00) {
                                        //Diagnostic Status Information
                                        //The structure of the payload varies between make/model, but many have a bulletin name

                                        int lowestBulletinOffset = response.DataOffset + 4;
                                        foreach (string name in PacketParser.Utils.StringManglerUtil.GetAsciiStrings(cipPacket.ParentFrame.Data, cipPacket.ContentIndex + lowestBulletinOffset, response.Length - lowestBulletinOffset, PcccResponse.BulletinChars, 3)) {
                                            parameters.Add("PCCC Bulletin Name", name.Trim());
                                            sourceHost.AddNumberedExtraDetail("PCCC Bulletin Name", name.Trim());
                                        }
                                    }
                                }
                                else {
                                    Logger.Log("PCCC Transaction ID in frame " + cipPacket.ParentFrame.FrameNumber + " does not match that in " + cipRequest.ParentFrame.FrameNumber, Logger.EventLogEntryType.Error);
                                }
                            }

                        }

                        if (cipRequest.DataPathSegments?.Length > 0) {
                            //Check for rockwell custom services: cip.sc in { 0x4c, 0x52, 0x4d, 0x53, 0x4e, 0x55 }
                            //https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

                            /**
                             * 0x0nc1 = Bool 1 byte, with n indicating bit position (0-7)
                             * 0x00c2 = SINT 1 byte
                             * 0x00c3 = INT 2 bytes
                             * 0x00c4 = DINT 4 bytes
                             * 0x00ca = REAL 4 bytes
                             * 0x00d3 = DWORD 4 bytes
                             * 0x00c5 = LINT 8 bytes
                             **/

                            if (Enum.IsDefined(typeof(RockwellService), cipPacket.ServiceRaw)) {
                                RockwellService rockwellService = (RockwellService)cipPacket.ServiceRaw;

                                if (rockwellService == RockwellService.Read_Tag) {//0x4C
                                    ushort tagType = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, cipPacket.ContentIndex, true);
                                    int index = cipPacket.ContentIndex + 2;
                                    if(this.TryGetRockwellTagValue(cipPacket, tagType, ref index, out string valueString)) {
                                        parameters.Add("Rockwell Read Tag " + cipRequest.DataPathSegments[0], valueString);
                                    }
                                }
                                
                            }
                        }
                    }
                }
            }

            if (parameters.Count > 0) {
                string details = "EtherNet/IP [0x" + etherNetIPPacket.Command.ToString("X4") + "]";
                if (Enum.IsDefined(typeof(EncapsulationCommand), etherNetIPPacket.Command))
                    details += " " + ((EncapsulationCommand)etherNetIPPacket.Command).ToString();
                this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(etherNetIPPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, etherNetIPPacket.ParentFrame.Timestamp, details));
            }

            return etherNetIPPacket.ParsedBytesCount;
        }

        private void AddSerialNumber(NetworkHost networkHost, uint serial) {
            networkHost.AddNumberedExtraDetail(EXTRA_DETAIL_SERIAL_NUMBER_LABEL, serial.ToString() + " / 0x" + serial.ToString("X8"));
        }

        private bool TryGetRockwellTagValue(CipPacket cipPacket, ushort tagValueType, ref int index, out string valueString) {

            /**
            * 0x0nc1 = Bool 1 byte, with n indicating bit position (0-7)
            * 0x00c2 = SINT 1 byte
            * 0x00c3 = INT 2 bytes
            * 0x00c4 = DINT 4 bytes
            * 0x00ca = REAL 4 bytes
            * 0x00d3 = DWORD 4 bytes
            * 0x00c5 = LINT 8 bytes
            **/

            if ((tagValueType & 0xff) == 0xc1) {//bool
                byte bitPosition = (byte)((tagValueType & 0x0700) >> 8);
                int value = cipPacket.ParentFrame.Data[index] >> (7 - bitPosition);
                index++;
                valueString = value.ToString();
                return true;
            }
            else if(tagValueType == 0x00c2) {//byte
                valueString = "0x" + cipPacket.ParentFrame.Data[index].ToString("X2");
                index++;
                return true;
            }
            else if (tagValueType == 0x00c3) {//ushort
                ushort v = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                valueString = v.ToString();
                index += 2;
                return true;
            }
            else if(tagValueType == 0x00c4) { //(u)int
                uint v = PacketParser.Utils.ByteConverter.ToUInt32(cipPacket.ParentFrame.Data, index, 4, true);
                valueString = v.ToString();
                index += 4;
                return true;
            }
            else if (tagValueType == 0x00ca) { //REAL
                uint v = PacketParser.Utils.ByteConverter.ToUInt32(cipPacket.ParentFrame.Data, index, 4, true);
                valueString = "0x" + v.ToString("X8");
                index += 4;
                return true;
            }
            else if (tagValueType == 0x00d3) { //DWORD (bit array?)
                uint v = PacketParser.Utils.ByteConverter.ToUInt32(cipPacket.ParentFrame.Data, index, 4, true);
                valueString = "0x" + v.ToString("X8");
                index += 4;
                return true;
            }
            else if (tagValueType == 0x00c5) { //long
                long v = (long)PacketParser.Utils.ByteConverter.ToUInt64(cipPacket.ParentFrame.Data, index, true);
                valueString = v.ToString();
                index += 8;
                return true;
            }
            else {
                index++;
                valueString = null;
                return false;
            }
        }

        private int ExtractCipEthernetLinkInstanceAttribute(CipPacket cipPacket, uint attributeID, int index, System.Collections.Specialized.NameValueCollection parameters) {
            throw new NotImplementedException();
        }

        private int ExtractCipIdentityInstanceAttribute(CipPacket cipPacket, uint attributeID, int index, System.Collections.Specialized.NameValueCollection parameters, NetworkHost sourceHost) {
            if (attributeID == 1) {
                ushort vendorID = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                if(CipPacket.TryGetVendorString(vendorID, out string vendorString)) { 
                    parameters.Add("Vendor", vendorString);
                    sourceHost.AddNumberedExtraDetail("CIP Vendor", vendorString);
                }
                else
                    parameters.Add("Vendor ID", "0x" + vendorID.ToString("X4"));
                return 2;
            }
            else if (attributeID == 2) {
                ushort deviceTypeID = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                lock (CipPacket.DeviceTypeIDs) {
                    if (CipPacket.DeviceTypeIDs.TryGetValue(deviceTypeID, out string deviceTypeString))
                        parameters.Add("Device type", deviceTypeString);
                    else
                        parameters.Add("Device type ID", "0x" + deviceTypeID.ToString("X4"));
                }
                return 2;
            }
            else if (attributeID == 3) {
                ushort productCode = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                parameters.Add("Product code", productCode.ToString());
                return 2;
            }
            else if (attributeID == 4) {
                byte revisionMajor = cipPacket.ParentFrame.Data[index++];
                byte revisionMinor = cipPacket.ParentFrame.Data[index++];
                parameters.Add("Revision", "" + revisionMajor + "." + revisionMinor);
                return 2;
            }
            else if (attributeID == 5) {
                ushort status = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                parameters.Add("Status", "0x" + status.ToString("X4"));
                return 2;
            }
            else if (attributeID == 6) {
                uint serial = PacketParser.Utils.ByteConverter.ToUInt32(cipPacket.ParentFrame.Data, index, 4, true);
                parameters.Add("Serial number", "0x" + serial.ToString("X8"));
                //sourceHost.AddNumberedExtraDetail(EXTRA_DETAIL_SERIAL_NUMBER_LABEL, serial.ToString() + " / 0x" + serial.ToString("X8"));
                this.AddSerialNumber(sourceHost, serial);
                return 4;
            }
            else if (attributeID == 7) {
                byte stringLength = cipPacket.ParentFrame.Data[index++];
                string productName = ASCIIEncoding.ASCII.GetString(cipPacket.ParentFrame.Data, index, stringLength).Trim();
                if (productName?.Length > 0) {
                    parameters.Add("Product name", productName);
                    sourceHost.AddNumberedExtraDetail("CIP Product name", productName);
                }
                return 1 + stringLength;
            }
            else
                return 0;
        }

        private int ExtractCipTcpIpInterfaceInstanceAttribute(CipPacket cipPacket, uint attributeID, int index, System.Collections.Specialized.NameValueCollection parameters, NetworkHost sourceHost) {
            //status
            //capability
            //control
            //link
            //interface conf
            //hostname

            int indexStart = index;
            if (attributeID == 1) {
                /**
                 * 0 = Not configured. 
                 * 1 = IP from BOOTP, DHCP or non volatile storage. 
                 * 2 = IP from hardware settings (e.g.: pushwheel, thumbwheel, etc.)
                 * 3-15 = Reserved for future use. 
                 **/
                byte interfaceConfig = (byte)(cipPacket.ParentFrame.Data[index] & 0x0f);
                return 4;
            }
            else if (attributeID == 2) {
                //Configuration Capability
                string parameterName = "Enabled Interface Capabilities";
                byte capabilityFlags = cipPacket.ParentFrame.Data[index];
                if ((capabilityFlags & 0x01) == 0x01)
                    parameters.Add(parameterName, "BOOTP Client");
                if ((capabilityFlags & 0x02) == 0x02)
                    parameters.Add(parameterName, "DNS Client");
                if ((capabilityFlags & 0x04) == 0x04)
                    parameters.Add(parameterName, "DHCP Client");
                if ((capabilityFlags & 0x08) == 0x08)
                    parameters.Add(parameterName, "DHCP-DNS Update");
                if ((capabilityFlags & 0x10) == 0x10)
                    parameters.Add(parameterName, "Configuration Settable");
                return 4;
            }
            else if (attributeID == 3) {
                //Configuration Control
                string paramName = "Network Configuration";
                byte cc = cipPacket.ParentFrame.Data[index];
                if ((cc & 0x0f) == 0)
                    parameters.Add(paramName, "Static IP");
                else if ((cc & 0x0f) == 1)
                    parameters.Add(paramName, "BOOTP IP");
                else if ((cc & 0x0f) == 2)
                    parameters.Add(paramName, "DHCP IP");
                if ((cc & 0x10) == 0x10)
                    parameters.Add(paramName, "DNS Enabled");
                else
                    parameters.Add(paramName, "DNS Disabled");
                return 4;
            }
            else if (attributeID == 4) {
                //Physical Link Object
                ushort logicalPathSegments = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                return 2 + 2 * logicalPathSegments;
            }
            else if (attributeID == 5) {
                //Interface Config
                IPAddress ip = this.GetIP(cipPacket.ParentFrame.Data, ref index);
                parameters.Add("IP Address", ip.ToString());
                if (!sourceHost.IPAddress.Equals(ip))
                    sourceHost.AddNumberedExtraDetail("CIP Local IP", ip.ToString());
                byte mask4 = cipPacket.ParentFrame.Data[index++];
                byte mask3 = cipPacket.ParentFrame.Data[index++];
                byte mask2 = cipPacket.ParentFrame.Data[index++];
                byte mask1 = cipPacket.ParentFrame.Data[index++];
                parameters.Add("Subnet Mask", string.Join(".", mask1, mask2, mask3, mask4));
                uint gwRaw = PacketParser.Utils.ByteConverter.ToUInt32(cipPacket.ParentFrame.Data, index, 4, true);
                IPAddress gwIP = this.GetIP(cipPacket.ParentFrame.Data, ref index);
                parameters.Add("Gateway IP", gwIP.ToString());
                //from DhcpPacketHandler.cs
                lock (sourceHost.ExtraDetailsList) {
                    if (!sourceHost.ExtraDetailsList.ContainsKey("Default Gateway"))
                        sourceHost.ExtraDetailsList["Default Gateway"] = gwIP.ToString();
                }
                for (int nsCount = 0; nsCount < 2; nsCount++) {
                    IPAddress nsIP = this.GetIP(cipPacket.ParentFrame.Data, ref index);
                    if (!nsIP.Equals(IPAddress.Any))
                        parameters.Add("Name Server(s)", nsIP.ToString());
                }
                ushort domainNameLength = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                index += 2;
                index += domainNameLength;
                return index - indexStart;
            }
            else if (attributeID == 6) {
                //Hostname
                ushort hostnameLength = PacketParser.Utils.ByteConverter.ToUInt16(cipPacket.ParentFrame.Data, index, true);
                index += 2;
                string hostname = ASCIIEncoding.ASCII.GetString(cipPacket.ParentFrame.Data, index, hostnameLength).Trim();
                index += hostnameLength;
                parameters.Add("Hostname", hostname);
                sourceHost.AddNumberedExtraDetail("CIP Hostname", hostname);
                sourceHost.AddHostName(hostname, "EtherNet/IP, CIP");
                return 2 + hostnameLength;
            }
            else
                return 0;
        }

        private IPAddress GetIP(byte[] data, ref int index) {
            byte[] ipBytes = new byte[4];
            Array.Copy(data, index, ipBytes, 0, 4);
            Array.Reverse(ipBytes);
            index += 4;
            return new IPAddress(ipBytes);
        }


        public void Reset() {
            lock (this.recentCipRequests) {
                this.recentCipRequests.Clear();
            }
        }
    }
}
