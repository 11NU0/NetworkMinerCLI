//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.IO;
using PacketParser.Packets;

namespace PacketHandlerFramework.Fingerprints {
    public class SatoriDhcpOsFingerprinter : IOsFingerprinter, IComparable<IOsFingerprinter>, IComparable {
        private List<DhcpFingerprint> fingerprintList;

        #region IOsFingerprinter Members

        public double Confidence { get; } = 0.5;

        public string Name { get; } = "Satori DHCP";

        public SatoriDhcpOsFingerprinter(Stream fingerprintXmlStream, string databaseName, double confidence)
            : this(fingerprintXmlStream) {
            this.Name = databaseName;
            this.Confidence = confidence;
        }

        public SatoriDhcpOsFingerprinter(string satoriDhcpXmlFilename)
            : this(new FileStream(satoriDhcpXmlFilename, FileMode.Open, FileAccess.Read)) {
        }

        private SatoriDhcpOsFingerprinter(Stream fingerprintXmlStream) {

            fingerprintList = new List<DhcpFingerprint>();

            XmlDocument dhcpXml = new XmlDocument();
            dhcpXml.Load(fingerprintXmlStream);
            XmlNode fingerprintsNode = dhcpXml.DocumentElement.FirstChild;

            //System.Xml.XPath.XPathNavigator navigator=dhcpXml.CreateNavigator();
            XPathNavigator navigator = fingerprintsNode.CreateNavigator();
            foreach (XPathNavigator fingerprintNavigator in navigator.Select("fingerprint")) {
                string osClass = fingerprintNavigator.GetAttribute("os_class", "");
                string os = fingerprintNavigator.GetAttribute("os_name", "");
                if (os == null || os.Length == 0)
                    os = fingerprintNavigator.GetAttribute("name", "");
                string deviceType = fingerprintNavigator.GetAttribute("device_type", "");
                string deviceVendor = fingerprintNavigator.GetAttribute("device_vendor", "");
                //string os=fingerprintNavigator.GetAttribute("os","");
                DhcpFingerprint fingerprint = new DhcpFingerprint(os, osClass, deviceType, deviceVendor);
                this.fingerprintList.Add(fingerprint);

                foreach (XPathNavigator testNav in fingerprintNavigator.Select("dhcp_tests/test")) fingerprint.AddTest(testNav.Clone());
            }


        }

        public int CompareTo(object obj) {
            if (obj is IOsFingerprinterInfo other)
                return this.CompareTo(other);
            else
                throw new NotImplementedException();
        }

        public int CompareTo(IOsFingerprinter other) {
            return this.Name.CompareTo(other.Name);
        }
        public int CompareTo(IOsFingerprinterInfo other) {
            return this.Name.CompareTo(other.Name);
        }

        public bool TryGetOperatingSystems(out IList<DeviceFingerprint> osList, IEnumerable<AbstractPacket> packetList) {
            try {
                //throw new Exception("The method or operation is not implemented.");
                DhcpPacket dhcpPacket = null;
                IPv4Packet ipPacket = null;

                foreach (AbstractPacket p in packetList) {
                    if (p.GetType() == typeof(DhcpPacket))
                        dhcpPacket = (DhcpPacket)p;
                    else if (p.GetType() == typeof(IPv4Packet))
                        ipPacket = (IPv4Packet)p;
                }

                if (dhcpPacket != null) {//It is OK if the ipPacket is null (which is unlikely)

                    osList = new List<DeviceFingerprint>();
                    int osListWeight = 3;//in order to avoid getting hits on tests with weight 1 and 2

                    foreach (DhcpFingerprint f in this.fingerprintList) {
                        int w = f.GetHighestMatchWeight(dhcpPacket, ipPacket);
                        if (w > osListWeight) {
                            osListWeight = w;
                            osList.Clear();
                            osList.Add(new DeviceFingerprint(f.ToString(false), f.DeviceType, f.DeviceVendor));
                        }
                        else if (w == osListWeight)
                            osList.Add(new DeviceFingerprint(f.ToString(false), f.DeviceType, f.DeviceVendor));
                    }
                    if (osList.Count > 0)                         //packetList=osList;
                        return true;

                }
            }
            catch (Exception e) {
                SharedUtils.Logger.Log("Satori DHCP exception. " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
            }
            osList = null;
            return false;
        }

        

        #endregion

        private class DhcpFingerprint {

            private string os, osClass;
            private List<Test> testList;

            //new for advanced DHCP fingerprinting
            private string deviceType;//device_category (eg SmartDevice, Computer etc)
            private string deviceVendor;//device_family (eg Windows, Android etc)

            internal string DeviceType { get { return this.deviceType; } }
            internal string DeviceVendor { get { return this.deviceVendor; } }

            internal DhcpFingerprint(string os, string osClass, string deviceType, string deviceVendor) {
                this.os = os;
                this.osClass = osClass;
                this.testList = new List<Test>();
                this.deviceType = deviceType;
                this.deviceVendor = deviceVendor;
            }


            public override string ToString() {
                return this.ToString(true);
            }
            public string ToString(bool appendDeviceTypeAndVendor) {

                StringBuilder osString = new StringBuilder();

                if (os != null && os.Length > 0 && osClass != null && osClass.Length > 0)
                    osString.Append(osClass + " - " + os);
                else if (os != null && os.Length > 0)
                    osString.Append(os);
                else if (osClass != null && osClass.Length > 0)
                    osString.Append(osClass);
                else
                    osString.Append(base.ToString());

                if (appendDeviceTypeAndVendor) {
                    if (this.deviceType != null && this.deviceType.Length > 0)
                        osString.Append(" [" + this.deviceType + "]");
                    if (this.deviceVendor != null && this.deviceVendor.Length > 0)
                        osString.Append(" [" + this.deviceVendor + "]");
                }
                return osString.ToString();
            }

            internal void AddTest(XPathNavigator testNavigator) {
                testList.Add(new Test(testNavigator.Clone()));
            }

            //returns -1 if there was no match
            internal int GetHighestMatchWeight(DhcpPacket dhcpPacket, IPv4Packet ipPacket) {
                int highestWeight = -1;
                foreach (Test t in testList) {
                    if (t.Weight > highestWeight && t.Matches(dhcpPacket, ipPacket))
                        highestWeight = t.Weight;
                }
                return highestWeight;
            }

            /// <summary>
            /// Holds test information in order to see if a DHCP packet matches the fingerprint
            /// </summary>
            private class Test {
                private int weight;
                private System.Collections.Specialized.NameValueCollection attributeList;

                internal int Weight { get { return this.weight; } }

                //Typical data in navigator: <test weight="4" matchtype="exact" dhcptype="Inform" dhcpoptions="53,61,12,60,55"/>
                internal Test(XPathNavigator testXPathNavigator) {
                    testXPathNavigator.MoveToFirstAttribute();
                    attributeList = new System.Collections.Specialized.NameValueCollection();

                    do {
                        attributeList.Add(testXPathNavigator.Name, testXPathNavigator.Value);
                        if (testXPathNavigator.Name == "weight")
                            this.weight = Convert.ToInt32(testXPathNavigator.Value);
                    } while (testXPathNavigator.MoveToNextAttribute());

                }

                internal bool Matches(DhcpPacket dhcpPacket, IPv4Packet ipPacket) {
                    foreach (string key in attributeList.Keys) {
                        if (key == "weight") {
                            //do nothing
                            continue;
                        }
                        else if (key == "matchtype") {
                            //do nothing, I will alway require an exact match
                            continue;
                        }
                        else if (key == "dhcptype") {
                            //1   DHCPDISCOVER            [RFC2132]
                            //2   DHCPOFFER               [RFC2132]
                            //3   DHCPREQUEST             [RFC2132]
                            //4   DHCPDECLINE             [RFC2132]
                            //5   DHCPACK                 [RFC2132]
                            //6   DHCPNAK                 [RFC2132]
                            //7   DHCPRELEASE             [RFC2132]
                            //8   DHCPINFORM              [RFC2132]

                            if (attributeList[key] == "Any") {
                                //do nothing... this fingerprint test accept all DHCP types
                                continue;
                            }
                            else if (dhcpPacket.DhcpMessageType == 1 && attributeList[key] != "Discover")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 2 && attributeList[key] != "Offer")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 3 && attributeList[key] != "Request")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 4 && attributeList[key] != "Decline")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 5 && attributeList[key] != "ACK")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 6 && attributeList[key] != "NAK")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 7 && attributeList[key] != "Release")
                                return false;
                            else if (dhcpPacket.DhcpMessageType == 8 && attributeList[key] != "Inform")
                                return false;
                        }
                        else if (key == "dhcpoptions") {
                            //Typical format: 53,61,12,60,55
                            StringBuilder optionSB = new StringBuilder();
                            foreach (DhcpPacket.Option op in dhcpPacket.OptionList) {
                                optionSB.Append(op.OptionCode);
                                optionSB.Append(",");
                            }
                            if (optionSB.Length < 1)
                                return false;
                            else if (optionSB.ToString(0, optionSB.Length - 1) != attributeList[key])
                                return false;
                        }
                        else if (key == "dhcpvendorcode") {
                            //find OptionCode 60 (vendor class identifier) and compare its value to attributeList[key]
                            //can be for example: MSFT 5.0
                            DhcpPacket.Option option60 = null;
                            foreach (DhcpPacket.Option o in dhcpPacket.OptionList)
                                if (o.OptionCode == 60)
                                    option60 = o;
                            if (option60 == null)
                                return false;
                            else if (PacketParser.Utils.ByteConverter.ReadString(option60.OptionValue) != attributeList[key])
                                return false;
                        }
                        else if (key == "dhcpttl") {
                            //this is for IP packets!
                            if (ipPacket == null)
                                return false;
                            else if (ipPacket.TimeToLive.ToString() != attributeList[key])
                                return false;
                        }
                        else if (key == "dhcpoption51") {
                            //IP Address Lease Time
                            //for example: 77760000 (really?) or 43200
                            //It could also be 0xffffffff = "infinite" lease time
                            DhcpPacket.Option option51 = null;
                            foreach (DhcpPacket.Option o in dhcpPacket.OptionList) {
                                if (o.OptionCode == 51)
                                    option51 = o;
                            }
                            if (option51 == null)
                                return false;
                            else if (uint.TryParse(attributeList[key], out uint _uint) && PacketParser.Utils.ByteConverter.ToUInt32(option51.OptionValue) != _uint)
                                return false;
                            else if (PacketParser.Utils.ByteConverter.ToUInt32(option51.OptionValue) == uint.MaxValue && attributeList[key] != "infinite")
                                return false;
                        }
                        else if (key == "dhcpoption55") {
                            //Parameter Request List                
                            //For example: 1,3,6,15,28,12,7,9,42,48,49
                            DhcpPacket.Option option55 = null;
                            foreach (DhcpPacket.Option o in dhcpPacket.OptionList) {
                                if (o.OptionCode == 55)
                                    option55 = o;
                            }
                            if (option55 == null)
                                return false;
                            else {
                                StringBuilder sb = new StringBuilder();
                                foreach (byte b in option55.OptionValue) {
                                    sb.Append(b.ToString());
                                    sb.Append(",");
                                }
                                if (sb.Length < 1)
                                    return false;
                                else if (sb.ToString(0, sb.Length - 1) != attributeList[key])
                                    return false;
                            }
                        }
                        else if (key == "dhcpoption57") {
                            //DHCP Maximum Message Size             
                            //For example: 548 or 590 or 1500
                            DhcpPacket.Option option57 = null;
                            foreach (DhcpPacket.Option o in dhcpPacket.OptionList) {
                                if (o.OptionCode == 57)
                                    option57 = o;
                            }
                            if (option57 == null)
                                return false;
                            else if (PacketParser.Utils.ByteConverter.ToUInt16(option57.OptionValue) != Convert.ToUInt16(attributeList[key]))
                                return false;

                        }
                        else if (key == "ipttl") {
                            if (ipPacket.TimeToLive.ToString() != attributeList[key])
                                return false;
                        }
                    }
                    //since no mis-match was found I guess it was a match...
                    return true;
                }

            }

        }

    }
}
