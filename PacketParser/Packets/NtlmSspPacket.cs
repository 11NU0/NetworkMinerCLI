//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    public class NtlmSspPacket : AbstractPacket{
        //http://davenport.sourceforge.net/ntlm.html

        public enum NtlmMessageTypes : uint { Negotiate=0x01000000, Challenge=0x02000000, Authentication=0x03000000 }

        public struct SecurityBuffer {

            public ushort length;
            public ushort lengthAllocated;
            public uint offset;

            public SecurityBuffer(byte[] data, ref int dataOffset) {
                this.length = Utils.ByteConverter.ToUInt16(data, dataOffset, true);
                dataOffset+=2;
                this.lengthAllocated = Utils.ByteConverter.ToUInt16(data, dataOffset, true);
                dataOffset+=2;
                this.offset = Utils.ByteConverter.ToUInt32(data, dataOffset, 4, true);
                dataOffset+=4;
            }

            public byte[] GetBufferData(byte[] frameData, int packetStartIndex) {
                byte[] buffer=new byte[this.length];
                Array.Copy(frameData, packetStartIndex+offset, buffer, 0, length);
                return buffer;
            }
        }

        public uint MessageType { get; }
        public string DomainName { get; }
        public string UserName { get; }
        public string HostName { get; }

        public string LanManagerResponse { get; }
        public string NtlmResponse { get; }

        public string NtlmChallenge { get; }

        internal NtlmSspPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "NTLMSSP") {

            this.DomainName=null;
            this.UserName=null;
            this.HostName=null;

            this.LanManagerResponse=null;
            this.NtlmResponse=null;

            int packetIndex=packetStartIndex;
            //0x4e544c4d53535000 = "NTLMSSP"
            if (Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref packetIndex) != "NTLMSSP")
                throw new Exception("Expected NTLMSSP signature string missing!");
            this.MessageType = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetIndex);
            //message type is normally 0x00000001 = Negotiate
            packetIndex+=4;

            if(this.MessageType ==(uint)NtlmMessageTypes.Negotiate) {
                /*
                 *  Description Content 
                 * 0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000) 
                 * 8 NTLM Message Type long (0x01000000) 
                 * 12 Flags long 
                 * (16) Supplied Domain (Optional) security buffer 
                 * (24) Supplied Workstation (Optional) security buffer 
                 * (32) OS Version Structure (Optional) 8 bytes 
                 * (32) (40) start of data block (if required) 
                 */
            }
            else if(this.MessageType ==(uint)NtlmMessageTypes.Challenge) {
                //  Description Content 
                //0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000) 
                //8 NTLM Message Type long (0x02000000) 
                //12 Target Name security buffer 
                //20 Flags long 
                //24 Challenge 8 bytes 
                //(32) Context (optional) 8 bytes (two consecutive longs) 
                //(40) Target Information (optional) security buffer 
                //(48) OS Version Structure (Optional) 8 bytes 
                //32 (48) (56) start of data block 
                
                SecurityBuffer targetNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);

                byte[] flags = new byte[4];
                Array.Copy(parentFrame.Data, packetIndex, flags, 0, 4);
                bool dataIsUnicode = (flags[3] & 0x01) == 0x01;
                packetIndex += 4;//skip past flags

                //see if we have unicode data
                if (targetNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+targetNameSecurityBuffer.offset+targetNameSecurityBuffer.length-1]==(byte)0x00);

                
                this.NtlmChallenge = Utils.ByteConverter.ToHexString(parentFrame.Data, 8, packetIndex);
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("NTLM Challenge", this.NtlmChallenge);

                if(targetNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)targetNameSecurityBuffer.offset;
                    //check if target is a hostname or domain name
                    if ((flags[1] & 0x03) == 0x02) {
                        this.HostName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, targetNameSecurityBuffer.length, dataIsUnicode, true);
                        if (!this.ParentFrame.QuickParse)
                            this.Attributes.Add("Target Host Name", this.DomainName);
                    }
                    else {
                        this.DomainName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, targetNameSecurityBuffer.length, dataIsUnicode, true);
                        if (!this.ParentFrame.QuickParse)
                            this.Attributes.Add("Target Domain Name", this.DomainName);
                    }
                }

            }
            else if(this.MessageType ==(uint)NtlmMessageTypes.Authentication) {
                //  Description Content 
                //0 NTLMSSP Signature Null-terminated ASCII "NTLMSSP" (0x4e544c4d53535000) 
                //8 NTLM Message Type long (0x03000000) 
                //12 LM/LMv2 Response security buffer 
                //20 NTLM/NTLMv2 Response security buffer 
                //28 Target Name security buffer 
                //36 User Name security buffer 
                //44 Workstation Name security buffer 
                //(52) Session Key (optional) security buffer 
                //(60) Flags (optional) long 
                //(64) OS Version Structure (Optional) 8 bytes 
                //52 (64) (72) start of data block 

                bool dataIsUnicode=false;
                SecurityBuffer lanManagerSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer ntLanManagerSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer domainNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer userNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer workstationNameSecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                SecurityBuffer sessionKeySecurityBuffer=new SecurityBuffer(parentFrame.Data, ref packetIndex);
                
                //see if we have unicode data
                if(domainNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+domainNameSecurityBuffer.offset+domainNameSecurityBuffer.length-1]==(byte)0x00);
                else if(userNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+userNameSecurityBuffer.offset+userNameSecurityBuffer.length-1]==(byte)0x00);
                else if(workstationNameSecurityBuffer.length>0)
                    dataIsUnicode=(parentFrame.Data[packetStartIndex+workstationNameSecurityBuffer.offset+workstationNameSecurityBuffer.length-1]==(byte)0x00);   

                //extract the data
                if(lanManagerSecurityBuffer.length>0) {
                    byte[] bufferData=lanManagerSecurityBuffer.GetBufferData(parentFrame.Data, packetStartIndex);
                    this.LanManagerResponse = Utils.ByteConverter.ToHexString(bufferData, bufferData.Length);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("LAN Manager Response", this.LanManagerResponse);
                }
                if(ntLanManagerSecurityBuffer.length>0) {
                    byte[] bufferData=ntLanManagerSecurityBuffer.GetBufferData(parentFrame.Data, PacketStartIndex);
                    this.NtlmResponse = Utils.ByteConverter.ToHexString(bufferData, bufferData.Length);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("NTLM Response", this.NtlmResponse);
                }
                if(domainNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)domainNameSecurityBuffer.offset;
                    this.DomainName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, domainNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Domain Name", this.DomainName);
                }
                if(userNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)userNameSecurityBuffer.offset;
                    this.UserName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, userNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("User Name", this.UserName);
                }
                if(workstationNameSecurityBuffer.length>0) {
                    packetIndex=packetStartIndex+(int)workstationNameSecurityBuffer.offset;
                    this.HostName = Utils.ByteConverter.ReadString(parentFrame.Data, ref packetIndex, workstationNameSecurityBuffer.length, dataIsUnicode, true);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Host Name", this.HostName);
                }

            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
        }
    }
}
