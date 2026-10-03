using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
//using System.Web.UI.WebControls.WebParts;

namespace PacketParser.Packets {
    //https://quicwg.org/
    //https://www.rfc-editor.org/rfc/rfc9000.html
    //https://www.rfc-editor.org/rfc/rfc9001.html
    //https://www.keysight.com/blogs/en/tech/nwvs/2021/07/17/looking-into-quic-packets-in-your-network
    //https://www.microsoft.com/en-us/research/uploads/prod/2020/10/2020-114.pdf

    public class QuicPacket : AbstractPacket {

#if DEBUG
        /*
        static QuicPacket() {
            RunQuicPacketTest();
        }
        */

        static void RunQuicPacketTest() {
            //test the implementation
            //https://www.rfc-editor.org/rfc/rfc9001.html#section-a.2
            byte[] clientInitialPacketData = Utils.ByteConverter.ToByteArrayFromHexString("0x" +
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" +
            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" +
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" +
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" +
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" +
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" +
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" +
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" +
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" +
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" +
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" +
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" +
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" +
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" +
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" +
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" +
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" +
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" +
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" +
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" +
            "e221af44860018ab0856972e194cd934");

            Frame frame = new Frame(DateTime.Now, clientInitialPacketData, 1);
            QuicPacket qp = new QuicPacket(frame, 0, frame.Data.Length - 1);
            bool success = InitialPacket.TryParse(qp, out InitialPacket initialPacket);
            byte[] destinationConnectionID = Utils.ByteConverter.ToByteArrayFromHexString("0x8394c8f03e515708");
            System.Diagnostics.Debug.Assert(destinationConnectionID.SequenceEqual(initialPacket.DestinationConnectionId));
            byte[] initialSecret;
            System.Diagnostics.Debug.Assert(initialPacket.TryExtractInitialSecret(out initialSecret) == true);
            //7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44 (256-bit)
            System.Diagnostics.Debug.Assert(initialSecret.SequenceEqual(Utils.ByteConverter.ToByteArrayFromHexString("0x7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")));
            System.Diagnostics.Debug.Assert(Keys.CLIENT_IN_LABEL.SequenceEqual(Utils.ByteConverter.ToByteArrayFromHexString("0x00200f746c73313320636c69656e7420696e00")));
            byte[] clientInitialSecret = HkdfExpand(initialSecret, Keys.CLIENT_IN_LABEL, 32);
            //c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea (256-bit)
            byte[] headerProtectionSecret = HkdfExpand(clientInitialSecret, Keys.QUIC_HP_LABEL, 16);
            //9f50449e04a0e810283a1e9933adedd2 (128-bit)

            byte[] serverInitialSecret = HkdfExpand(initialSecret, Keys.SERVER_IN_LABEL, 32);
            //3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b (256-bit)

        }
#endif

        public class Keys {

            //client in: 00200f746c73313320636c69656e7420696e00
            //Expand-Label is defined in RFC8446: section 7.1 Key Schedule
            //https://www.rfc-editor.org/rfc/rfc9001.html#section-a.1
            //[\x0020][length]tls13 client in[\x00]
            internal static readonly byte[] CLIENT_IN_LABEL = {
                0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63,
                0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00
            };

            //server in: 00200f746c7331332073657276657220696e00
            internal static readonly byte[] SERVER_IN_LABEL = Utils.ByteConverter.ToByteArrayFromHexString("0x00200f746c7331332073657276657220696e00");
            //quic key:  00100e746c7331332071756963206b657900
            internal static readonly byte[] QUIC_KEY_LABEL = Utils.ByteConverter.ToByteArrayFromHexString("0x00100e746c7331332071756963206b657900");
            //quic iv:   000c0d746c733133207175696320697600
            internal static readonly byte[] QUIC_IV_LABEL = Utils.ByteConverter.ToByteArrayFromHexString("0x000c0d746c733133207175696320697600");
            //quic hp:   00100d746c733133207175696320687000
            internal static readonly byte[] QUIC_HP_LABEL = {
                0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71,
                0x75, 0x69, 0x63, 0x20, 0x68, 0x70, 0x00
            };

            internal bool TryExtractKeys(InitialPacket initialPacket, out Keys initialKeys) {
                if(initialPacket.InitialKeys != null || initialPacket.TryExtractInitialSecret(out _)) {
                    initialKeys = initialPacket.InitialKeys;
                    return true;
                }
                initialKeys = null;
                return false;
            }

            private byte[] clientInitial = null;
            private byte[] clientHeaderProtection = null;
            private byte[] clientPayloadKey = null;
            private byte[] clientPayloadIV = null;
            private byte[] serverInitial = null;

            //byte[] clientInitial, clientHeaderProtection, clientPayloadKey, clientPayloadIV, serverInitial = null;

            public byte[] Initial { get; }
            public byte[] ClientInitial {
                get {
                    if(this.clientInitial == null)
                        this.clientInitial = HkdfExpand(this.Initial, CLIENT_IN_LABEL, 32);
                    return clientInitial;
                }
            }
            public byte[] ClientHeaderProtection {
                get {
                    if(this.clientHeaderProtection == null)
                        this.clientHeaderProtection = HkdfExpand(this.ClientInitial, QUIC_HP_LABEL, 16);
                    return clientHeaderProtection;
                }
            }
            public byte[] ClientPayloadKey {
                get {
                    if (this.clientPayloadKey == null)
                        this.clientPayloadKey = HkdfExpand(this.ClientInitial, QUIC_KEY_LABEL, 16);
                    return clientPayloadKey;
                }
            }
            public byte[] ClientPayloadIV {
                get {
                    if (this.clientPayloadIV == null)
                        this.clientPayloadIV = HkdfExpand(this.ClientInitial, QUIC_IV_LABEL, 12);
                    return clientPayloadIV;
                }
            }

            public byte[] ServerInitial {
                get {
                    if(this.serverInitial == null)
                        this.serverInitial = HkdfExpand(this.Initial, SERVER_IN_LABEL, 32);
                    return serverInitial;
                }
            }
            public Keys(byte[] initialSecret) {
                this.Initial = initialSecret;
            }
        }

        /**
         * ==Encryption==
         * 1. Packet protection with key from Destination Connection ID
         * 2. Header protection with key from encrypted packet data (sampled)
         *
         * ==Decryption==
         * 1. Decrypt protected headers with sampled and encrypted packet data
         **/

        public enum PacketType : byte {
            Initial = 0,
            ZeroRTT = 1,
            Handshake = 2,
            Retry = 3,
        }

        private static readonly HashAlgorithmName DEFAULT_HASH_ALGO = HashAlgorithmName.SHA256;

        


        //salt array values are copied from https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-quic.c
        private static readonly byte[] HANDSHAKE_SALT_DRAFT_22 = {
            0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
            0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
        };
        static readonly byte[] HANDSHAKE_SALT_DRAFT_23 = {
            0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
            0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
        };
        static readonly byte[] HANDSHAKE_SALT_DRAFT_29 = {
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
            0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
        };

        //This secret is determined by using HKDF-Extract (see Section 2.2 of [HKDF]) with a salt of 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
        //https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2
        static readonly byte[] HANDSHAKE_SALT_V1 = {
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
        };
        static readonly byte[] HANDSHAKE_SALT_DRAFT_Q50 = {
            0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
            0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
        };
        static readonly byte[] HANDSHAKE_SALT_DRAFT_T50 = {
            0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
            0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10
        };
        static readonly byte[] HANDSHAKE_SALT_DRAFT_T51 = {
            0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
            0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d
        };
        static readonly byte[] HANDSHAKE_SALT_v2 = {
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
            0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
        };

        //https://github.com/wireshark/wireshark/blob/4d9d63a37c4bafdfa73809e4554f0950557e8fff/epan/dissectors/packet-quic.c#L890
        static readonly Dictionary<uint, byte[]> VERSION_TO_SALT = new Dictionary<uint, byte[]> {
            { 0x00000001, HANDSHAKE_SALT_V1 },//version 34
            { 0x51303530, HANDSHAKE_SALT_DRAFT_Q50 },//Google's old Q050, often uses gQUIC CRYPTO frames
            { 0x54303530, HANDSHAKE_SALT_DRAFT_T50 },
            { 0x54303531, HANDSHAKE_SALT_DRAFT_T51 },
            { 0x6b3343cf, HANDSHAKE_SALT_v2 },//version 100
            { 0xfaceb001, HANDSHAKE_SALT_DRAFT_22 },//Facebook mvfst
            { 0xfaceb002, HANDSHAKE_SALT_DRAFT_23 },//Facebook mvfst (draft 27)
            { 0xfaceb00e, HANDSHAKE_SALT_DRAFT_23 },//Facebook mvfst (draft 27)
            { 0xff000016, HANDSHAKE_SALT_DRAFT_22 },
            { 0xff000017, HANDSHAKE_SALT_DRAFT_23 },
            { 0xff000018, HANDSHAKE_SALT_DRAFT_23 },//draft 24
            { 0xff000019, HANDSHAKE_SALT_DRAFT_23 },//draft 25
            { 0xff00001a, HANDSHAKE_SALT_DRAFT_23 },//draft 26
            { 0xff00001b, HANDSHAKE_SALT_DRAFT_23 },//draft 27
            { 0xff00001c, HANDSHAKE_SALT_DRAFT_23 },//draft 28
            { 0xff00001d, HANDSHAKE_SALT_DRAFT_29 },
        };

        private static (byte length, byte[] value) GetFixedLengthAndValue(byte[] data, ref int offset) {
            byte length = data[offset];
            offset++;
            byte[] value = new byte[length];
            Array.Copy(data, offset, value, 0, length);
            offset += length;
            return (length, value);
        }


        private static (int length, byte[] value) GetVariableLengthAndValue(byte[] data, ref int offset) {
            int length = (int)ParseVariableLengthInteger(data, ref offset);
            if (length < 0 || length > Frame.MAX_FRAME_SIZE)
                throw new Exception("Abnormal length field: " + length);
            byte[] value = new byte[length];
            Array.Copy(data, offset, value, 0, length);
            offset += length;
            return (length, value);
        }
        private static ulong ParseVariableLengthInteger(byte[] data, ref int offset) {
            //https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
            int base2Log = data[offset] >> 6;
            int length = 1 << base2Log;
            ulong value = (ulong)(data[offset] & 0x3f);
            for (int i = 1; i < length; i++) {
                value <<= 8;
                value |= data[++offset];
            }
            offset++;
            return value;
        }

        //AEAD_AES_128_GCM
        private static bool TryDecryptAesGcm128(byte[] key, byte[] nonce, byte[] ciphertext, int tagSizeInBytes, out byte[] plaintext) {
            //AEAD = Authenticated Encryption with Associated Data
            //https://en.wikipedia.org/wiki/Galois/Counter_Mode#Basic_operation
            //https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
            //https://www.rfc-editor.org/rfc/rfc5116.html


            //From NIST  800-38D:
            //when the length of the IV is 96 bits, then the padding string
            //0[31]||1 is appended to the IV to form the pre-counter block
            if (nonce.Length != 12) {
                plaintext = null;
                return false;
            }
            byte[] counter = new byte[16];
            nonce.CopyTo(counter, 0);
            counter[15] = 1;

            plaintext = new byte[ciphertext.Length - tagSizeInBytes];

            try {

                //There's no GCM mode in .NET Framework so we need to roll our own(!!)
                using (var aes = new AesManaged {
                    KeySize = 128,
                    Key = key,
                    BlockSize = 128,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None,
                }) {
                    using (var encryptor = aes.CreateEncryptor()) {
                        byte[] xorKey = new byte[16];
                        for (uint i = 0; i * 16 < plaintext.Length; i++) {
                            //counter 1 (first lap) is only used for auth data. start with counter 2
                            Utils.ByteConverter.ToByteArray(i + 2).CopyTo(counter, 12);
                            encryptor.TransformBlock(counter, 0, 16, xorKey, 0);
                            //perform xor
                            for (int j = 0; j < 16; j++) {
                                if (i * 16 + j >= plaintext.Length)
                                    break;//if last block is not a multiple of 16
                                plaintext[i * 16 + j] = (byte)(ciphertext[i * 16 + j] ^ xorKey[j]);
                            }
                        }
                    }
                    return true;
                }
            }
            catch {
                return false;
            }

        }


        private static byte[] HkdfExpand(byte[] prk, byte[] info, int outputLength) {
            //https://tools.ietf.org/html/rfc5869
            byte[] hashBlock = new byte[0];
            byte[] output = new byte[outputLength];
            int offset = 0;

            for (int i = 1; offset < output.Length; i++) {
                byte[] currentInfo = new byte[hashBlock.Length + info.Length + 1];
                Array.Copy(hashBlock, 0, currentInfo, 0, hashBlock.Length);
                Array.Copy(info, 0, currentInfo, hashBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)i;
                using (IncrementalHash hmac = IncrementalHash.CreateHMAC(DEFAULT_HASH_ALGO, prk)) {
                    hmac.AppendData(currentInfo);
                    hashBlock = hmac.GetHashAndReset();
                }
                Array.Copy(hashBlock, 0, output, offset, Math.Min(hashBlock.Length, output.Length - offset));
                offset += hashBlock.Length;
            }

            return output;
        }

        private static byte[] HkdfExtract(byte[] salt, byte[] ikm) {
            //The hash function for HKDF when deriving initial secrets and keys is SHA-256.

            /**
             * This also works if SHA256 can be used as a hardcoded hash:
            using (var hmac2 = new HMACSHA256(salt)) {
                return hmac2.ComputeHash(ikm);
            }
            */

            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(DEFAULT_HASH_ALGO, salt)) {
                hmac.AppendData(ikm);
                return hmac.GetHashAndReset();
            }

        }

        public interface LongHeader {
            //https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets
            //not matching this one(?) https://gist.github.com/martinthomson/744d04cbcec9be554f2f8e7bae2715b8
            bool LongHeaderForm { get; }
            bool FixedBit { get; }
            PacketType Type { get; }

            //Reserved Bits (2),
            //Packet Number Length(2),
            uint Version { get; }
            byte DestinationConnectionIdLength { get; }
            byte[] DestinationConnectionId { get; }
            byte SourceConnectionIdLength { get; }
            byte[] SourceConnectionId { get; }
            //Type-Specific Payload (..)
            //byte TokenLength
            //ushort Length
            //byte[] Payload
        }

        internal class ShortHeader {
            bool LongHeaderForm { get; } = false;
            //7 version specific bits
            //destination connection ID
            //Version-Specific Data (..),

        }


        public class InitialPacket : LongHeader {
            //https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2
            //https://github.com/FireNameFN/SharpQuic/blob/b9ea9e814fd4d5cc4bd46ebaca651cbec40dd6a1/SharpQuic/QuicPacketProtection.cs#L112



            internal static bool TryParse(QuicPacket quicPaket, out InitialPacket initialPacket) {
                try {
                    //check first nubble (long header, fixed bit=true, packet type=initial)
                    if ((quicPaket.ParentFrame.Data[quicPaket.PacketStartIndex] & 0xf0) == 0xc0) {
                        initialPacket = new InitialPacket(quicPaket);
                        byte[] packetHeaderXorKey;
                        if (initialPacket.TryGetClientHeaderProtectionMask(out packetHeaderXorKey)) {
                            if (initialPacket.TryUnprotectHeaders(packetHeaderXorKey)) {
                                if (initialPacket.TryUnprotectPayload(initialPacket.InitialKeys.ClientPayloadKey, initialPacket.InitialKeys.ClientPayloadIV)) {
                                    //parse contents in GetSubPackets of QuicPacket
                                    return true;
                                }
                            }
                        }
                    }
                }
                catch { }
                initialPacket = null;
                return false;
            }

            public enum Rfc9000FrameTypes : byte {
                PADDING = 0x00,
                PING = 0x01,
                ACK_02 = 0x02,
                ACK_03 = 0x03,
                CRYPTO = 0x06,
                CONNECTION_CLOSE_1c = 0x1c,
                CONNECTION_CLOSE_1d = 0x1d,
            };

            private QuicPacket quickPacket;

            public bool LongHeaderForm { get; } = true;
            public bool FixedBit { get; } = true;
            public PacketType Type { get; } = PacketType.Initial;

            public byte? ReservedBits { get; private set; } = null;//header protection
            public byte? PacketNumberLength { get; private set; } = null;//header protection
            public uint Version { get; }
            public byte DestinationConnectionIdLength { get; }
            public byte[] DestinationConnectionId { get; }
            public byte SourceConnectionIdLength { get; }
            public byte[] SourceConnectionId { get; }
            public int TokenLength = 0;//should always be zero in InitialPacket according to RFC 9000
            public byte[] Token { get; } = new byte[0];

            /// <summary>
            /// This is the length of the remainder of the packet (that is, the Packet Number and Payload fields) in bytes, encoded as a variable-length integer.
            /// </summary>
            public uint Length { get; }
            public uint? PacketNumber { get; private set; } = null;//header protection
            internal int PacketNumberOffset { get; }

            internal int? PayloadOffset {
                get {
                    if (this.PacketNumberLength.HasValue)
                        return this.PacketNumberOffset + this.PacketNumberLength.Value;
                    else
                        return null;
                }
            }

            public byte[] DecryptedPayload { get; private set; } = null;

            public Keys InitialKeys { get; private set; } = null;

            private InitialPacket(QuicPacket quicPaket) {
                this.quickPacket = quicPaket;
                //https://github.com/gendalf90/Datagrammer.Quic/blob/master/Datagrammer.Quic/Datagrammer.Quic/Protocol/Packet/PacketPayload.cs#L33
                this.LongHeaderForm = (quicPaket.ParentFrame.Data[quicPaket.PacketStartIndex] & 0x80) == 0x80;
                this.FixedBit = (quicPaket.ParentFrame.Data[quicPaket.PacketStartIndex] & 0x40) == 0x40;
                this.Type = (PacketType)((quicPaket.ParentFrame.Data[quicPaket.PacketStartIndex] & 0x30) >> 4);
                //reserved is encrypted
                //length is encrypted
                this.Version = Utils.ByteConverter.ToUInt32(quicPaket.ParentFrame.Data, quicPaket.PacketStartIndex + 1, 4);
                int offset = quicPaket.PacketStartIndex + 5;
                (this.DestinationConnectionIdLength, this.DestinationConnectionId) = GetFixedLengthAndValue(quicPaket.ParentFrame.Data, ref offset);
                (this.SourceConnectionIdLength, this.SourceConnectionId) = GetFixedLengthAndValue(quicPaket.ParentFrame.Data, ref offset);
                (this.TokenLength, this.Token) = GetVariableLengthAndValue(quicPaket.ParentFrame.Data, ref offset);
                //packet nr is encrypted and of variable length (ParseVariableLengthInteger)
                this.Length = (uint)ParseVariableLengthInteger(quicPaket.ParentFrame.Data, ref offset);
                this.PacketNumberOffset = offset;
            }


            public string GetStreamIdentifier() {
                string s = PacketParser.Utils.ByteConverter.ToHexString(this.SourceConnectionId, this.SourceConnectionId.Length);
                string d = PacketParser.Utils.ByteConverter.ToHexString(this.DestinationConnectionId, this.DestinationConnectionId.Length);
                return s + "-" + d;
            }

            public bool TryExtractInitialSecret(out byte[] initialSecret) {
                //https://datatracker.ietf.org/doc/html/rfc5869
                //System.Security.Cryptography.HKDF is not available on .Net Framework 4.8 ;(
                //.NET 5 or later is required!

                if (VERSION_TO_SALT.TryGetValue(this.Version, out byte[] salt)) {
                    byte[] ikm = this.DestinationConnectionId;
                    initialSecret = HkdfExtract(salt, ikm);
                    this.InitialKeys = new Keys(initialSecret);
                    return true;
                }
                else {
                    initialSecret = null;
                    return false;
                    //throw new NotImplementedException("No salt defined for QUIC version 0x" + this.Version.ToString("X4"));
                }
                
                
            }

            private bool TryGetClientHeaderProtectionMask(out byte[] mask) {

                /**
                 * Initial packets apply the packet protection process, but use a
                 * secret derived from the Destination Connection ID field from the
                 * client's first Initial packet.
                 * This secret is determined by using HKDF-Extract
                 * https://www.rfc-editor.org/rfc/rfc9001#section-5.2
                 **/
                if(this.InitialKeys != null || this.TryExtractInitialSecret(out _)) {
                    mask = this.GetHeaderProtectionMask(this.InitialKeys.ClientHeaderProtection);
                    //verify that Reserved bits are b00
                    return ((this.quickPacket.ParentFrame.Data[this.quickPacket.PacketStartIndex] ^ mask[0]) & 0x0c) == 0;
                }
                else
                    mask = null;

                return false;
            }

            private byte[] GetHeaderProtectionMask(byte[] headerProtectionSecret) {
                int sampleOffsetStart = this.PacketNumberOffset + 4;
                byte[] sample = new byte[16];
                Array.Copy(this.quickPacket.ParentFrame.Data, sampleOffsetStart, sample, 0, sample.Length);
                //https://github.com/gendalf90/Datagrammer.Quic/blob/master/Datagrammer.Quic/Datagrammer.Quic/Protocol/Tls/Hashes/Hash.cs
                //https://github.com/httpv3/QuicDotNet/blob/master/src/HTTPv3.Quic.Core/HTTPv3.Quic.Core/Messages/Common/InboundEncryptedLongPacket.cs#L52
                //https://github.com/FireNameFN/SharpQuic/blob/master/SharpQuic/QuicPacketProtection.cs

                using (var aes = new AesManaged {
                    KeySize = 128,
                    Key = headerProtectionSecret,
                    BlockSize = 128,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None,
                }) {
                    using (var encryptor = aes.CreateEncryptor()) {
                        byte[] maskBuffer = new byte[sample.Length];
                        encryptor.TransformBlock(sample, 0, sample.Length, maskBuffer, 0);
                        return maskBuffer.Take(5).ToArray();
                    }
                }
            }


            internal bool TryUnprotectHeaders(byte[] xorKey) {
                if (xorKey.Length < 5)
                    return false;

                byte[] frameData = this.quickPacket.ParentFrame.Data;

                this.ReservedBits = (byte)(((frameData[this.quickPacket.PacketStartIndex] ^ xorKey[0]) >> 2) & 0x03);
                if (this.ReservedBits != 0)//reduces false positives by 87.5% (1/8)
                    return false;
                this.PacketNumberLength = (byte)(1 + ((frameData[this.quickPacket.PacketStartIndex] ^ xorKey[0]) & 0x03));//2 bits => 1..4 bytes
                byte[] packetNumberData = new byte[this.PacketNumberLength.Value];
                for (int i = 0; i < this.PacketNumberLength.Value; i++)
                    packetNumberData[i] = (byte)(frameData[this.PacketNumberOffset + i] ^ xorKey[1 + i]);
                this.PacketNumber = Utils.ByteConverter.ToUInt32(packetNumberData);
                return true;
            }

            internal bool TryUnprotectPayload(byte[] key, byte[] iv) {
                //https://github.com/gendalf90/Datagrammer.Quic/blob/master/Datagrammer.Quic/Datagrammer.Quic/Protocol/Packet/PacketPayload.cs#L33
                //https://github.com/gendalf90/Datagrammer.Quic/blob/master/Datagrammer.Quic/Datagrammer.Quic/Protocol/Tls/Aeads/AesGcmAead.cs
                //https://github.com/httpv3/QuicDotNet/blob/master/src/HTTPv3.Quic.Core/HTTPv3.Quic.Core/Security/EncryptionKeys.cs#L94
                //https://github.com/FireNameFN/SharpQuic/blob/b9ea9e814fd4d5cc4bd46ebaca651cbec40dd6a1/SharpQuic/QuicPacketProtection.cs#L112

                if (this.PayloadOffset.HasValue && this.PacketNumber.HasValue) {
                    //perform AEAD decryption to this.DecryptedPayload

                    //The nonce, N, is formed by combining the packet protection IV
                    //with the packet number. The 62 bits of the reconstructed QUIC
                    //packet number in network byte order are left-padded with
                    //zeros to the size of the IV

                    //The "62 bits" seems strange. 32 bits would make more sense
                    //https://www.rfc-editor.org/errata/rfc9001

                    byte[] nonce = new byte[iv.Length];
                    Utils.ByteConverter.ToByteArray(this.PacketNumber.Value, nonce, iv.Length - 4);
                    for (int i = 0; i < nonce.Length; i++) {
                        nonce[i] ^= iv[i];//XOR
                    }

                    byte[] encryptedPayload = new byte[this.Length - this.PacketNumberLength.Value];
                    Array.Copy(this.quickPacket.ParentFrame.Data, this.PayloadOffset.Value, encryptedPayload, 0, encryptedPayload.Length);

                    //AES GCM is not in .NET Framework, requires .NET Core 3.0 or later
                    if (TryDecryptAesGcm128(key, nonce, encryptedPayload, 16, out byte[] plaintext)) {
                        //verify that the payload holds a valid CRYPTO frame type according to RFC 9000
                        if (plaintext.Length > 0 && Enum.IsDefined(typeof(Rfc9000FrameTypes), plaintext[0])) {
                            this.DecryptedPayload = plaintext;
                            return true;
                        }
                    }
                }
                return false;


            }

            internal IEnumerable<(ulong, byte[])> GetSegments() {
                int offset = 0;
                while (offset < this.DecryptedPayload.Length) {
                    byte frameType = this.DecryptedPayload[offset++];
                    if (Enum.IsDefined(typeof(InitialPacket.Rfc9000FrameTypes), frameType)) {
                        if (frameType == (byte)InitialPacket.Rfc9000FrameTypes.PADDING) {
                            //offset++;
                        }
                        else if (frameType == (byte)InitialPacket.Rfc9000FrameTypes.PING) {
                            //offset++;
                        }
                        else if (frameType == (byte)InitialPacket.Rfc9000FrameTypes.ACK_02 || frameType == (byte)InitialPacket.Rfc9000FrameTypes.ACK_03) {
                            var _largestAcked = ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            var _ackDelay = ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            int ackRangeCount = (int)ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            if (ackRangeCount < 0 || ackRangeCount > this.DecryptedPayload.Length)
                                break;
                            var _firstAckRange = ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            offset += 2 * ackRangeCount;
                            //throw new NotImplementedException("QUIC ACK frames are not supported");
                        }
                        else if (frameType == (byte)InitialPacket.Rfc9000FrameTypes.CRYPTO) {
                            //quic.frame_type == 6
                            var streamOffset = ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            int length = (int)ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            if (length < 0 || offset + length > this.DecryptedPayload.Length)
                                break;//no need to proceed any longer in the while loop
                            byte[] data = new byte[length];
                            Array.Copy(this.DecryptedPayload, offset, data, 0, length);
                            yield return (streamOffset, data);
                            offset += length;
                        }
                        else if (frameType == (byte)InitialPacket.Rfc9000FrameTypes.CONNECTION_CLOSE_1c || frameType == (byte)InitialPacket.Rfc9000FrameTypes.CONNECTION_CLOSE_1d) {
                            var _errorCode = ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            var _frameType = ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            int reasonFrameLength = (int)ParseVariableLengthInteger(this.DecryptedPayload, ref offset);
                            if (reasonFrameLength < 0)
                                break;
                            offset += reasonFrameLength;
                        }
                        else
                            break;
                    }
                    else {
                        break;
                    }
                }
            }

        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out QuicPacket quickPacket) {
            if ((parentFrame.Data[packetStartIndex] & 0xf0) == 0xc0) {
                //check if it is a valid initial packet
                uint version = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 1, 4);
                if(VERSION_TO_SALT.ContainsKey(version)) {
                    int offset = packetStartIndex + 5;
                    //destinationConnectionIdLength
                    offset += parentFrame.Data[offset] + 1;
                    if (offset > packetStartIndex && offset < packetEndIndex) {
                        //sourceConnectionIdLength
                        offset += parentFrame.Data[offset] + 1;
                        if (offset > packetStartIndex && offset < packetEndIndex) {
                            int tokenLength = (int)ParseVariableLengthInteger(parentFrame.Data, ref offset);
                            offset += tokenLength;
                            if (offset > packetStartIndex && offset < packetEndIndex) {
                                int length = (int)ParseVariableLengthInteger(parentFrame.Data, ref offset);
                                if (length >= 0 && offset + length <= packetEndIndex + 1) {
                                    int newPacketEndIndex = offset + length - 1;
                                    quickPacket = new QuicPacket(parentFrame, packetStartIndex, newPacketEndIndex);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            quickPacket = null;
            return false;
        }



        public static bool TryGetTlsHandshakePacket(Frame parentFrame, IEnumerable<InitialPacket> initials, out TlsRecordPacket.HandshakePacket handshake) {
            SortedDictionary<ulong, byte[]> dataStream = new SortedDictionary<ulong, byte[]>();
            foreach (var initial in initials)
                if (initial.DecryptedPayload?.Length > 0)
                    foreach ((ulong streamOffset, byte[] data) in initial.GetSegments()) {
                        dataStream[streamOffset] = data;
                    }

            if (dataStream.Count > 0) {
                List<byte[]> sequentialBytes = new List<byte[]>();
                ulong sequentialBytesIndex = 0;
                foreach (KeyValuePair<ulong, byte[]> cryptoData in dataStream) {
                    if (cryptoData.Key > sequentialBytesIndex)
                        break;
                    else if (cryptoData.Key == sequentialBytesIndex) {
                        sequentialBytes.Add(cryptoData.Value);
                        sequentialBytesIndex += (ulong)cryptoData.Value.Length;
                    }
                    else if (cryptoData.Key < sequentialBytesIndex) {
                        if (cryptoData.Key + (ulong)cryptoData.Value.Length > sequentialBytesIndex) {
                            byte[] partialData = new byte[cryptoData.Key + (ulong)cryptoData.Value.Length - sequentialBytesIndex];
                            Array.Copy(cryptoData.Value, cryptoData.Value.Length - partialData.Length, partialData, 0, partialData.Length);
                            sequentialBytesIndex += (uint)partialData.Length;
                        }
                    }
                }
                if (sequentialBytes.Count > 0) {
                    byte[] decryptedCryptoPayload = sequentialBytes.SelectMany(b => b).ToArray();
                    if (decryptedCryptoPayload.Length > 0) {
                        Frame virtualFrame = new Frame(parentFrame.Timestamp, decryptedCryptoPayload, parentFrame.FrameNumber);
                        if (TlsRecordPacket.HandshakePacket.TryGetHandshake(virtualFrame, 0, virtualFrame.Data.Length - 1, out handshake)) {
                            return true;
                        }
                    }
                }
            }
            handshake = null;
            return false;
        }

        public InitialPacket Initial { get; }


        private QuicPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "QUIC") {
            //check for initial packet
            if ((parentFrame.Data[PacketStartIndex] & 0xf0) == 0xc0) {
                if(InitialPacket.TryParse(this, out InitialPacket initialPacket)) {
                    this.Initial = initialPacket;
                }
            }
        }



        public bool TryGetTlsHandshakePacket(out TlsRecordPacket.HandshakePacket handshake) {
            if (this.Initial != null && this.Initial.DecryptedPayload?.Length > 0) {
                //TODO parse whatever is inside of the quic payload
                //only return CRYPTO data structures
                
                //this is similar to TcpDataStream class
                return TryGetTlsHandshakePacket(this.ParentFrame, new InitialPacket[] { this.Initial }, out handshake);
            }
            handshake = null;
            return false;
            
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            //Do nothing, no known sub packets...
            
        }

    }
}
