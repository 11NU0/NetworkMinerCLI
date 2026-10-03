using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser {
    //this enum should probably be moved somewhere else...
    public enum ApplicationLayerProtocol {
        Unknown,
        BackConnect,//TCP
        BackConnectFileManager,//TCP
        BackConnectReverseShell,//TCP
        BackConnectReverseSocks,//TCP
        BackConnectReverseVNC,//TCP (reverse Rfb)
        CAPWAP,//UDP
        DHCP, //UDP
        DNS, //TCP or UDP
        EtherNetIP,//TCP
        FTP, //TCP
        GTP, //UDP
        HTTP, //TCP
        HTTP2, //TCP
        IRC, //TCP
        IEC_104, //TCP
        IMAP, //TCP
        Kerberos, //TCP or UDP
        LPD,
        Meterpreter,//TCP
        MC_NMF,//TCP
        ModbusTCP, //TCP
        NetBiosNameService, //TCP or UDP
        NetBiosDatagramService, //UDP
        NetBiosSessionService, //TCP
        njRAT,//TCP
        OpenFlow, //TCP
        Oscar, //TCP
        OscarFileTransfer, //TCP
        POP3, //TCP
        VNC,//TCP
        QUIC,//UDP
        Remcos,//TCP
        RMS,//TCP
        RTP,//TCP
        SIP, //UDP
        SMTP, //TCP
        SNMP,//UDP
        SOCKS, //TCP
        SpotifyServerProtocol, //TCP
        SSH, //TCP
        SSL, //TCP
        Syslog, //UDP
        TabularDataStream, //TCP
        Teredo,//UDP
        TFTP, //UDP
        TPKT, //TCP
        TZSP, //UDP
        UPnP, //UDP
        VXLAN//UDP
    }


}
