using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils {
    public static class IPHelper {
        public static bool IpInNet(System.Net.IPAddress ip, System.Net.IPAddress netIp, byte netPrefixLength) {
            //Make sure filter and IP is of same type (IPv4 vs IPv6)
            if (ip.AddressFamily != netIp.AddressFamily)
                return false;
            byte[] ipBytes = ip.GetAddressBytes();
            byte[] cidrIpBytes = netIp.GetAddressBytes();
            for (int i = 0; i < ipBytes.Length; i++) {//let's do one octet at a time
                uint mask = 0xff;
                mask >>= Math.Max(0, netPrefixLength - i * 8);
                if ((ipBytes[i] | mask) != (cidrIpBytes[i] | mask))
                    return false;
            }
            return true;
        }

        public static bool IpInRange(System.Net.IPAddress ip, (System.Net.IPAddress first, System.Net.IPAddress last) range) {
            SortableIpAddress fromSortable = new SortableIpAddress(range.first);
            SortableIpAddress toSortable = new SortableIpAddress(range.last);
            return IpInRange(ip, (fromSortable, toSortable));
        }
        
        public static bool IpInRange(System.Net.IPAddress ip, (SortableIpAddress First, SortableIpAddress Last) range) {
            return range.First.CompareTo (ip) >= 0 && range.Last.CompareTo(ip) <= 0;
        }

    }
}
