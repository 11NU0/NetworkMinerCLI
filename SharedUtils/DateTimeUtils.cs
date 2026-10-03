using SharedUtils.Pcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SharedUtils.Pcap.PcapParser;

namespace SharedUtils {
    public static class DateTimeUtils {

        static readonly DateTime EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime EpochToDateTime(uint seconds, (TimestampResolition resolution, uint count)? subSeconds = null) {
            long tics = ((long)seconds) * 10000000;
            if(subSeconds.HasValue) {
                if (subSeconds.Value.resolution == TimestampResolition.microsecond)
                    tics += subSeconds.Value.count * 10;
                else if (subSeconds.Value.resolution == TimestampResolition.nanosecond)
                    tics += subSeconds.Value.count / 100;
            }
            TimeSpan timespan = new TimeSpan(tics);
            return EPOCH.Add(timespan);
        }

        public static (uint seconds, uint microseconds) DateTimeToEpoch(DateTime timestamp) {
            TimeSpan delta = timestamp.ToUniversalTime().Subtract(EPOCH);
            //The smallest unit of time is the tick, which is equal to 100 nanoseconds. A tick can be negative or positive.
            long totalMicroseconds = delta.Ticks / 10;
            uint seconds = (uint)(totalMicroseconds / 1000000);
            uint microseconds = (uint)(totalMicroseconds % 1000000);
            return (seconds, microseconds);
        }
    }
}
