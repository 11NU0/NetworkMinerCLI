using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketHandlerFramework.PacketHandlers {
    interface ICanParse {
        Type[] ParsedTypes { get; }
        bool CanParse(HashSet<Type> packetTypeSet);

    }
}
