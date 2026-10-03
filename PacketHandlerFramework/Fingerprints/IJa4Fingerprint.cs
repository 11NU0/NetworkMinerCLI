using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketHandlerFramework.Fingerprints {
    public interface IJa4Fingerprint {

        bool TryGetOS(out string OS);

        bool TryGetApplication(out string Application);
    }
}
