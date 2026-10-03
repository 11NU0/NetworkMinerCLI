using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketHandlerFramework.FileTransfer {
    public interface ITcpStreamAssembler {
        bool IsCompleted { get; }

        int AddData(byte[] data, uint sequenceNumber);
        void Finish();

        void Clear();
    }
}
