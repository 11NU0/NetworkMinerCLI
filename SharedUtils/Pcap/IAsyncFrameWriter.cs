using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharedUtils.Pcap {
    public interface IAsyncFrameWriter : IFrameWriter, IDisposable {
        string FullOutputPath { get; }
        PcapFrame.DataLinkTypeEnum DataLinkType { get; }

        Task WriteFrameAsync(IPcapFrame frame, CancellationToken cancellationToken);
        Task FlushAsync(CancellationToken cancellationToken);
        Task CloseAsync();
    }
}
