// Named-pipe client for the QuantumLink service IPC.
//
// The UI process is unprivileged; this client is its only path to
// tunnel state. One request line -> one response line with a matching
// correlation id (see rust/quantumlink-proto/src/ipc.rs).

using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using QuantumLink.Windows.Models;

namespace QuantumLink.Windows.Services;

public sealed class ServicePipeClient : IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private ulong _nextId = 1;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public bool IsConnected => _pipe?.IsConnected == true;

    public async Task ConnectAsync(CancellationToken cancellation = default)
    {
        var pipe = new NamedPipeClientStream(
            ".", IpcProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(TimeSpan.FromSeconds(3), cancellation);
        _pipe = pipe;
        _reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        _writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };

        var hello = await RoundTripAsync(new PipeRequest
        {
            Command = "hello",
            SchemaVersion = IpcProtocol.SchemaVersion,
        }, cancellation);
        if (hello.Kind != "helloAck")
        {
            throw new InvalidOperationException(
                $"service rejected handshake: {hello.Message ?? hello.Kind}");
        }
    }

    public Task<PipeResponse> GetStatusAsync(CancellationToken ct = default) =>
        RoundTripAsync(new PipeRequest { Command = "status" }, ct);

    public Task<PipeResponse> ConnectTunnelAsync(TunnelConfiguration? configuration, CancellationToken ct = default) =>
        RoundTripAsync(new PipeRequest { Command = "connect", Configuration = configuration }, ct);

    public Task<PipeResponse> DisconnectTunnelAsync(CancellationToken ct = default) =>
        RoundTripAsync(new PipeRequest { Command = "disconnect" }, ct);

    public Task<PipeResponse> ReloadConfigurationAsync(TunnelConfiguration configuration, CancellationToken ct = default) =>
        RoundTripAsync(new PipeRequest { Command = "reloadConfiguration", Configuration = configuration }, ct);

    public Task<PipeResponse> ExportDiagnosticsAsync(CancellationToken ct = default) =>
        // The service command always returns the bounded default-safe bundle;
        // no raw export option exists on the IPC schema.
        RoundTripAsync(new PipeRequest { Command = "exportDiagnostics" }, ct);

    private async Task<PipeResponse> RoundTripAsync(PipeRequest request, CancellationToken cancellation)
    {
        if (_writer is null || _reader is null)
        {
            throw new InvalidOperationException("pipe is not connected");
        }
        await _gate.WaitAsync(cancellation);
        try
        {
            var withId = request with { Id = _nextId++ };
            await _writer.WriteLineAsync(JsonSerializer.Serialize(withId, JsonOptions).AsMemory(), cancellation);

            // Responses are ordered; unsolicited pushes carry id 0 and
            // are skipped here (a future status-stream consumer will
            // subscribe to them separately).
            while (true)
            {
                var line = await _reader.ReadLineAsync(cancellation)
                    ?? throw new IOException("service closed the pipe");
                var response = JsonSerializer.Deserialize<PipeResponse>(line, JsonOptions)
                    ?? throw new IOException("malformed response from service");
                if (response.Id == withId.Id)
                {
                    return response;
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _reader?.Dispose();
        _writer?.Dispose();
        if (_pipe is not null)
        {
            await _pipe.DisposeAsync();
        }
        _gate.Dispose();
    }
}
