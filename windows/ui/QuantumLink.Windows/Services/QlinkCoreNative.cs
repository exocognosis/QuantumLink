// P/Invoke bindings for qlink_core.dll — the Windows equivalent of the
// macOS RustCoreBridge dylib loading, made platform-aware.
//
// The UI only needs read-only utility entry points (version/suite for
// the About panel and update gating). All tunnel-core, mesh-transport,
// and keypair FFI surfaces are intentionally NOT bound here: those run
// inside the privileged service, which links qlink-core natively and
// needs no FFI at all.

using System.Runtime.InteropServices;

namespace QuantumLink.Windows.Services;

public static partial class QlinkCoreNative
{
    private const string Library = "qlink_core"; // resolves qlink_core.dll next to the exe

    [LibraryImport(Library, EntryPoint = "qlink_core_version")]
    private static partial nint QlinkCoreVersion();

    [LibraryImport(Library, EntryPoint = "qlink_core_default_suite")]
    private static partial nint QlinkCoreDefaultSuite();

    public static string? TryGetVersion()
    {
        try
        {
            return Marshal.PtrToStringUTF8(QlinkCoreVersion());
        }
        catch (DllNotFoundException)
        {
            return null; // UI still works; the service owns the core.
        }
    }

    public static string? TryGetDefaultSuite()
    {
        try
        {
            return Marshal.PtrToStringUTF8(QlinkCoreDefaultSuite());
        }
        catch (DllNotFoundException)
        {
            return null;
        }
    }
}
