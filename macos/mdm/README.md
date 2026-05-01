# Managed Deployment Payload Templates

These files are templates for the managed deployment work that can be prepared before Apple Developer account setup. They are not installable as-is.

Replace placeholders before use:

- `TEAMID`
- `com.quantumlink.macos`
- `com.quantumlink.macos.PacketTunnel`
- `group.com.quantumlink.macos`
- VPN payload UUIDs
- Organization-specific app bundle identifiers for per-app VPN mapping

Real validation requires Apple-granted Network Extension entitlements, signed bundles, provisioning profiles, and an MDM-managed Mac.
