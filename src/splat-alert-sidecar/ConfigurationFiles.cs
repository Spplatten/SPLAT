namespace Splat.AlertSidecar;

internal static class ConfigurationFiles
{
    internal static byte[] Read(string path,int maximum=16384)
    {
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if (stream.Length < 1 || stream.Length > maximum) throw new InvalidDataException("Configuration/event file size refused.");
        var bytes=new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Configuration changed during read.");
        return bytes;
    }
}
