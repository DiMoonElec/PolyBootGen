using System.Globalization;
using System.Xml.Linq;

namespace PolyBootGen
{
  public class FirmwareConfig
  {
    public byte[] EncryptionKey { get; private set; }
    public byte[] IntegrityKey { get; private set; }
    public uint FlashStartAddress { get; private set; }
    public uint FlashSize { get; private set; }
    public string DeviceID { get; private set; }

    public FirmwareConfig(string path)
    {
      if (!File.Exists(path))
        throw new FileNotFoundException("Config file not found", path);

      var doc = XDocument.Load(path);
      var root = doc.Element("FirmwareConfig")
                 ?? throw new InvalidDataException("Root element <FirmwareConfig> not found.");

      byte[] HexStringToByteArray(string hex)
      {
        if (hex.Length % 2 != 0)
          throw new FormatException("Hex string length must be even.");
        return Enumerable.Range(0, hex.Length / 2)
                         .Select(i => byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber))
                         .ToArray();
      }

      string encryptionKeyHex = root.Element("EncryptionKey")?.Value
                                ?? throw new InvalidDataException("<EncryptionKey> not found");
      string integrityKeyHex = root.Element("IntegrityKey")?.Value
                               ?? throw new InvalidDataException("<IntegrityKey> not found");
      string flashStartHex = root.Element("FlashStartAddress")?.Value
                             ?? throw new InvalidDataException("<FlashStartAddress> not found");
      string flashSizeStr = root.Element("FlashSize")?.Value
                            ?? throw new InvalidDataException("<FlashSize> not found");
      DeviceID = root.Element("DeviceID")?.Value
                            ?? throw new InvalidDataException("<FlashSize> not found");

      EncryptionKey = HexStringToByteArray(encryptionKeyHex);
      IntegrityKey = HexStringToByteArray(integrityKeyHex);
      FlashStartAddress = flashStartHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                              ? Convert.ToUInt32(flashStartHex, 16)
                              : uint.Parse(flashStartHex);
      FlashSize = uint.Parse(flashSizeStr);

    }
  }
}
