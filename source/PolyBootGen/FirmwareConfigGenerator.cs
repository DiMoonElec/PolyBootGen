using System.Security.Cryptography;
using System.Xml.Linq;

namespace PolyBootGen
{
  public static class FirmwareConfigGenerator
  {
    public static void Generate(
      string outputPath,
      uint flashStart,
      uint flashSize,
      string deviceID)
    {
      byte[] encryptionKey = new byte[32]; // 256-bit
      byte[] integrityKey = new byte[32];  // 256-bit

      RandomNumberGenerator.Fill(encryptionKey);
      RandomNumberGenerator.Fill(integrityKey);

      string ToHex(byte[] data) =>
        BitConverter.ToString(data).Replace("-", "");

      var doc = new XDocument(
        new XDeclaration("1.0", "utf-8", null),
        new XElement("FirmwareConfig",
          new XElement("EncryptionKey", ToHex(encryptionKey)),
          new XElement("IntegrityKey", ToHex(integrityKey)),
          new XElement("FlashStartAddress", $"0x{flashStart:X8}"),
          new XElement("FlashSize", flashSize.ToString()),
          new XElement("DeviceID", deviceID)
        )
      );

      doc.Save(outputPath);
    }
  }
}
