using NaCl.Core;

namespace PolyBootGen
{
  using System.Security.Cryptography;
  public class FirmwareBuilder
  {
    public const int MacSize = 16;
    public const int HashSize = 16;
    public const int V2TailSize = HashSize + MacSize;

    public byte[] BuildFirmware(byte[] binData, FirmwareConfig config)
      => BuildImage(binData, config, Array.Empty<byte>());

    public (byte[] Image, byte[] Hash) BuildFirmwareV2(byte[] binData, FirmwareConfig config)
    {
      ArgumentNullException.ThrowIfNull(binData);
      // Hash only the original binary, before filling, adding the tail or encrypting.
      byte[] hash = SHA256.HashData(binData).AsSpan(0, HashSize).ToArray();
      return (BuildImage(binData, config, hash), hash);
    }

    private static byte[] BuildImage(byte[] binData, FirmwareConfig config, byte[] hash)
    {
      if (config == null) throw new ArgumentNullException(nameof(config));
      if (binData == null) throw new ArgumentNullException(nameof(binData));

      int tailSize = MacSize + hash.Length;
      if (config.FlashSize <= tailSize)
        throw new InvalidOperationException($"Application length must exceed the {tailSize}-byte tail.");
      int capacity = checked((int)config.FlashSize - tailSize);
      if (binData.Length > capacity)
        throw new InvalidOperationException($"Binary size ({binData.Length}) exceeds application capacity ({capacity} bytes, excluding the {tailSize}-byte tail).");

      // Создаем итоговый массив с размером FlashSize
      byte[] firmware = new byte[config.FlashSize];

      // Копируем исходный бинарник
      Array.Copy(binData, firmware, binData.Length);

      // Заполняем оставшуюся область 0xFF
      for (int i = binData.Length; i < firmware.Length; i++)
        firmware[i] = 0xFF;

      hash.CopyTo(firmware, firmware.Length - tailSize);

      // Хэш входит в область, защищённую MAC.
      byte[] mac = new byte[MacSize];
      Poly1305.ComputeMac(config.IntegrityKey, firmware.AsSpan(0, firmware.Length - MacSize), mac);

      // Записываем MAC в конец массива
      Array.Copy(mac, 0, firmware, firmware.Length - MacSize, MacSize);

      return firmware;
    }
  }
}
