using NaCl.Core;

namespace PolyBootGen
{
  public class FirmwareBuilder
  {
    private const int MAC_SIZE = 16;

    public byte[] BuildFirmware(byte[] binData, FirmwareConfig config)
    {
      if (config == null) throw new ArgumentNullException(nameof(config));
      if (binData == null) throw new ArgumentNullException(nameof(binData));

      if (binData.Length > config.FlashSize - MAC_SIZE)
        throw new InvalidOperationException($"Binary size ({binData.Length}) exceeds allowed FlashSize - MAC_SIZE ({config.FlashSize - MAC_SIZE}).");

      // Создаем итоговый массив с размером FlashSize
      byte[] firmware = new byte[config.FlashSize];

      // Копируем исходный бинарник
      Array.Copy(binData, firmware, binData.Length);

      // Заполняем оставшуюся область 0xFF
      for (int i = binData.Length; i < firmware.Length; i++)
        firmware[i] = 0xFF;

      // Вычисляем Poly1305 MAC
      byte[] mac = new byte[MAC_SIZE];
      Poly1305.ComputeMac(config.IntegrityKey, new ReadOnlySpan<byte>(firmware, 0, (int)(config.FlashSize - MAC_SIZE)), mac);

      // Записываем MAC в конец массива
      Array.Copy(mac, 0, firmware, firmware.Length - MAC_SIZE, MAC_SIZE);

      return firmware;
    }
  }
}
