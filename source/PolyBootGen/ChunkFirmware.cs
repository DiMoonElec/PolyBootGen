using System.Security.Cryptography;

namespace PolyBootGen
{
  public class FirmwareChunker
  {
    private const int CHUNK_SIZE = 128;
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    public static List<FirmwareChunk> ChunkFirmware(byte[] firmware, FirmwareConfig config)
    {
      if (firmware == null) throw new ArgumentNullException(nameof(firmware));
      if (config == null) throw new ArgumentNullException(nameof(config));

      List<FirmwareChunk> chunks = new();
      uint currentAddress = config.FlashStartAddress;

      int totalChunks = (int)Math.Ceiling(firmware.Length / (double)CHUNK_SIZE);

      for (int i = 0; i < totalChunks; i++)
      {
        int offset = i * CHUNK_SIZE;
        int chunkLen = Math.Min(CHUNK_SIZE, firmware.Length - offset);

        byte[] plaintext = new byte[chunkLen];
        Array.Copy(firmware, offset, plaintext, 0, chunkLen);

        // 🔐 Безопасный nonce
        byte[] nonce = new byte[24];
        Rng.GetBytes(nonce);

        var chunk = new FirmwareChunk(
            currentAddress,
            plaintext,
            config.EncryptionKey,
            nonce
        );

        chunks.Add(chunk);
        currentAddress += (uint)chunkLen;
      }

      return chunks;
    }
  }
}
