using System.Security.Cryptography;
using System.Text;

namespace PolyBootGen
{
  public class FirmwareChunker
  {
    private const int CHUNK_SIZE = FirmwareChunk.ChunkSize;
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    public static List<FirmwareChunk> ChunkFirmware(byte[] firmware, FirmwareConfig config,
      bool skipErasedChunks = false)
    {
      if (firmware == null) throw new ArgumentNullException(nameof(firmware));
      if (config == null) throw new ArgumentNullException(nameof(config));

      List<FirmwareChunk> chunks = new();

      int totalChunks = (int)Math.Ceiling(firmware.Length / (double)CHUNK_SIZE);

      for (int i = 0; i < totalChunks; i++)
      {
        int offset = i * CHUNK_SIZE;
        int chunkLen = Math.Min(CHUNK_SIZE, firmware.Length - offset);

        // Test the actual image bytes before encryption and zero padding.
        if (skipErasedChunks && firmware.AsSpan(offset, chunkLen).IndexOfAnyExcept((byte)0xFF) < 0)
          continue;

        byte[] plaintext = new byte[chunkLen];
        Array.Copy(firmware, offset, plaintext, 0, chunkLen);

        // Безопасный nonce
        byte[] nonce = new byte[24];
        Rng.GetBytes(nonce);

        var chunk = new FirmwareChunk(
            config.FlashStartAddress + (uint)offset,
            plaintext,
            config.EncryptionKey,
            nonce
        );

        chunks.Add(chunk);
      }

      return chunks;
    }

    public static FirmwareChunk ChunkHeader(FirmwareConfig config)
    {
      byte[] nonce = new byte[24];
      Rng.GetBytes(nonce);

      var devID = ConvertToUtf8Array(config.DeviceID, FirmwareChunk.ChunkSize);
      var chunk = new FirmwareChunk(
            config.FlashSize,
            devID,
            config.EncryptionKey,
            nonce
        );

      return chunk;
    }

    private static byte[] ConvertToUtf8Array(string input, int length)
    {
      if (input == null)
      {
        throw new ArgumentNullException(nameof(input));
      }

      byte[] utf8Bytes = Encoding.UTF8.GetBytes(input);

      if (utf8Bytes.Length > length)
      {
        throw new ArgumentException($"The DeviceID string length exceeds the limit of {length} bytes.\r\n");
      }

      byte[] result = new byte[length];
      Array.Copy(utf8Bytes, 0, result, 0, utf8Bytes.Length);

      return result;
    }
  }
}
