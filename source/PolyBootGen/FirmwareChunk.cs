using NaCl.Core;

namespace PolyBootGen
{
  public class FirmwareChunk
  {
    public const int ChunkSize = 128;
    public const int TagSize = 16;
    public const int NonceSize = 24;

    public uint Address { get; private set; }
    public byte Len { get; private set; }

    public byte[] Nonce { get; private set; } = new byte[NonceSize];
    public byte[] Ciphertext { get; private set; } = new byte[ChunkSize];
    public byte[] Tag { get; private set; } = new byte[TagSize];

    public FirmwareChunk(
      uint address,
      byte[] plaintext,
      byte[] key,
      byte[] nonce)
    {
      if (plaintext == null)
        throw new ArgumentNullException(nameof(plaintext));

      if (plaintext.Length > ChunkSize)
        throw new ArgumentException("Plaintext too long");

      if (key.Length != 32)
        throw new ArgumentException("Key must be 32 bytes");

      if (nonce.Length != NonceSize)
        throw new ArgumentException("Nonce must be 24 bytes (XChaCha)");

      Address = address;
      Len = (byte)plaintext.Length;

      Array.Copy(nonce, Nonce, NonceSize);

      // pad plaintext to 128 bytes
      byte[] padded = new byte[ChunkSize];
      Array.Copy(plaintext, padded, plaintext.Length);

      EncryptXChaCha20Poly1305(key, padded);
    }

    private void EncryptXChaCha20Poly1305(byte[] key, byte[] plaintext)
    {
      // AAD = address || len
      byte[] aad = new byte[5];
      aad[0] = (byte)(Address >> 0);
      aad[1] = (byte)(Address >> 8);
      aad[2] = (byte)(Address >> 16);
      aad[3] = (byte)(Address >> 24);
      aad[4] = Len;

      var aead = new XChaCha20Poly1305(key);

      // NaCl.Core возвращает ciphertext || tag

      aead.Encrypt(Nonce, plaintext, Ciphertext, Tag, aad);
    }

    public byte[] ToBytes()
    {
      byte[] data = new byte[
        4 +     // address
        1 +     // len
        NonceSize +
        ChunkSize +
        TagSize
      ];

      int offset = 0;

      data[offset++] = (byte)(Address >> 0);
      data[offset++] = (byte)(Address >> 8);
      data[offset++] = (byte)(Address >> 16);
      data[offset++] = (byte)(Address >> 24);

      data[offset++] = Len;

      Array.Copy(Nonce, 0, data, offset, NonceSize);
      offset += NonceSize;

      Array.Copy(Ciphertext, 0, data, offset, ChunkSize);
      offset += ChunkSize;

      Array.Copy(Tag, 0, data, offset, TagSize);

      return data;
    }
  }
}
