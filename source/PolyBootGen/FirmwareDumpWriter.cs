using System.Security.Cryptography;
using System.Text;

namespace PolyBootGen
{
  public static class FirmwareDumpWriter
  {
    public static void WriteToFile(
        IEnumerable<FirmwareChunk> chunks,
        FirmwareChunk headerChunk,
        string filePath)
    {
      if (chunks == null)
        throw new ArgumentNullException(nameof(chunks));

      if (headerChunk == null)
        throw new ArgumentNullException(nameof(headerChunk));

      if (string.IsNullOrWhiteSpace(filePath))
        throw new ArgumentException("Invalid file path", nameof(filePath));

      var linesForHash = new List<string>();

      // ---------- Text header ----------
      string textHeader = "#POLYBOOT;PROTO=1;FORMAT=1";
      linesForHash.Add(textHeader);

      // ---------- Base64 header chunk ----------
      string headerChunkBase64 = Convert.ToBase64String(headerChunk.ToBytes());
      linesForHash.Add(headerChunkBase64);

      // ---------- Data chunks ----------
      foreach (var chunk in chunks)
      {
        byte[] raw = chunk.ToBytes();
        string base64 = Convert.ToBase64String(raw);
        linesForHash.Add(base64);
      }

      // ---------- SHA256 over text lines ----------
      byte[] sha256Bytes = ComputeSha256OverLines(linesForHash);
      string sha256Hex = ConvertToHex(sha256Bytes);

      // ---------- Write file ----------
      using var writer = new StreamWriter(filePath, false, Encoding.ASCII);

      foreach (string line in linesForHash)
        writer.WriteLine(line);

      writer.WriteLine(sha256Hex);
    }

    // ======================================================

    private static byte[] ComputeSha256OverLines(List<string> lines)
    {
      using var sha256 = SHA256.Create();

      foreach (string line in lines)
      {
        byte[] bytes = Encoding.ASCII.GetBytes(line);
        sha256.TransformBlock(bytes, 0, bytes.Length, null, 0);
      }

      sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
      return sha256.Hash!;
    }

    private static string ConvertToHex(byte[] data)
    {
      var sb = new StringBuilder(data.Length * 2);
      foreach (byte b in data)
        sb.AppendFormat("{0:x2}", b);
      return sb.ToString();
    }
  }
}