using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PolyBootGen
{
  public static class FirmwareDumpWriter
  {
    /// <summary>
    /// Сохраняет зашифрованные чанки прошивки в текстовый файл (Base64, по строке на чанк)
    /// </summary>
    /// <param name="chunks">Список зашифрованных чанков</param>
    /// <param name="filePath">Путь к выходному файлу</param>
    public static void WriteToFile(IEnumerable<FirmwareChunk> chunks, string filePath)
    {
      if (chunks == null)
        throw new ArgumentNullException(nameof(chunks));

      if (string.IsNullOrWhiteSpace(filePath))
        throw new ArgumentException("Invalid file path", nameof(filePath));

      using var writer = new StreamWriter(filePath, false, Encoding.ASCII);

      foreach (var chunk in chunks)
      {
        byte[] raw = chunk.ToBytes();
        string base64 = Convert.ToBase64String(raw);

        writer.WriteLine(base64);
      }
    }
  }
}
