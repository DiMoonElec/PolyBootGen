using System.Text;

namespace PolyBootGen
{
  public static class FirmwareKeyHeaderGenerator
  {
    public static void Generate(string configPath, FirmwareConfig config)
    {
      if (config == null)
        throw new ArgumentNullException(nameof(config));

      string outputPath = Path.ChangeExtension(configPath, ".inc");

      using var writer = new StreamWriter(outputPath, false, Encoding.ASCII);

      writer.WriteLine("// Auto-generated file");
      writer.WriteLine("// DO NOT EDIT MANUALLY");
      writer.WriteLine();
      writer.WriteLine("#pragma once");
      writer.WriteLine();
      writer.WriteLine("#include <stdint.h>");
      writer.WriteLine();

      WriteArray(writer, "EncryptionKey", config.EncryptionKey);
      writer.WriteLine();
      WriteArray(writer, "IntegrityKey", config.IntegrityKey);
    }

    private static void WriteArray(StreamWriter writer, string name, byte[] data)
    {
      writer.WriteLine($"static const uint8_t {name}[{data.Length}] =");
      writer.WriteLine("{");

      for (int i = 0; i < data.Length; i++)
      {
        if (i % 8 == 0)
          writer.Write("    ");

        writer.Write($"0x{data[i]:X2}");

        if (i != data.Length - 1)
          writer.Write(", ");

        if ((i + 1) % 8 == 0 || i == data.Length - 1)
          writer.WriteLine();
      }

      writer.WriteLine("};");
    }
  }
}
