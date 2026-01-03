namespace PolyBootGen
{
  public class PolyBootGen
  {
    public static void Main(string[] args)
    {
      if (args.Length == 0)
      {
        PrintUsage();
        return;
      }

      try
      {
        string mode = args[0].ToLowerInvariant();

        switch (mode)
        {
          case "build":
            RunBuildMode(args);
            break;

          case "genconfig":
            RunGenerateConfig(args);
            break;

          default:
            Console.WriteLine($"Unknown mode: {mode}");
            PrintUsage();
            break;
        }
      }
      catch (Exception ex)
      {
        Console.WriteLine($"Error: {ex.Message}");
      }
    }

    // ---------------- build ----------------

    private static void RunBuildMode(string[] args)
    {
      string? binPath = null;
      string? configPath = null;
      string outputPath = "firmware_dump.txt";

      for (int i = 1; i < args.Length; i++)
      {
        switch (args[i])
        {
          case "-bin":
            binPath = args[++i];
            break;
          case "-config":
            configPath = args[++i];
            break;
          case "-out":
            outputPath = args[++i];
            break;
        }
      }

      if (binPath == null || configPath == null)
        throw new ArgumentException("Usage: build -bin <file> -config <file> [-out file]");

      byte[] firmware = File.ReadAllBytes(binPath);
      var config = FirmwareConfig.LoadFromFile(configPath);

      var builder = new FirmwareBuilder();
      var prepared = builder.BuildFirmware(firmware, config);
      var chunks = FirmwareChunker.ChunkFirmware(prepared, config);

      FirmwareDumpWriter.WriteToFile(chunks, outputPath);

      Console.WriteLine("Firmware dump generated");
    }

    // ---------------- genconfig ----------------

    private static void RunGenerateConfig(string[] args)
    {
      string? output = null;
      uint flashAddr = 0;
      uint flashSize = 0;

      for (int i = 1; i < args.Length; i++)
      {
        switch (args[i])
        {
          case "-out":
            output = args[++i];
            break;
          case "-flash":
            flashAddr = ParseUInt(args[++i]);
            break;
          case "-size":
            flashSize = uint.Parse(args[++i]);
            break;
        }
      }

      if (output == null || flashSize == 0)
        throw new ArgumentException("Usage: genconfig -out <file> -flash <addr> -size <bytes>");

      FirmwareConfigGenerator.Generate(output, flashAddr, flashSize);

      FirmwareConfig config = FirmwareConfig.LoadFromFile(output);
      FirmwareKeyHeaderGenerator.Generate(output, config);

      Console.WriteLine($"Config generated: {output}");
    }

    private static uint ParseUInt(string value)
    {
      return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? Convert.ToUInt32(value, 16)
        : uint.Parse(value);
    }

    private static void PrintUsage()
    {
      Console.WriteLine("PolyBootGen usage:");
      Console.WriteLine();
      Console.WriteLine("  build     -bin <file> -config <file> [-out file]");
      Console.WriteLine("  genconfig -out <file> -flash <addr> -size <bytes>");
      Console.WriteLine();
      Console.WriteLine("Examples:");
      Console.WriteLine("  PolyBootGen genconfig -out config.xml -flash 0x08000000 -size 262144");
      Console.WriteLine("  PolyBootGen build -bin app.bin -config config.xml -out firmware.txt");
    }
  }
}
