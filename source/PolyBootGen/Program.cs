namespace PolyBootGen
{
  public class PolyBootGen
  {
    public static int Main(string[] args)
    {
      if (args.Length == 0)
      {
        PrintUsage();
        return 1;
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

          case "build-v2":
            RunBuildV2Mode(args);
            break;

          default:
            Console.WriteLine($"Unknown mode: {mode}");
            PrintUsage();
            return 1;
        }
        return 0;
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine($"Error: {ex.Message}");
        return 1;
      }
    }

    // ---------------- build ----------------

    private static void RunBuildV2Mode(string[] args)
    {
      string? config = null;
      string? output = null;
      for (int i = 1; i < args.Length; i++)
      {
        string option = args[i];
        if (option != "-config" && option != "-out")
          throw new ArgumentException($"Unknown build-v2 option: {option}");
        if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
          throw new ArgumentException($"Missing value for {option}.");
        string value = args[++i];
        if (option == "-config")
        {
          if (config != null) throw new ArgumentException("Duplicate -config option.");
          config = value;
        }
        else
        {
          if (output != null) throw new ArgumentException("Duplicate -out option.");
          output = value;
        }
      }
      if (config == null) throw new ArgumentException("Usage: build-v2 -config <file> [-out file]");
      UpdatePackageBuilder.Build(UpdatePackageConfig.Load(config), output);
    }

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
      var config = new FirmwareConfig(configPath);

      var builder = new FirmwareBuilder();
      var prepared = builder.BuildFirmware(firmware, config);
      var chunks = FirmwareChunker.ChunkFirmware(prepared, config);
      var header = FirmwareChunker.ChunkHeader(config);

      FirmwareDumpWriter.WriteToFile(chunks, header, outputPath);

      Console.WriteLine("Firmware dump generated");
    }

    // ---------------- genconfig ----------------

    private static void RunGenerateConfig(string[] args)
    {
      string? output = null;
      string? deviceID = null;
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
          case "-devid":
            deviceID = args[++i];
            break;
        }
      }

      if (output == null || deviceID == null || flashSize == 0)
        throw new ArgumentException("Usage: genconfig -out <file> -flash <addr> -size <bytes> -devid \"DEVICE_NAME\"");

      FirmwareConfigGenerator.Generate(output, flashAddr, flashSize, deviceID);

      var config = new FirmwareConfig(output);
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
      Console.WriteLine("  build-v2  -config <package.xml> [-out file]");
      Console.WriteLine("  genconfig -out <file> -flash <addr> -size <bytes> -devid \"DEVICE_NAME\"");
      Console.WriteLine();
      Console.WriteLine("Examples:");
      Console.WriteLine("  PolyBootGen genconfig -out config.xml -flash 0x08000000 -size 262144 -devid \"MY DEVICE\"");
      Console.WriteLine("  PolyBootGen build -bin app.bin -config config.xml -out firmware.txt");
    }
  }
}
