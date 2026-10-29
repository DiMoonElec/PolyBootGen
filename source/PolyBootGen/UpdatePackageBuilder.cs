namespace PolyBootGen
{
  public static class UpdatePackageBuilder
  {
    public static void Build(UpdatePackageConfig package, string? outputOverride = null)
    {
      string output = Path.GetFullPath(outputOverride ?? package.OutputPath);
      var inputs = package.Firmwares.SelectMany(f => new[] { f.BinaryPath, f.VersionHeaderPath })
        .Append(package.ConfigPath);
      if (inputs.Any(p => string.Equals(output, p, StringComparison.OrdinalIgnoreCase)))
        throw new InvalidDataException("Output must not overwrite the package config, a binary or a version header.");

      var lines = new List<string>
      {
        $"#POLYBOOT;PROTO=2;FORMAT=2;TYPE={package.Type.ToString().ToUpperInvariant()};MIN_UPDATER={package.MinUpdaterVersion}"
      };
      lines.AddRange(package.Comments.Select(c => "#REM " + c));
      // Keep informational versions before all sections, as required by the tokenizer.
      foreach (var firmware in package.Firmwares.Where(f => f.Version.HasValue))
        lines.Add($"#REM {firmware.Target.ToString().ToUpperInvariant()} ID=\"{firmware.Config.DeviceID}\" VERSION={firmware.Version}");
      foreach (var firmware in package.Firmwares)
      {
        var config = firmware.Config;
        byte[] binary = File.ReadAllBytes(firmware.BinaryPath);
        if (binary.Length == 0) throw new InvalidDataException($"Empty binary: {firmware.BinaryPath}");
        var (image, hash) = new FirmwareBuilder().BuildFirmwareV2(binary, config);
        string hashHex = Convert.ToHexString(hash);
        string metadata = $"#FIRMWARE;TARGET={firmware.Target.ToString().ToUpperInvariant()};ID=\"{config.DeviceID}\";HASH={hashHex};BOOTLOADER={firmware.BootloaderVersion}";
        if (firmware.ProxyVersion is int proxy) metadata += $";PROXY={proxy}";
        lines.Add(metadata);
        lines.Add(Convert.ToBase64String(FirmwareChunker.ChunkHeader(config).ToBytes()));
        lines.AddRange(FirmwareChunker.ChunkFirmware(image, config)
          .Select(chunk => Convert.ToBase64String(chunk.ToBytes())));

        ulong end = (ulong)config.FlashStartAddress + config.FlashSize;
        Console.WriteLine($"{firmware.Target} {config.DeviceID}: hash {hashHex}, binary {binary.Length} bytes");
        Console.WriteLine($"  App [0x{config.FlashStartAddress:X8}, 0x{end:X8}), length {config.FlashSize}; hash 0x{end - FirmwareBuilder.V2TailSize:X8}; MAC 0x{end - FirmwareBuilder.MacSize:X8}; free {image.Length - FirmwareBuilder.V2TailSize - binary.Length} bytes");
      }
      FirmwareDumpWriter.WriteLines(lines, output, normalize: true);
      Console.WriteLine($"FORMAT=2 package generated: {output}");
    }
  }
}
