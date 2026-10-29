using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using NaCl.Core;
using PolyBootGen;
using Generator = PolyBootGen.PolyBootGen;

string work = Path.Combine(Path.GetTempPath(), "PolyBootGen.Tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(work);
int passed = 0;
var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
var integrityKey = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
string hexKey = Convert.ToHexString(key);
string hexIntegrity = Convert.ToHexString(integrityKey);
string header = "#ifndef FWVERSION_H\n#define FWVERSION_H\n#define FW_VERSION_MAJOR 258 // comment\n#define FW_VERSION_MINOR 772\n#define FW_VERSION_PATCH 1286\n#endif\n";
string configPath = Path.Combine(work, "update.xml");
string fixturePath = args.Length == 1 ? Path.GetFullPath(args[0]) : Path.Combine(work, "fixtures");
Directory.CreateDirectory(fixturePath);

void Assert(bool condition, string message)
{
  if (!condition) throw new Exception(message);
}
void Test(string name, Action action)
{
  action();
  passed++;
  Console.WriteLine("PASS: " + name);
}
void Reject(Action action)
{
  try { action(); }
  catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or FormatException or OverflowException) { return; }
  throw new Exception("Expected operation to fail.");
}
XElement Section(string target, string id, string binary, string version, string size = "257") =>
  new("Firmware", new XAttribute("Target", target),
    new XElement("DeviceId", id), new XElement("BootloaderVersion", 2),
    new XElement("Binary", binary), new XElement("VersionHeader", version),
    new XElement("Memory", new XElement("AppBegin", "0x08003000"), new XElement("AppLength", size)),
    new XElement("Keys", new XElement("EncryptionKey", hexKey), new XElement("IntegrityKey", hexIntegrity)));
XDocument Package(bool complex = false)
{
  var root = Section("ROOT", "DEVICE; MAIN", "root.bin", "FWVersion.h");
  var doc = new XDocument(new XElement("UpdatePackage", new XAttribute("SchemaVersion", 1),
    new XAttribute("Format", 2), new XAttribute("Type", complex ? "COMPLEX" : "SINGLE"),
    new XElement("Output", "dist/update.xbin"), new XElement("MinUpdaterVersion", "1.0.0"),
    new XElement("Comment", "Test package"), root));
  if (complex)
  {
    root.Add(new XElement("ProxyVersion", 1));
    var slave = Section("SLAVE", "SLAVE", "slave.bin", "SlaveVersion.h", "256");
    // Exercise independent device keys and ROOT/SLAVE ordering.
    slave.Element("Keys")!.Element("EncryptionKey")!.Value = hexIntegrity;
    slave.Element("Keys")!.Element("IntegrityKey")!.Value = hexKey;
    doc.Root!.AddFirst(slave);
  }
  return doc;
}
UpdatePackageConfig Load(XDocument doc)
{
  doc.Save(configPath);
  return UpdatePackageConfig.Load(configPath);
}
byte[] Decrypt(string line, byte[] encryptionKey, out uint address, out int length)
{
  byte[] bytes = Convert.FromBase64String(line);
  Assert(bytes.Length == 173, "Binary chunk structure changed.");
  address = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
  length = bytes[4];
  byte[] plain = new byte[128];
  using var aead = new XChaCha20Poly1305(encryptionKey);
  aead.Decrypt(bytes.AsSpan(5, 24), bytes.AsSpan(29, 128), bytes.AsSpan(157, 16), plain, bytes.AsSpan(0, 5));
  return plain;
}
void CheckMac(byte[] image, byte[] macKey)
{
  byte[] expected = new byte[16];
  Poly1305.ComputeMac(macKey, image.AsSpan(0, image.Length - 16), expected);
  Assert(image.AsSpan(image.Length - 16).SequenceEqual(expected), "Image MAC mismatch.");
}
void CheckHash(string[] lines)
{
  string expected = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(string.Concat(lines[..^1]))));
  Assert(expected.Equals(lines[^1], StringComparison.OrdinalIgnoreCase), "Container SHA256 mismatch.");
}

(string[] Lines, string[] Hashes, byte[][] Images) Snapshot(UpdatePackageConfig package, string name)
{
  string path = Path.Combine(work, name + ".xbin");
  UpdatePackageBuilder.Build(package, path);
  string[] lines = File.ReadAllLines(path);
  CheckHash(lines);
  var images = new List<byte[]>();
  var hashes = new List<string>();
  int pos = Array.FindIndex(lines, line => line.StartsWith("#FIRMWARE;"));
  foreach (var firmware in package.Firmwares)
  {
    hashes.Add(lines[pos++].Split(';').Single(field => field.StartsWith("HASH="))[5..]);
    pos++; // Encrypted header.
    var image = new List<byte>();
    while (pos < lines.Length - 1 && !lines[pos].StartsWith('#'))
    {
      byte[] plain = Decrypt(lines[pos++], firmware.Config.EncryptionKey, out _, out int count);
      image.AddRange(plain[..count]);
    }
    images.Add(image.ToArray());
  }
  return (lines, hashes.ToArray(), images.ToArray());
}

try
{
  File.WriteAllText(Path.Combine(work, "FWVersion.h"), header);
  File.WriteAllText(Path.Combine(work, "SlaveVersion.h"), "#define FW_VERSION_MAJOR 9\n#define FW_VERSION_MINOR 8\n#define FW_VERSION_PATCH 7\n");
  byte[] binary = Enumerable.Range(0, 133).Select(i => (byte)i).ToArray();
  File.WriteAllBytes(Path.Combine(work, "root.bin"), binary);
  File.WriteAllBytes(Path.Combine(work, "slave.bin"), [1, 2, 3]);

  Test("Version header, include guard, comments and uint16 bounds", () =>
  {
    Assert(FirmwareVersion.ReadHeader(Path.Combine(work, "FWVersion.h")) == new FirmwareVersion(258, 772, 1286), "Wrong header version.");
    Assert(FirmwareVersion.Parse("0.65535.0").Minor == 65535, "uint16 upper bound.");
    foreach (string value in new[] { "-1.0.0", "1.2", "1.2.65536", "1.2.3.4", "1.2.+3" })
      Reject(() => FirmwareVersion.Parse(value));
    string bad = Path.Combine(work, "bad.h");
    foreach (string text in new[]
    {
      header.Replace("772", "65536"), header.Replace("772", "(1 + 2)"),
      header.Replace("#define FW_VERSION_MINOR 772", "#define FW_VERSION_MINOR"),
      header.Replace("#endif", "#define FW_VERSION_MAJOR 1\n#endif"),
      header.Replace("#define FW_VERSION_PATCH 1286", "#if 0\n#define FW_VERSION_PATCH 1286\n#endif"),
      header.Replace("#define FW_VERSION_PATCH 1286", "#ifndef FEATURE\n#define FW_VERSION_PATCH 1286\n#endif"),
      header.Replace("772", "7/**/72")
    })
    {
      File.WriteAllText(bad, text);
      Reject(() => FirmwareVersion.ReadHeader(bad));
    }
  });

  Test("Memory numbers and overflow", () =>
  {
    foreach (string size in new[] { "118784", "0x1D000", "116K", "116k" })
      Assert(UpdatePackageConfig.ParseMemoryNumber(size, true) == 118784, "Wrong AppLength.");
    Reject(() => UpdatePackageConfig.ParseMemoryNumber("4194304K", true));
    Reject(() => UpdatePackageConfig.ParseMemoryNumber("116K", false));
    Reject(() => UpdatePackageConfig.ParseMemoryNumber("-1", true));
  });

  Test("Hashed image: SHA256 prefix, FF fill, 32-byte tail, MAC and size bounds", () =>
  {
    var config = new FirmwareConfig(key, integrityKey, 0x08003000, 257, "DEVICE");
    var builder = new FirmwareBuilder();
    var (image, hash) = builder.BuildFirmwareV2(binary, config);
    Assert(image.Length == 257 && image.AsSpan(0, binary.Length).SequenceEqual(binary), "Image placement.");
    Assert(image.AsSpan(binary.Length, 225 - binary.Length).ToArray().All(b => b == 255), "Missing FF fill.");
    Assert(hash.SequenceEqual(SHA256.HashData(binary)[..16]), "Wrong input binary hash.");
    Assert(image.AsSpan(225, 16).SequenceEqual(hash), "Hash layout.");
    Assert(builder.BuildFirmwareV2(Encoding.ASCII.GetBytes("abc"), config).Hash
      .SequenceEqual(Convert.FromHexString("BA7816BF8F01CFEA414140DE5DAE2223")), "Known SHA256 truncation vector.");
    CheckMac(image, integrityKey);
    image[225] ^= 1;
    byte[] changedMac = new byte[16];
    Poly1305.ComputeMac(integrityKey, image.AsSpan(0, image.Length - 16), changedMac);
    Assert(!image.AsSpan(image.Length - 16).SequenceEqual(changedMac), "Hash is not protected by MAC.");
    builder.BuildFirmwareV2(new byte[225], config);
    Reject(() => builder.BuildFirmwareV2(new byte[226], config));
    var larger = new FirmwareConfig(integrityKey, key, 0x08004000, 512, "OTHER");
    Assert(builder.BuildFirmwareV2(binary, larger).Hash.SequenceEqual(hash), "Hash depends on keys, placement or filler.");
    byte[] changedBinary = (byte[])binary.Clone();
    changedBinary[0] ^= 1;
    Assert(!builder.BuildFirmwareV2(changedBinary, config).Hash.SequenceEqual(hash), "Binary change did not affect hash.");
    Reject(() => new FirmwareConfig(key, integrityKey, uint.MaxValue - 100, 257, "DEVICE"));
    Reject(() => new FirmwareConfig(key, integrityKey, 0, 0, "DEVICE"));
  });

  Test("V1 CLI and old XML: no version tail, encrypted header and data, SHA256", () =>
  {
    string legacy = Path.Combine(work, "legacy.xml");
    new XDocument(new XElement("FirmwareConfig", new XElement("EncryptionKey", hexKey),
      new XElement("IntegrityKey", hexIntegrity), new XElement("FlashStartAddress", "0x08003000"),
      new XElement("FlashSize", "257"), new XElement("DeviceID", "DEVICE"))).Save(legacy);
    string output = Path.Combine(fixturePath, "v1.xbin");
    Assert(Generator.Main(["build", "-bin", Path.Combine(work, "root.bin"), "-config", legacy, "-out", output]) == 0, "V1 CLI failed.");
    var lines = File.ReadAllLines(output);
    Assert(lines[0] == "#POLYBOOT;PROTO=1;FORMAT=1", "V1 text header.");
    CheckHash(lines);
    byte[] plainHeader = Decrypt(lines[1], key, out uint length, out int headerSize);
    Assert(length == 257 && headerSize == 128 && Encoding.UTF8.GetString(plainHeader).TrimEnd('\0') == "DEVICE", "V1 header.");
    var image = new List<byte>();
    for (int i = 2; i < lines.Length - 1; i++)
    {
      byte[] plain = Decrypt(lines[i], key, out uint address, out int count);
      Assert(address == 0x08003000 + image.Count, "V1 addresses.");
      image.AddRange(plain[..count]);
    }
    Assert(image.Count == 257 && image.Skip(binary.Length).Take(241 - binary.Length).All(b => b == 255), "V1 tail changed.");
    CheckMac(image.ToArray(), integrityKey);
  });

  foreach (bool complex in new[] { false, true })
    Test(complex ? "V2 COMPLEX, independent slave keys and hashes" : "V2 SINGLE, relative paths and full encrypted image", () =>
    {
      var package = Load(Package(complex));
      string output = Path.Combine(fixturePath, complex ? "complex.xbin" : "single.xbin");
      UpdatePackageBuilder.Build(package, output);
      var lines = File.ReadAllLines(output);
      CheckHash(lines);
      Assert(lines[0].Contains(complex ? "TYPE=COMPLEX" : "TYPE=SINGLE") && lines[1] == "#REM Test package", "Global metadata.");
      int pos = 2;
      foreach (var firmware in package.Firmwares)
        Assert(lines[pos++] == $"#REM {firmware.Target.ToString().ToUpperInvariant()} ID=\"{firmware.Config.DeviceID}\" VERSION={firmware.Version}", "Missing informational version comment.");
      foreach (var firmware in package.Firmwares)
      {
        byte[] input = File.ReadAllBytes(firmware.BinaryPath);
        byte[] expectedHash = SHA256.HashData(input)[..16];
        string metadata = lines[pos++];
        Assert(metadata.Contains($";HASH={Convert.ToHexString(expectedHash)};") && !metadata.Contains(";VER="), "Metadata hash.");
        byte[] plainHeader = Decrypt(lines[pos++], firmware.Config.EncryptionKey, out uint size, out _);
        Assert(size == firmware.Config.FlashSize, "Header image length.");
        Assert(Encoding.UTF8.GetString(plainHeader).TrimEnd('\0') == firmware.Config.DeviceID, "Header DeviceID.");
        var image = new List<byte>();
        while (pos < lines.Length - 1 && !lines[pos].StartsWith('#'))
        {
          byte[] plain = Decrypt(lines[pos++], firmware.Config.EncryptionKey, out uint address, out int count);
          Assert(address == firmware.Config.FlashStartAddress + image.Count, "Chunk address.");
          Assert(count == Math.Min(128, (int)size - image.Count), "Final chunk length.");
          Assert(plain.Skip(count).All(b => b == 0), "Chunk encryption padding.");
          image.AddRange(plain[..count]);
        }
        byte[] actual = image.ToArray();
        Assert(actual.Length == size, "Full AppLength was not emitted.");
        Assert(actual.AsSpan(0, input.Length).SequenceEqual(input), "Decoded binary differs.");
        Assert(actual.AsSpan(input.Length, actual.Length - 32 - input.Length).ToArray().All(b => b == 255), "Decoded FF filler differs.");
        Assert(actual.AsSpan(actual.Length - 32, 16).SequenceEqual(expectedHash), "Metadata/tail hash mismatch.");
        CheckMac(actual, firmware.Config.IntegrityKey);
      }
      Assert(pos == lines.Length - 1, "Unexpected section content.");
      Assert(Generator.Main(["build-v2", "-config", configPath]) == 0 && File.Exists(Path.Combine(work, "dist", "update.xbin")), "XML-relative output.");
    });

  Test("VersionHeader is optional independently for each firmware", () =>
  {
    foreach (bool complex in new[] { false, true })
    {
      var doc = Package(complex);
      foreach (var section in doc.Root!.Elements("Firmware")) section.Element("VersionHeader")!.Remove();
      var package = Load(doc);
      Assert(package.Firmwares.All(f => f.VersionHeaderPath == null && f.Version == null), "Version default must be absent.");
      var snapshot = Snapshot(package, "without-version");
      Assert(snapshot.Lines.Count(line => line.StartsWith("#REM")) == 1 && !snapshot.Lines.Any(line => line.Contains("VERSION=")), "Unexpected version comment.");
      foreach (var pair in snapshot.Images.Zip(package.Firmwares)) CheckMac(pair.First, pair.Second.Config.IntegrityKey);

      // Add a header to ROOT only: no version information may be invented for SLAVE.
      if (complex)
      {
        doc.Root.Elements("Firmware").Single(f => (string?)f.Attribute("Target") == "ROOT").Add(new XElement("VersionHeader", "FWVersion.h"));
        var mixed = Snapshot(Load(doc), "mixed-version");
        Assert(mixed.Lines.Count(line => line.StartsWith("#REM") && line.Contains("VERSION=")) == 1, "Wrong mixed version comments.");
        Assert(mixed.Lines.Contains("#REM ROOT ID=\"DEVICE; MAIN\" VERSION=258.772.1286"), "Missing ROOT version comment.");
      }
    }
  });

  Test("Version-only edits do not change hash or image; one binary edit changes only its section", () =>
  {
    var before = Snapshot(Load(Package(true)), "before-change");
    File.WriteAllText(Path.Combine(work, "FWVersion.h"), header.Replace("772", "773"));
    var versionOnly = Snapshot(Load(Package(true)), "version-only");
    Assert(before.Hashes.SequenceEqual(versionOnly.Hashes), "Informational version changed binary hashes.");
    Assert(before.Images.Zip(versionOnly.Images).All(pair => pair.First.SequenceEqual(pair.Second)), "Informational version changed images.");
    Assert(!before.Lines.SequenceEqual(versionOnly.Lines) && versionOnly.Lines.Any(l => l.Contains("VERSION=258.773.1286")), "Version comment not updated.");
    File.WriteAllText(Path.Combine(work, "FWVersion.h"), header);
    File.WriteAllBytes(Path.Combine(work, "slave.bin"), [1, 2, 4]);
    var changedSlave = Snapshot(Load(Package(true)), "changed-slave");
    Assert(before.Hashes[0] != changedSlave.Hashes[0] && before.Hashes[1] == changedSlave.Hashes[1], "Unchanged ROOT hash was affected.");
    Assert(!before.Images[0].SequenceEqual(changedSlave.Images[0]) && before.Images[1].SequenceEqual(changedSlave.Images[1]), "Unchanged ROOT image was affected.");
    File.WriteAllBytes(Path.Combine(work, "slave.bin"), [1, 2, 3]);
  });

  Test("Reject invalid sections, keys, paths, memory and metadata", () =>
  {
    Action<XDocument>[] changes =
    [
      d => d.Root!.Add(new XElement(d.Root.Element("Firmware")!)),
      d => d.Root!.Element("Firmware")!.SetAttributeValue("Target", "SLAVE"),
      d => d.Root!.SetAttributeValue("Type", "COMPLEX"),
      d => d.Root!.Element("Firmware")!.Element("Keys")!.Element("EncryptionKey")!.Value = "AB",
      d => d.Root!.Element("Firmware")!.Element("Keys")!.Element("IntegrityKey")!.Value = new string('Z', 64),
      d => d.Root!.Element("Firmware")!.Element("Binary")!.Value = "missing.bin",
      d => d.Root!.Element("Firmware")!.Element("VersionHeader")!.Value = "missing.h",
      d => d.Root!.Element("Firmware")!.Element("VersionHeader")!.Value = "",
      d => d.Root!.Element("Firmware")!.Add(new XElement("VersionHeader", "FWVersion.h")),
      d => d.Root!.Element("Firmware")!.Element("Memory")!.Element("AppLength")!.Value = "32",
      d => d.Root!.Element("Firmware")!.Element("Memory")!.Element("AppLength")!.Value = "128",
      d => d.Root!.Element("Firmware")!.Element("Memory")!.Element("AppBegin")!.Value = "0xFFFFFFF0",
      d => d.Root!.Element("Firmware")!.Element("DeviceId")!.Value = new string('A', 33),
      d => d.Root!.Element("Firmware")!.Element("DeviceId")!.Value = "устройство",
      d => d.Root!.Element("Firmware")!.Element("DeviceId")!.Value = "BAD\"ID",
      d => d.Root!.Element("Firmware")!.Element("BootloaderVersion")!.Value = "1",
      d => d.Root!.Element("MinUpdaterVersion")!.Value = "1.0.65536",
      d => d.Root!.Add(new XElement("Comment", "Non-ASCII: я")),
      d => d.Root!.Element("Firmware")!.Add(new XElement("Unknown", "value")),
      d => d.Root!.Element("Firmware")!.Add(new XElement("Binary", "root.bin")),
      d => d.Root!.SetAttributeValue("SchemaVersion", "2")
    ];
    foreach (var change in changes)
    {
      var doc = Package();
      change(doc);
      Reject(() => Load(doc));
    }
    var duplicateId = Package(true);
    duplicateId.Root!.Elements("Firmware").First().Element("DeviceId")!.Value = "DEVICE; MAIN";
    Reject(() => Load(duplicateId));
    var noProxy = Package(true);
    noProxy.Root!.Elements("Firmware").Single(f => (string?)f.Attribute("Target") == "ROOT").Element("ProxyVersion")!.Remove();
    Reject(() => Load(noProxy));
    var singleWithSlave = Package(true);
    singleWithSlave.Root!.SetAttributeValue("Type", "SINGLE");
    Reject(() => Load(singleWithSlave));
  });

  Test("CLI failures preserve existing output and inputs", () =>
  {
    Load(Package());
    string output = Path.Combine(work, "dist", "update.xbin");
    File.WriteAllText(output, "previous output");
    File.WriteAllBytes(Path.Combine(work, "root.bin"), new byte[226]);
    Assert(Generator.Main(["build-v2", "-config", configPath]) != 0, "Oversize CLI exit code.");
    Assert(File.ReadAllText(output) == "previous output", "Existing output was damaged.");
    File.WriteAllBytes(Path.Combine(work, "root.bin"), binary);
    Assert(Generator.Main(["build-v2", "-config", configPath, "-out", configPath]) != 0, "Input overwrite allowed.");
    UpdatePackageConfig.Load(configPath);
    Assert(Generator.Main(["build-v2", "-config"]) != 0, "Missing option value accepted.");
    Assert(Generator.Main(["build-v2", "-config", configPath, "-unknown", "x"]) != 0, "Unknown option accepted.");
    Assert(Generator.Main(["build-v2", "-config", configPath, "-config", configPath]) != 0, "Duplicate option accepted.");
    Assert(!Directory.GetFiles(Path.Combine(work, "dist"), "*.tmp").Any(), "Temporary output leaked.");
  });

  Test("Legacy genconfig still exports matching key include", () =>
  {
    string path = Path.Combine(work, "generated.xml");
    Assert(Generator.Main(["genconfig", "-out", path, "-flash", "0x08003000", "-size", "257", "-devid", "DEVICE"]) == 0, "genconfig failed.");
    var config = new FirmwareConfig(path);
    Assert(config.EncryptionKey.Length == 32 && config.IntegrityKey.Length == 32 && File.Exists(Path.ChangeExtension(path, ".inc")), "genconfig artifacts.");
  });

  Console.WriteLine($"All {passed} checks passed. Fixtures: {fixturePath}");
  return 0;
}
catch (Exception ex)
{
  Console.Error.WriteLine(ex);
  return 1;
}
finally
{
  Directory.Delete(work, recursive: true);
}
