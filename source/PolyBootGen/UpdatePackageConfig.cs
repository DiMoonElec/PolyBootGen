using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace PolyBootGen
{
  public enum FirmwareTarget { Root, Slave }
  public enum PackageType { Single, Complex }

  public sealed record PackageFirmware(FirmwareTarget Target, FirmwareConfig Config,
    string BinaryPath, string? VersionHeaderPath, FirmwareVersion? Version,
    int BootloaderVersion, int? ProxyVersion);

  public sealed record UpdatePackageConfig(string ConfigPath, string OutputPath,
    PackageType Type, FirmwareVersion MinUpdaterVersion,
    IReadOnlyList<string> Comments, IReadOnlyList<PackageFirmware> Firmwares)
  {
    public static UpdatePackageConfig Load(string path)
    {
      path = Path.GetFullPath(path);
      var doc = XDocument.Load(path, LoadOptions.SetLineInfo);
      var root = doc.Root ?? throw new InvalidDataException("Empty package config.");
      if (root.Name != "UpdatePackage")
        throw Error(root, "Expected <UpdatePackage> root.");
      CheckShape(root, ["Output", "MinUpdaterVersion", "Comment", "Firmware"], ["SchemaVersion", "Format", "Type"]);
      if (Attribute(root, "SchemaVersion") != "1" || Attribute(root, "Format") != "2")
        throw Error(root, "Expected SchemaVersion=\"1\" and Format=\"2\".");
      var type = Attribute(root, "Type").ToUpperInvariant() switch
      {
        "SINGLE" => PackageType.Single,
        "COMPLEX" => PackageType.Complex,
        _ => throw Error(root, "Type must be SINGLE or COMPLEX.")
      };
      string basePath = Path.GetDirectoryName(path)!;
      string Resolve(string value) => Path.GetFullPath(value, basePath);
      string output = Resolve(Value(root, "Output"));
      var minimum = FirmwareVersion.Parse(Value(root, "MinUpdaterVersion"));
      var comments = root.Elements("Comment").Select(e =>
      {
        CheckShape(e, [], []);
        string comment = e.Value.Trim();
        RequireAscii(comment, e, "Comment");
        return comment;
      }).ToArray();

      var firmwares = new List<PackageFirmware>();
      foreach (var element in root.Elements("Firmware"))
      {
        try
        {
          CheckShape(element, ["DeviceId", "BootloaderVersion", "ProxyVersion", "Binary", "VersionHeader", "Memory", "Keys"], ["Target"]);
          var target = Attribute(element, "Target").ToUpperInvariant() switch
          {
            "ROOT" => FirmwareTarget.Root,
            "SLAVE" => FirmwareTarget.Slave,
            _ => throw Error(element, "Target must be ROOT or SLAVE.")
          };
          string id = Value(element, "DeviceId");
          RequireAscii(id, element, "DeviceId");
          if (id.Length > 32 || id.Contains('"'))
            throw Error(element, "DeviceId must contain 1..32 ASCII characters without double quotes.");
          int bootloader = PositiveInt(Value(element, "BootloaderVersion"));
          if (bootloader < 2)
            throw Error(element, "FORMAT=2 requires BootloaderVersion >= 2.");
          var proxyElement = One(element, "ProxyVersion", false);
          int? proxy = proxyElement == null ? null : PositiveInt(Value(element, "ProxyVersion"));
          if (target == FirmwareTarget.Slave && proxy.HasValue)
            throw Error(element, "ProxyVersion is only allowed for ROOT.");

          var memory = One(element, "Memory")!;
          CheckShape(memory, ["AppBegin", "AppLength"], []);
          uint begin = ParseMemoryNumber(Value(memory, "AppBegin"), false);
          uint length = ParseMemoryNumber(Value(memory, "AppLength"), true);
          if (length <= FirmwareBuilder.V2TailSize)
            throw Error(memory, "AppLength must exceed the 32-byte hash and MAC tail.");
          var keys = One(element, "Keys")!;
          CheckShape(keys, ["EncryptionKey", "IntegrityKey"], []);
          byte[] encryptionKey = ReadKey(Value(keys, "EncryptionKey"));
          byte[] integrityKey = ReadKey(Value(keys, "IntegrityKey"));
          var config = new FirmwareConfig(encryptionKey, integrityKey, begin, length, id);
          string binary = Resolve(Value(element, "Binary"));
          string? header = One(element, "VersionHeader", false) == null
            ? null : Resolve(Value(element, "VersionHeader"));
          if (!File.Exists(binary))
            throw Error(element, $"Binary not found: {binary}");
          if (header != null && !File.Exists(header))
            throw Error(element, $"Version header not found: {header}");
          FirmwareVersion? version = header == null ? null : FirmwareVersion.ReadHeader(header);
          long binarySize = new FileInfo(binary).Length;
          if (binarySize == 0 || binarySize > length - FirmwareBuilder.V2TailSize)
            throw Error(element, $"Binary must contain 1..{length - FirmwareBuilder.V2TailSize} bytes; actual size: {binarySize}.");
          firmwares.Add(new PackageFirmware(target, config, binary, header, version, bootloader, proxy));
        }
        catch (Exception ex) when (ex is InvalidDataException or FormatException or OverflowException)
        {
          if (ex is InvalidDataException && ex.Message.StartsWith('<')) throw;
          throw Error(element, ex.Message);
        }
      }
      if (firmwares.Count(f => f.Target == FirmwareTarget.Root) != 1)
        throw Error(root, "Package must contain exactly one ROOT firmware.");
      if (firmwares.Select(f => f.Config.DeviceID).Distinct(StringComparer.Ordinal).Count() != firmwares.Count)
        throw Error(root, "DeviceId must be unique across all firmware sections (case sensitive).");
      if (type == PackageType.Single && firmwares.Count != 1)
        throw Error(root, "SINGLE must contain only one ROOT firmware.");
      if (type == PackageType.Complex && (firmwares.Count < 2 ||
          !firmwares.Single(f => f.Target == FirmwareTarget.Root).ProxyVersion.HasValue))
        throw Error(root, "COMPLEX requires at least one SLAVE and ProxyVersion on ROOT.");
      return new UpdatePackageConfig(path, output, type, minimum, comments, firmwares.AsReadOnly());
    }

    public static uint ParseMemoryNumber(string value, bool allowKilobytes)
    {
      uint multiplier = 1;
      if (allowKilobytes && value.EndsWith("K", StringComparison.OrdinalIgnoreCase))
      {
        multiplier = 1024;
        value = value[..^1].TrimEnd();
      }
      bool hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
      uint number = uint.Parse(hex ? value[2..] : value,
        hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None, CultureInfo.InvariantCulture);
      return checked(number * multiplier);
    }

    private static int PositiveInt(string value)
    {
      int result = int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
      if (result < 1) throw new InvalidDataException("Protocol versions must be positive integers.");
      return result;
    }

    private static byte[] ReadKey(string value)
    {
      if (value.Length != 64)
        throw new InvalidDataException("Each key must contain exactly 64 hexadecimal characters (32 bytes).");
      try { return Convert.FromHexString(value); }
      catch (FormatException) { throw new InvalidDataException("Keys must contain hexadecimal characters only."); }
    }

    private static void RequireAscii(string value, XElement element, string field)
    {
      if (value.Any(c => c < 32 || c > 126))
        throw Error(element, $"{field} must contain printable ASCII characters on a single line.");
    }

    private static string Attribute(XElement element, string name)
      => (string?)element.Attribute(name) is string value && !string.IsNullOrWhiteSpace(value)
        ? value.Trim() : throw Error(element, $"Missing attribute {name}.");

    private static string Value(XElement parent, string name)
    {
      var element = One(parent, name)!;
      CheckShape(element, [], []);
      return !string.IsNullOrWhiteSpace(element.Value) ? element.Value.Trim()
        : throw Error(element, $"{name} must not be empty.");
    }

    private static XElement? One(XElement parent, string name, bool required = true)
    {
      var elements = parent.Elements(name).ToArray();
      if (elements.Length > 1 || (required && elements.Length == 0))
        throw Error(parent, $"Expected {(required ? "exactly one" : "at most one")} <{name}>.");
      return elements.SingleOrDefault();
    }

    private static void CheckShape(XElement element, string[] children, string[] attributes)
    {
      if (element.Elements().Any(e => !children.Contains(e.Name.ToString())) ||
          element.Attributes().Any(a => !attributes.Contains(a.Name.ToString())))
        throw Error(element, "Unknown XML element or attribute.");
    }

    private static InvalidDataException Error(XElement element, string message)
      => new($"<{element.Name}> line {((IXmlLineInfo)element).LineNumber}: {message}");
  }
}
