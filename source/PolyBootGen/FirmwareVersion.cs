using System.Globalization;
using System.Text.RegularExpressions;

namespace PolyBootGen
{
  public readonly record struct FirmwareVersion(ushort Major, ushort Minor, ushort Patch)
  {
    public override string ToString() => $"{Major}.{Minor}.{Patch}";

    public static FirmwareVersion Parse(string text)
    {
      var parts = text.Split('.');
      if (parts.Length != 3 || parts.Any(p => !Regex.IsMatch(p, @"\A[0-9]+\z") ||
          !ushort.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
        throw new InvalidDataException($"Invalid version '{text}': expected three integers in 0..65535.");
      return new FirmwareVersion(ushort.Parse(parts[0], CultureInfo.InvariantCulture),
        ushort.Parse(parts[1], CultureInfo.InvariantCulture), ushort.Parse(parts[2], CultureInfo.InvariantCulture));
    }

    public static FirmwareVersion ReadHeader(string path)
    {
      string source = File.ReadAllText(path);
      // Preserve line boundaries when removing C comments.
      source = Regex.Replace(source, @"/\*.*?\*/|//[^\r\n]*",
        m => " " + new string('\n', m.Value.Count(c => c == '\n')), RegexOptions.Singleline);
      var lines = source.Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).ToList();
      if (lines.Count >= 3)
      {
        var guard = Regex.Match(lines[0], @"\A#[ \t]*ifndef[ \t]+([A-Za-z_][A-Za-z0-9_]*)\z");
        if (guard.Success && Regex.IsMatch(lines[1], @"\A#[ \t]*define[ \t]+" + guard.Groups[1].Value + @"\z") &&
            Regex.IsMatch(lines[^1], @"\A#[ \t]*endif\z"))
          lines = lines.Skip(2).Take(lines.Count - 3).ToList();
      }
      source = string.Join('\n', lines);
      if (Regex.IsMatch(source, @"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif|undef)\b", RegexOptions.Multiline))
        throw new InvalidDataException($"{path}: conditional version headers are not supported (an #ifndef include guard is allowed).");

      ushort Read(string name)
      {
        var matches = Regex.Matches(source, @"^[ \t]*#[ \t]*define[ \t]+" + name + @"\b([^\r\n]*)", RegexOptions.Multiline);
        if (matches.Count != 1)
          throw new InvalidDataException($"{path}: expected exactly one #define {name}.");
        string value = matches[0].Groups[1].Value.Trim();
        if (!Regex.IsMatch(value, @"\A[0-9]+\z") ||
            !ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ushort number))
          throw new InvalidDataException($"{path}: {name} must be a decimal integer in 0..65535.");
        return number;
      }

      return new FirmwareVersion(Read("FW_VERSION_MAJOR"), Read("FW_VERSION_MINOR"), Read("FW_VERSION_PATCH"));
    }
  }
}
