using System.Text.Json;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Helper;

public static class TestSettings
{
    // Reads the OPTIONAL, developer-only testsettings.local.json (gitignored; copied to the test
    // output when present). Absent file -> SQLite, which is what CI always uses.
    public static bool UseSqlite { get; } = ReadUseSqlite();

    private static bool ReadUseSqlite()
    {
        var file = Path.Combine(AppContext.BaseDirectory, "testsettings.local.json");
        if (!File.Exists(file))
            return true;

        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        return !doc.RootElement.TryGetProperty("UseSqlite", out var value) || value.GetBoolean();
    }
}
