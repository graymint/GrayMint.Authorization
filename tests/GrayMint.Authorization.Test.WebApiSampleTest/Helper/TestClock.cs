using Microsoft.Extensions.Internal;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Helper;

public class TestClock : ISystemClock
{
    public DateTimeOffset UtcNow { get; set; } = DateTimeOffset.UtcNow;
}
