using GrayMint.Authorization.OpenIdAuthentications;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Tests;

// A mistake in the settings would only show at the first request, as tokens that are all refused: the
// service doesn't start with one.
[TestClass]
public class OptionsTest
{
    [TestMethod]
    public void GoodOptionsPass()
    {
        Create(CreateProvider("main", "https://id.example.com/")).Validate();
    }

    [TestMethod]
    public void ServiceNeedsAProvider()
    {
        Assert.Throws<InvalidOperationException>(() => new OpenIdAuthenticationOptions().Validate());
    }

    [TestMethod]
    [DataRow("", "https://id.example.com/", "files")]
    [DataRow("main", "id.example.com", "files")]
    [DataRow("main", "http://id.example.com/", "files")]
    [DataRow("main", "https://id.example.com/", "")]
    public void ProviderNeedsANameAnHttpsIssuerAndAnAudience(string name, string issuer, string audience)
    {
        var provider = new OpenIdProviderOptions { Name = name, Issuer = issuer, Audience = audience };
        Assert.Throws<InvalidOperationException>(() => Create(provider).Validate());
    }

    [TestMethod]
    public void PlainHttpIssuerIsForADevelopersMachine()
    {
        var provider = new OpenIdProviderOptions {
            Name = "main", Issuer = "http://localhost:5280/", Audience = "files", AllowInsecureHttp = true
        };

        Create(provider).Validate();
    }

    // Two providers under one name would share their users, and one issuer under two names would have its
    // accounts tied twice.
    [TestMethod]
    public void ProviderAndIssuerAreNamedOnce()
    {
        Assert.Throws<InvalidOperationException>(() => Create(
            CreateProvider("main", "https://id.example.com/"),
            CreateProvider("main", "https://other.example.com/")).Validate());

        Assert.Throws<InvalidOperationException>(() => Create(
            CreateProvider("main", "https://id.example.com/"),
            CreateProvider("other", "https://id.example.com/")).Validate());
    }

    [TestMethod]
    public void ProviderNeedsAWayItSignsAndNoEmptyApplication()
    {
        var noAlgorithm = new OpenIdProviderOptions {
            Name = "main", Issuer = "https://id.example.com/", Audience = "files", Algorithms = []
        };

        Assert.Throws<InvalidOperationException>(() => Create(noAlgorithm).Validate());

        var emptyClient = new OpenIdProviderOptions {
            Name = "main", Issuer = "https://id.example.com/", Audience = "files", ClientIds = ["app", ""]
        };

        Assert.Throws<InvalidOperationException>(() => Create(emptyClient).Validate());
    }

    [TestMethod]
    public void CacheTimeoutIsMoreThanNothing()
    {
        var options = new OpenIdAuthenticationOptions {
            Providers = [CreateProvider("main", "https://id.example.com/")],
            CacheTimeout = TimeSpan.Zero
        };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    private static OpenIdProviderOptions CreateProvider(string name, string issuer)
    {
        return new OpenIdProviderOptions { Name = name, Issuer = issuer, Audience = "files", ClientIds = ["app"] };
    }

    private static OpenIdAuthenticationOptions Create(params IReadOnlyList<OpenIdProviderOptions> providers)
    {
        return new OpenIdAuthenticationOptions { Providers = providers };
    }
}
