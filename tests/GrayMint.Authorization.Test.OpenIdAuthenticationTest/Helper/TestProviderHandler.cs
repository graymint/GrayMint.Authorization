using System.Net;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

// Every request the service means for a provider ends here: no test reaches the network.
public sealed class TestProviderHandler(IReadOnlyList<TestProvider> providers) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var address = request.RequestUri ?? throw new InvalidOperationException("The request has no address.");
        var response = providers.Select(x => x.Answer(address)).FirstOrDefault(x => x != null) ??
                       new HttpResponseMessage(HttpStatusCode.NotFound);
        return Task.FromResult(response);
    }
}
