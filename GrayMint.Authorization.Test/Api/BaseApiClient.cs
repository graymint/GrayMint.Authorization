#pragma warning disable CA1822 // Mark members as static
#pragma warning disable IDE0060 // Remove unused parameter

using System.Text;

namespace GrayMint.Authorization.Test.Api;

public class BaseApiClient
{
    protected Task PrepareRequestAsync(HttpClient client, HttpRequestMessage request,
        string url, CancellationToken ct)
    {
        return Task.CompletedTask;
    }

    protected Task PrepareRequestAsync(HttpClient client, HttpRequestMessage request,
        StringBuilder urlBuilder, CancellationToken ct)
    {
        return Task.CompletedTask;
    }

    protected Task ProcessResponseAsync(HttpClient client,
        HttpResponseMessage response, CancellationToken ct)
    {
        return Task.CompletedTask;
    }


}