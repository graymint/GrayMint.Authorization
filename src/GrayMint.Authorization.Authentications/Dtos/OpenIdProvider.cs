namespace GrayMint.Authorization.Authentications.Dtos;

public class OpenIdProvider
{
    public required string Name { get; init; }
    public required string? Issuer { get; init; }
    public IReadOnlyList<string> Issuers { get; init; } = [];
    public required string Audience { get; init; }
    public IReadOnlyList<string> Audiences { get; init; } = [];
}