using GrayMint.Authorization.Abstractions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;

namespace GrayMint.Authorization.Authentications.Utils;

public static class ClaimUtil
{
    public static void AddClaim(ClaimsIdentity source, ClaimsIdentity destination, string sourceType,
        string? destinationType = null, string? destinationValueType = null, bool replace = true)
    {
        foreach (var claim in source.Claims.Where(x => x.Type == sourceType))
            destination.AddClaim(new Claim(destinationType ?? sourceType, claim.Value, destinationValueType ?? claim.ValueType));

        if (replace)
            RemoveClaims(destination, sourceType);
    }

    public static void RemoveClaims(ClaimsIdentity claimsIdentity, string claimType)
    {
        var claimsToRemove = claimsIdentity.FindAll(claimType).ToArray();
        foreach (var claim in claimsToRemove)
            claimsIdentity.TryRemoveClaim(claim);
    }

    public static void SetClaim(ClaimsIdentity claimsIdentity, Claim claim)
    {
        RemoveClaims(claimsIdentity, claim.Type);
        claimsIdentity.AddClaim(claim);
    }

    public static DateTime? GetUtcTime(ClaimsIdentity claimsIdentity, string type)
    {
        var linuxTime = claimsIdentity.FindFirst(type)?.Value;
        return linuxTime != null
            ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(linuxTime)).UtcDateTime
            : null;
    }

    public static DateTime GetRequiredUtcTime(ClaimsIdentity claimsIdentity, string type)
    {
        return GetUtcTime(claimsIdentity, type)
            ?? throw new AuthenticationException($"Could not find {type} claim.");
    }

    public static string GetRequiredClaimString(ClaimsIdentity claimsIdentity, string type)
    {
        return claimsIdentity.FindFirst(GrayMintClaimTypes.RefreshTokenType)?.Value
            ?? throw new AuthenticationException($"Could not find {type} claim.");
    }

    public static Claim CreateClaimTime(string type, DateTime value)
    {
        var unixTime = ((DateTimeOffset)value).ToUnixTimeSeconds();
        return new Claim(type, unixTime.ToString(), ClaimValueTypes.Integer64);
    }

    public static ClaimsPrincipal CreateClaimsPrincipal(ClaimsIdentity claimsIdentity)
    {
        var destination = claimsIdentity.Clone();
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.Sub, ClaimTypes.NameIdentifier);
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.Email, ClaimTypes.Email);
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.GivenName, ClaimTypes.GivenName);
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.FamilyName, ClaimTypes.Surname);
        return new ClaimsPrincipal(destination);
    }
}