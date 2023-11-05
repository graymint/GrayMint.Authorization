using System.IdentityModel.Tokens.Jwt;
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

    public static void ReplaceClaim(ClaimsIdentity claimsIdentity, Claim claim)
    {
        RemoveClaims(claimsIdentity, claim.Type);
        claimsIdentity.AddClaim(claim);
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