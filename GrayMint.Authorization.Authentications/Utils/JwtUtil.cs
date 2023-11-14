using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications.Utils;

public static class JwtUtil
{
    public static string CreateSymmetricJwt(byte[] key, string issuer, string audience, string subject,
        string email, string[]? roles)
    {
        return CreateSymmetricJwt(key, issuer, audience, subject, email, null, roles);
    }

    public static DateTime UtcNow
    {
        get
        {
            // drop milliseconds
            var utcNow = DateTime.UtcNow;   
            return new DateTime(utcNow.Year, utcNow.Month, utcNow.Day, utcNow.Hour, utcNow.Minute, utcNow.Second, DateTimeKind.Utc);    
        }
    }

    public static string CreateSymmetricJwt(byte[] key, string issuer, string audience, string? subject = null,
        string? email = null, Claim[]? claims = null, string[]? roles = null, DateTime? expirationTime = null)
    {
        var claimIdentity = new ClaimsIdentity(claims);
        ClaimUtil.SetClaim(claimIdentity, ClaimUtil.CreateClaimTime("iat", UtcNow));
        ClaimUtil.SetClaim(claimIdentity, new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        claimIdentity.TryRemoveClaim(claimIdentity.FindFirst(JwtRegisteredClaimNames.Aud));
        claimIdentity.TryRemoveClaim(claimIdentity.FindFirst(JwtRegisteredClaimNames.Iss));
        if (subject != null) ClaimUtil.SetClaim(claimIdentity, new Claim(JwtRegisteredClaimNames.Sub, subject));
        if (email != null) ClaimUtil.SetClaim(claimIdentity, new Claim(JwtRegisteredClaimNames.Email, email));
        if (roles != null) claimIdentity.AddClaims(roles.Select(x => new Claim(ClaimTypes.Role, x)));

        // add issued at time

        // create token
        var secKey = new SymmetricSecurityKey(key);
        var signingCredentials = new SigningCredentials(secKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(issuer,
            claims: claimIdentity.Claims,
            audience: audience,
            expires: expirationTime ?? JwtUtil.UtcNow.AddYears(13),
            signingCredentials: signingCredentials);

        var handler = new JwtSecurityTokenHandler();
        var ret = handler.WriteToken(token);
        return ret;
    }
}