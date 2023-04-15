using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public class JwtUtil
{
    public static string CreateSymmetricJwt(byte[] key, string issuer, string audience, string subject,
        string email, string[]? roles)
    {
        return CreateSymmetricJwt(key, issuer, audience, subject, email, null, roles);
    }

    public static string CreateSymmetricJwt(byte[] key, string issuer, string audience, string? subject = null, string? email = null,
        Claim[]? claims = null, string[]? roles = null)
    {
        var claimsList = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        if (subject != null) claimsList.Add(new Claim(JwtRegisteredClaimNames.Sub, subject));
        if (email != null) claimsList.Add(new Claim(JwtRegisteredClaimNames.Email, email));
        if (claims != null) claimsList.AddRange(claims);
        if (roles != null) claimsList.AddRange(roles.Select(x => new Claim(ClaimTypes.Role, x)));

        // create token
        var secKey = new SymmetricSecurityKey(key);
        var signingCredentials = new SigningCredentials(secKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(issuer,
            claims: claimsList.ToArray(),
            audience: audience,
            expires: DateTime.Now.AddYears(10),
            signingCredentials: signingCredentials);

        var handler = new JwtSecurityTokenHandler();
        var ret = handler.WriteToken(token);
        return ret;
    }
}