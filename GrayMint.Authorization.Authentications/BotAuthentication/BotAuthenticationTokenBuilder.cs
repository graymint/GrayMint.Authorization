using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications.BotAuthentication;

public class BotAuthenticationTokenBuilder
{
    private readonly IAuthorizationProvider _authenticationProvider;
    private readonly BotAuthenticationOptions _botAuthenticationOptions;

    public BotAuthenticationTokenBuilder(IAuthorizationProvider authenticationProvider, IOptions<BotAuthenticationOptions> botAuthenticationOptions)
    {
        _authenticationProvider = authenticationProvider;
        _botAuthenticationOptions = botAuthenticationOptions.Value;
    }

    public Task<AuthenticationHeaderValue> CreateAuthenticationHeader(string subject, string email, DateTime? expirationTime = null)
    {
        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, subject));
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));
        return CreateAuthenticationHeader(claimsIdentity, expirationTime);
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(ClaimsIdentity claimsIdentity, DateTime? expirationTime = null)
    {
        // get authcode by transforming jwt claim to .net claim
        var tempIdentity = claimsIdentity.Clone();
        var nameClaim = tempIdentity.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub);
        if (nameClaim != null) tempIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameClaim.Value));

        var emailClaim = tempIdentity.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email);
        if (emailClaim != null) tempIdentity.AddClaim(new Claim(ClaimTypes.Email, emailClaim.Value));

        var authorizationCode = await _authenticationProvider.GetAuthorizationCode(new ClaimsPrincipal(tempIdentity));
        if (string.IsNullOrEmpty(authorizationCode))
            throw new Exception("Could not get the AuthorizationCode.");

        // add authorization code to claim
        claimsIdentity.AddClaim(new Claim(BotAuthenticationDefaults.AuthorizationCodeTypeName, authorizationCode));

        // create jwt
        var audience = string.IsNullOrEmpty(_botAuthenticationOptions.BotAudience) ? _botAuthenticationOptions.BotIssuer : _botAuthenticationOptions.BotAudience;
        var jwt = JwtUtil.CreateSymmetricJwt(
            key: _botAuthenticationOptions.BotKey,
            issuer: _botAuthenticationOptions.BotIssuer,
            audience: audience,
            claims: claimsIdentity.Claims.ToArray(),
            expirationTime: expirationTime);

        return new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, jwt);
    }

}