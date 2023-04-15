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

    public Task<AuthenticationHeaderValue> CreateAuthenticationHeader(string subject, string email)
    {
        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, subject));
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));
        return CreateAuthenticationHeader(claimsIdentity);
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(ClaimsIdentity claimsIdentity)
    {
        // get authcode by standard claim
        var nameClaim = claimsIdentity.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub);
        if (nameClaim != null) claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameClaim.Value));

        var emailClaim = claimsIdentity.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email);
        if (emailClaim != null) claimsIdentity.AddClaim(new Claim(ClaimTypes.Email, emailClaim.Value));

        var authorizationCode = await _authenticationProvider.GetAuthorizationCode(new ClaimsPrincipal(claimsIdentity));
        if (string.IsNullOrEmpty(authorizationCode))
            throw new Exception("Could not get the AuthorizationCode.");

        claimsIdentity.AddClaim(new Claim(BotAuthenticationDefaults.AuthorizationCodeTypeName, authorizationCode));

        // create jwt
        var audience = string.IsNullOrEmpty(_botAuthenticationOptions.BotAudience) ? _botAuthenticationOptions.BotIssuer : _botAuthenticationOptions.BotAudience;
        var jwt = JwtUtil.CreateSymmetricJwt(
            _botAuthenticationOptions.BotKey,
            _botAuthenticationOptions.BotIssuer,
            audience,
            null, //read from claims,
            null,
            claimsIdentity.Claims.ToArray());

        return new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, jwt);
    }

}