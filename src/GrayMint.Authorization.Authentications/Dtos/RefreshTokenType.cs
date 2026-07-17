using System.Text.Json.Serialization;

namespace GrayMint.Authorization.Authentications.Dtos;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RefreshTokenType
{
    None,
    Web,
    App
}