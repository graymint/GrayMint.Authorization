using GrayMint.Authorization.Authentications.Controllers.Controllers;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace GrayMint.Authorization.Authentications.Controllers;

// An endpoint the service's settings rule out isn't there, and its API description doesn't list it: Google's sign-in
// can't work without an identity provider named Google, and a user's own API key is refused without AllowUserApiKey.
// Decided when the service starts.
internal class AuthenticationActionConvention(GrayMintAuthenticationOptions authenticationOptions)
    : IApplicationModelConvention
{
    private static readonly IReadOnlyList<string> GoogleSignInActions = [
        nameof(AuthenticationController.GoogleSignInHandler),
        nameof(AuthenticationController.GetGoogleSignInUrl)
    ];

    private static readonly IReadOnlyList<string> UserApiKeyActions = [
        nameof(AuthenticationController.ResetCurrentUserApiKey)
    ];

    public void Apply(ApplicationModel application)
    {
        if (!HasGoogleProvider())
            RemoveActions(application, GoogleSignInActions);

        if (!authenticationOptions.AllowUserApiKey)
            RemoveActions(application, UserApiKeyActions);
    }

    private bool HasGoogleProvider() =>
        authenticationOptions.OpenIdProviders.Any(x => x.Name == GrayMintAuthenticationDefaults.GoogleProviderName);

    private static void RemoveActions(ApplicationModel application, IReadOnlyList<string> actionNames)
    {
        var authenticationControllers = application.Controllers
            .Where(x => typeof(AuthenticationController).IsAssignableFrom(x.ControllerType));

        foreach (var controller in authenticationControllers) {
            var actions = controller.Actions
                .Where(x => actionNames.Contains(x.ActionMethod.Name))
                .ToArray();

            foreach (var action in actions)
                controller.Actions.Remove(action);
        }
    }
}
