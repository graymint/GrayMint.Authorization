﻿using System.Text.RegularExpressions;
using GrayMint.Authorization.Abstractions;
using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionAuthorizationRequirement>
{
    private static IEnumerable<string> ExtractRouteResourceArgs(string input)
    {
        const string pattern = @"\{([^{}]+)\}";
        var matches = Regex.Matches(input, pattern);

        foreach (Match match in matches)
            yield return match.Groups[1].Value;
    }

    private static string BuildResourceByRouteData(HttpContext httpContext, string resourceRoute)
    {
        var args = ExtractRouteResourceArgs(resourceRoute);
        foreach (var arg in args)
        {
            var argValue = httpContext.GetRouteValue(arg) as string;
            if (string.IsNullOrEmpty(argValue)) argValue = AuthorizationConstants.RootResourceId;
            resourceRoute = resourceRoute.Replace("{" + arg + "}", argValue);
        }

        return resourceRoute;
    }
    public static string GetResourceId(object? resource, string? resourceRoute)
    {
        if (resource is string permissionResource)
            return permissionResource;

        if (resource is HttpContext httpContext)
            return BuildResourceByRouteData(httpContext, resourceRoute ?? AuthorizationConstants.RootResourceId);

        return AuthorizationConstants.RootResourceId;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionAuthorizationRequirement requirement)
    {
        try
        {
            // get resource id 
            var resourceId = GetResourceId(context.Resource, requirement.ResourceRoute);
            var requiredClaim = PermissionAuthorization.BuildPermissionClaim(resourceId, requirement.Permission);
            var requiredRootClaim = PermissionAuthorization.BuildPermissionClaim(AuthorizationConstants.RootResourceId, requirement.Permission);

            // check user has requiredClaim
            var succeeded =
                context.User.Claims.Any(x => x.Type == requiredClaim.Type && x.Value == requiredClaim.Value) ||
                context.User.Claims.Any(x => x.Type == requiredRootClaim.Type && x.Value == requiredRootClaim.Value);

            // result
            if (succeeded)
                context.Succeed(requirement);
            else
                context.Fail(new AuthorizationFailureReason(this, "Access forbidden."));

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            context.Fail(new AuthorizationFailureReason(this, ex.Message));
            return Task.CompletedTask;
        }
    }
}