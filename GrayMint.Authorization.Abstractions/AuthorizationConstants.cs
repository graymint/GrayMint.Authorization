﻿namespace GrayMint.Authorization.Abstractions;

public static class AuthorizationConstants
{
    public const string RootResourceId = "*";
    public const string AnyAuthCode = "*";
    public const string DatabaseSchemePrefix = "gm";
    public const string SystemUserId = "system";
    public static TimeSpan CacheTimeout { get; } = TimeSpan.FromMinutes(60);
}