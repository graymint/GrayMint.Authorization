using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

/// <summary>
/// A resource's team: the people and bots with a role on it.
/// </summary>
/// <remarks>
/// A role gives its holder the role's permissions on the resource. Changing the team takes the permission to change
/// it, and an owner's role only an owner can give or take.
/// </remarks>
[Authorize]
[Route("/api/team")]
public abstract class TeamControllerBase<TUser, TUserRole, TRole>(TeamService teamService)
    : ControllerBase
{
    protected abstract TUser ToDto(User user);
    protected abstract TRole ToDto(Role role);
    protected abstract TUserRole ToDto(TeamUserRole user);

    /// <summary>
    /// List the resources you have a role on
    /// </summary>
    /// <returns>The resources' ids.</returns>
    [Authorize]
    [HttpGet("users/current/resources")]
    public async Task<IEnumerable<string>> ListCurrentUserResources()
    {
        var userId = await teamService.GetUserId(User);
        var userRoles = await teamService.GetUserRoles(userId: userId);
        var resourceIds = userRoles.Items
            .Select(x => x.ResourceId)
            .Distinct();

        return resourceIds;
    }

    /// <summary>
    /// List your permissions on a resource
    /// </summary>
    /// <param name="resourceId">The resource's id.</param>
    /// <returns>The permissions your roles there give you.</returns>
    [Authorize]
    [HttpGet("users/current/resources/{resourceId}/permissions")]
    public async Task<IEnumerable<string>> ListCurrentUserPermissions(string resourceId)
    {
        var userId = await teamService.GetUserId(User);
        var permissions = await teamService.GetUserPermissions(resourceId, userId);
        return permissions;
    }

    /// <summary>
    /// Give a bot a new API key
    /// </summary>
    /// <remarks>
    /// Its old key stops working at once. It takes the permission to change the team of every resource the bot has a
    /// role on.
    /// </remarks>
    /// <param name="userId">The bot's user id.</param>
    /// <returns>The bot's new API key, shown only here.</returns>
    [HttpPost("users/{userId}/bot/reset-api-key")]
    public async Task<ApiKey> ResetBotApiKey(string userId)
    {
        // a reset racing the bot's add to another resource may hand out a key with that resource's rights: no more
        // than a key reset just before the add gets, as a key acts with the bot's roles wherever it is added
        await VerifyWritePermissionOnBot(userId);
        var res = await teamService.ResetBotApiKey(userId);
        return res;
    }

    /// <summary>
    /// Rename a bot
    /// </summary>
    /// <remarks>
    /// It takes the permission to change the team of every resource the bot has a role on.
    /// </remarks>
    /// <param name="userId">The bot's user id.</param>
    /// <param name="updateParam">The bot's new name.</param>
    /// <returns>The bot.</returns>
    [HttpPatch("users/{userId}/bot")]
    public async Task<TUser> UpdateBot(string userId, TeamUpdateBotParam updateParam)
    {
        await VerifyWritePermissionOnBot(userId);
        var user = await teamService.UpdateBot(userId, updateParam);
        return ToDto(user);
    }


    /// <summary>
    /// List a resource's roles
    /// </summary>
    /// <param name="resourceId">The resource's id.</param>
    /// <returns>The roles a team member can have there.</returns>
    [HttpGet("resources/{resourceId}/roles")]
    public async Task<IEnumerable<TRole>> ListRoles(string resourceId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var roles = await teamService.GetRoles(ToResourceId(resourceId));
        return roles.Select(ToDto);
    }

    /// <summary>
    /// List a resource's team
    /// </summary>
    /// <remarks>
    /// One item for each role a member has. A person added by email shows only that email until their first request
    /// to the resource.
    /// </remarks>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="roleId">Only the members with this role.</param>
    /// <param name="userId">Only this user.</param>
    /// <param name="search">Only the users with this id, or whose first name, last name or email starts with it.</param>
    /// <param name="isBot">Only the bots, or only the people.</param>
    /// <param name="recordIndex">How many items to skip.</param>
    /// <param name="recordCount">How many items to return at most.</param>
    /// <returns>A page of the team.</returns>
    [HttpGet("resources/{resourceId}/user-roles")]
    public async Task<ListResult<TUserRole>> ListUserRoles(string resourceId,
        string? roleId = null, string? userId = null,
        string? search = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userRoles = await teamService.GetUserRoles(resourceId: ToResourceId(resourceId),
            roleId: roleId, userId: userId,
            search: search, isBot: isBot,
            recordIndex: recordIndex, recordCount: recordCount);

        var ret = new ListResult<TUserRole> {
            TotalCount = userRoles.TotalCount,
            Items = userRoles.Items.Select(ToDto).ToArray()
        };

        return ret;
    }

    /// <summary>
    /// Get a team member
    /// </summary>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="userId">The member's user id.</param>
    /// <returns>The member, with their roles on the resource.</returns>
    [HttpGet("resources/{resourceId}/users/{userId}")]
    public async Task<TeamUser<TUser, TRole>> GetUser(string resourceId, string userId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userByEmail = await teamService.GetUser(resourceId, userId);
        var ret = new TeamUser<TUser, TRole> {
            User = ToDto(userByEmail.User),
            Roles = userByEmail.Roles.Select(ToDto).ToArray()
        };

        return ret;
    }

    /// <summary>
    /// Get a team member by their email
    /// </summary>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="email">The member's email.</param>
    /// <returns>The member, with their roles on the resource.</returns>
    [HttpGet("resources/{resourceId}/users/email:{email}")]
    public async Task<TeamUser<TUser, TRole>> GetUserByEmail(string resourceId, string email)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userByEmail = await teamService.GetUserByEmail(resourceId, email);
        var ret = new TeamUser<TUser, TRole> {
            User = ToDto(userByEmail.User),
            Roles = userByEmail.Roles.Select(ToDto).ToArray()
        };

        return ret;
    }


    /// <summary>
    /// Add a bot
    /// </summary>
    /// <remarks>
    /// A new bot with the role, for a script or another service to call the API with. The service may not let a bot
    /// have an owner's role.
    /// </remarks>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="roleId">The bot's role.</param>
    /// <param name="addParam">The bot's name.</param>
    /// <returns>The bot's API key, shown only here.</returns>
    [HttpPost("resources/{resourceId}/roles/{roleId}/bots")]
    public async Task<ApiKey> AddNewBot(string resourceId, string roleId, TeamAddBotParam addParam)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        var res = await teamService.AddNewBot(ToResourceId(resourceId), roleId, addParam);
        return res;
    }

    /// <summary>
    /// Add a person by their email
    /// </summary>
    /// <remarks>
    /// They are on the team at once, with no invitation to accept, and an email with no account gets one. The team
    /// sees only the email until their first request to the resource. The role takes the place of their other roles
    /// there, unless the service lets a member have several.
    /// </remarks>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="roleId">The role to give.</param>
    /// <param name="email">The person's email.</param>
    /// <param name="addParam">Nothing yet; leave it out.</param>
    /// <returns>Their role on the resource.</returns>
    [HttpPost("resources/{resourceId}/roles/{roleId}/users/email:{email}")]
    public async Task<TUserRole> AddUserByEmail(string resourceId, string roleId, string email,
        TeamAddEmailParam? addParam = null)
    {
        _ = addParam; //reserved

        var user = await teamService.FindUserByEmail(email);
        if (user != null)
            return await AddUser(resourceId, roleId, user.UserId);

        await VerifyWritePermissionOnRole(resourceId, roleId);
        var res = await teamService.AddUserByEmail(ToResourceId(resourceId), roleId, email, User);
        return ToDto(res);
    }

    /// <summary>
    /// Give a user a role
    /// </summary>
    /// <remarks>
    /// A person or a bot with an account. The role takes the place of their other roles on the resource, unless the
    /// service lets a member have several. A bot takes the permission to change the team of every resource it has a
    /// role on.
    /// </remarks>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="roleId">The role to give.</param>
    /// <param name="userId">The user's id.</param>
    /// <returns>Their role on the resource.</returns>
    [HttpPost("resources/{resourceId}/roles/{roleId}/users/{userId}")]
    public async Task<TUserRole> AddUser(string resourceId, string roleId, string userId)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        // any user may be added to a resource, so the user needs no write check; a bot does, below
        await VerifyAppOwnerPolicy(resourceId, userId, roleId, true);

        // check write permission on bot; the answers tell no one, a bot out of reach and a person apart, left so:
        // ids are random, so only someone who shared a team with that person knows one, and saw them there
        var user = await teamService.GetUser(userId);
        if (user.IsBot)
            await VerifyWritePermissionOnBot(userId: userId);

        // the caller's rights over the roles the new one replaces are checked on the very roles it removes
        var res = await teamService.AddUser(ToResourceId(resourceId), roleId, userId, User);
        return ToDto(res);
    }

    /// <summary>
    /// Take a role away from a user
    /// </summary>
    /// <remarks>
    /// An owner can't give up their own owner's role; another owner can take it away.
    /// </remarks>
    /// <param name="resourceId">The resource's id.</param>
    /// <param name="roleId">The role to take away.</param>
    /// <param name="userId">The user's id.</param>
    [HttpDelete("resources/{resourceId}/roles/{roleId}/users/{userId}")]
    public async Task RemoveUser(string resourceId, string roleId, string userId)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        await VerifyWritePermissionOnUser(resourceId, userId);
        await VerifyAppOwnerPolicy(resourceId, userId, roleId, false);
        await teamService.RemoveUser(ToResourceId(resourceId), roleId, userId);
    }

    /// <summary>
    /// Get an API key for the service's own administration
    /// </summary>
    /// <remarks>
    /// A new bot with the system role that can change teams, from the service's secret. The service may not allow it.
    /// </remarks>
    /// <param name="secret">The service's secret, as a form field.</param>
    /// <returns>The new bot's API key, shown only here.</returns>
    [HttpPost("system/api-key")]
    [AllowAnonymous]
    public async Task<ApiKey> CreateSystemApiKey([FromForm] string secret)
    {
        var res = await teamService.CreateSystemApiKey(secret);
        return res;
    }

    private async Task VerifyWritePermissionOnBot(string userId)
    {
        // one bare 403 for all but a bot in the caller's full reach, so the answer tells nothing of a user out of
        // reach, nor whether a teammate who is no bot belongs elsewhere too
        var userRoles = await teamService.GetUserRoles(userId: userId);
        if (userRoles.Items.FirstOrDefault()?.User is not { IsBot: true })
            throw new UnauthorizedAccessException();

        // the caller needs write rights over every resource of the bot
        var resourceIds = userRoles.Items.Select(x => x.ResourceId).Distinct();
        foreach (var resId in resourceIds)
            await teamService.VerifyWritePermissionOnUser(User, resId, userId);
    }

    private static string ToResourceId(string resourceId)
    {
        return resourceId;
    }

    protected Task VerifyReadPermissionOnRole(string resourceId)
    {
        return teamService.VerifyRoleReadPermission(User, ToResourceId(resourceId));
    }

    protected Task<TeamUserRole[]> VerifyWritePermissionOnUser(string resourceId, string userId)
    {
        return teamService.VerifyWritePermissionOnUser(User, ToResourceId(resourceId), userId);
    }

    protected Task VerifyWritePermissionOnRole(string resourceId, string roleId)
    {
        return teamService.VerifyWritePermissionOnRole(User, ToResourceId(resourceId), roleId);
    }

    protected Task VerifyAppOwnerPolicy(string resourceId, string userId, string targetRoleId, bool isAdding)
    {
        return teamService.VerifyAppOwnerPolicy(User, ToResourceId(resourceId), userId, targetRoleId, isAdding);
    }

    protected string GetRootResourceId()
    {
        return teamService.GetRootResourceId();
    }
}

public abstract class TeamControllerBase(TeamService teamService)
    : TeamControllerBase<User, TeamUserRole, Role>(teamService)
{
    protected override User ToDto(User user) => user;
    protected override Role ToDto(Role role) => role;
    protected override TeamUserRole ToDto(TeamUserRole userRole) => userRole;
}