using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserRole = GrayMint.Authorization.RoleManagement.TeamControllers.Dtos.UserRole;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[Authorize]
[Route("/api/v{version:apiVersion}/team")]
public abstract class TeamControllerBase<TUser, TUserRole, TRole>(TeamService teamService) 
    : ControllerBase
{
    protected abstract TUser ToDto(User user);
    protected abstract TRole ToDto(Role role);
    protected abstract TUserRole ToDto(UserRole user);
    public class TeamUser
    {
        public required TUser User { get; init; }
        public required TRole[] Roles { get; init; }
    }


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

    [Authorize]
    [HttpGet("users/current/resources/{resourceId}/permissions")]
    public async Task<IEnumerable<string>> ListCurrentUserPermissions(string resourceId)
    {
        var userId = await teamService.GetUserId(User);
        var permissions = await teamService.GetUserPermissions(resourceId, userId);
        return permissions;
    }

    [HttpPost("users/{userId}/bot/reset-api-key")]
    public async Task<ApiKey> ResetBotApiKey(string userId)
    {
        await VerifyWritePermissionOnBot(userId);
        var res = await teamService.ResetBotApiKey(userId);
        return res;
    }

    [HttpPatch("users/{userId}/bot")]
    public async Task<TUser> UpdateBot(string userId, TeamUpdateBotParam updateParam)
    {
        await VerifyWritePermissionOnBot(userId);
        var user = await teamService.UpdateBot(userId, updateParam);
        return ToDto(user);

    }


    [HttpGet("resources/{resourceId}/roles")]
    public async Task<IEnumerable<TRole>> ListRoles(string resourceId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var roles = await teamService.GetRoles(ToResourceId(resourceId));
        return roles.Select(ToDto);
    }

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

        var ret = new ListResult<TUserRole>
        {
            TotalCount = userRoles.TotalCount,
            Items = userRoles.Items.Select(ToDto)
        };
        return ret;
    }

    [HttpGet("resources/{resourceId}/users/{userId}")]
    public async Task<TeamUser> GetUser(string resourceId, string userId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userByEmail = await teamService.GetUser(resourceId, userId);
        var ret = new TeamUser
        {
            User = ToDto(userByEmail.User),
            Roles = userByEmail.Roles.Select(ToDto).ToArray(),
        };
        return ret;
    }

    [HttpGet("resources/{resourceId}/users/email:{email}")]
    public async Task<TeamUser> GetUserByEmail(string resourceId, string email)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userByEmail = await teamService.GetUserByEmail(resourceId, email);
        var ret = new TeamUser
        {
            User = ToDto(userByEmail.User),
            Roles = userByEmail.Roles.Select(ToDto).ToArray(),
        };
        return ret;
    }


    [HttpPost("resources/{resourceId}/roles/{roleId}/bots")]
    public async Task<ApiKey> AddNewBot(string resourceId, string roleId, TeamAddBotParam addParam)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        var res = await teamService.AddNewBot(ToResourceId(resourceId), roleId, addParam);
        return res;
    }

    [HttpPost("resources/{resourceId}/roles/{roleId}/users/email:{email}")]
    public async Task<TUserRole> AddUserByEmail(string resourceId, string roleId, string email, TeamAddEmailParam? addParam = null)
    {
        _ = addParam; //reserved

        var user = await teamService.FindUserByEmail(email);
        if (user != null)
            return await AddUser(resourceId, roleId, user.UserId);

        await VerifyWritePermissionOnRole(resourceId, roleId);
        var res = await teamService.AddUserByEmail(ToResourceId(resourceId), roleId, email);
        return ToDto(res);
    }

    [HttpPost("resources/{resourceId}/roles/{roleId}/users/{userId}")]
    public async Task<TUserRole> AddUser(string resourceId, string roleId, string userId)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        //await VerifyWritePermissionOnUser(resourceId, userId); any user can be added to a resource except bots
        await VerifyAppOwnerPolicy(resourceId, userId, roleId, true);


        // check write permission on bot
        var user = await teamService.GetUser(userId);
        if (user.IsBot)
            await VerifyWritePermissionOnBot(userId: userId);

        var res = await teamService.AddUser(ToResourceId(resourceId), roleId, userId);
        return ToDto(res);
    }

    [HttpDelete("resources/{resourceId}/roles/{roleId}/users/{userId}")]
    public async Task RemoveUser(string resourceId, string roleId, string userId)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        await VerifyWritePermissionOnUser(resourceId, userId);
        await VerifyAppOwnerPolicy(resourceId, userId, roleId, false);
        await teamService.RemoveUser(ToResourceId(resourceId), roleId, userId);
    }

    [HttpPost("system/api-key")]
    [AllowAnonymous]
    public async Task<ApiKey> CreateSystemApiKey([FromForm] string secret)
    {
        var res = await teamService.CreateSystemApiKey(secret);
        return res;
    }

    // ReSharper disable once UnusedMethodReturnValue.Local
    private async Task<IEnumerable<UserRole>> VerifyWritePermissionOnBot(string userId)
    {
        var userRoles = await teamService.GetUserRoles(userId: userId);

        // find user
        var user = userRoles.Items.FirstOrDefault()?.User;
        if (user == null)
            throw new UnauthorizedAccessException("UserId does not belong to any role.");

        // check is a bot user
        if (user is not { IsBot: true })
            throw new InvalidOperationException("This operation can only be performed on bots.");

        // check is the caller has permission over all resources that the bot belong to
        var resourceIds = userRoles.Items.Select(x => x.ResourceId).Distinct();
        foreach (var resId in resourceIds)
            await teamService.VerifyWritePermissionOnUser(User, resId, userId);

        return userRoles.Items;
    }

    private static string ToResourceId(string resourceId)
    {
        return resourceId;
    }

    protected Task VerifyReadPermissionOnRole(string resourceId)
    {
        return teamService.VerifyRoleReadPermission(User, ToResourceId(resourceId));
    }

    protected Task<UserRole[]> VerifyWritePermissionOnUser(string resourceId, string userId)
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
    : TeamControllerBase<User, UserRole, Role>(teamService)
{
    protected override User ToDto(User user) => user;
    protected override Role ToDto(Role role) => role;
    protected override UserRole ToDto(UserRole userRole) => userRole;
}
