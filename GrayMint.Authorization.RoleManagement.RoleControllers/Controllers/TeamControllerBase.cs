using GrayMint.Authorization.RoleManagement.RoleControllers.Dtos;
using GrayMint.Authorization.RoleManagement.RoleControllers.Services;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.RoleManagement.RoleControllers.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[Authorize]
[Route("/api/v{version:apiVersion}/team")]
public abstract class TeamControllerBase<TResource, TResourceId, TUser, TUserRole, TRole>
    : ControllerBase where TResourceId : notnull
{
    protected readonly RoleService RoleService;
    protected abstract TUser ToDto(User user);
    protected abstract TRole ToDto(Role role);
    protected abstract TUserRole ToDto(UserRole user);
    protected abstract string ToResourceId(TResourceId resourceId);
    protected abstract Task<IEnumerable<TResource>> GetResources(IEnumerable<string> resourceId);

    protected TeamControllerBase(
        RoleService roleService)
    {
        RoleService = roleService;
    }

    [HttpPost("users/system/api-key")]
    [AllowAnonymous]
    public async Task<UserApiKey> CreateSystemApiKey()
    {
        if (!RoleService.RoleControllersOptions.IsTestEnvironment)
            throw new UnauthorizedAccessException();

        var res = await RoleService.CreateSystemApiKey();
        return res;
    }

    [HttpPost("users/current/register")]
    [Authorize]
    public virtual async Task<TUser> RegisterCurrentUser()
    {
        if (!RoleService.RoleControllersOptions.AllowUserSelfRegister)
            throw new UnauthorizedAccessException("Self-Register is not enabled.");

        var res = await RoleService.Register(User);
        return ToDto(res);
    }

    [HttpGet("users/current")]
    [Authorize]
    public async Task<TUser> GetCurrentUser()
    {
        var userId = await RoleService.GetUserId(User);
        var ret = await RoleService.GetUser(userId);
        return ToDto(ret);
    }

    [HttpPost("users/current/reset-api-key")]
    [Authorize]
    public async Task<UserApiKey> ResetCurrentUserApiKey()
    {
        if (!RoleService.RoleControllersOptions.AllowUserApiKey)
            throw new UnauthorizedAccessException("User ApiKey is not enabled.");

        var userId = await RoleService.GetUserId(User);
        var res = await RoleService.ResetUserApiKey(userId);
        return res;
    }

    [Authorize]
    [HttpGet("users/current/resources")]
    public async Task<IEnumerable<TResource>> ListCurrentUserResources()
    {
        var userId = await RoleService.GetUserId(User);
        var userRoles = await RoleService.GetUserRoles(userId: userId);
        var resourceIds = userRoles.Items.Distinct().Select(x => x.ResourceId);
        return await GetResources(resourceIds);
    }

    [HttpGet("resources/{resourceId}/roles")]
    public async Task<IEnumerable<TRole>> ListRoles(TResourceId resourceId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var roles = await RoleService.GetRoles(ToResourceId(resourceId));
        return roles.Select(ToDto);
    }

    [HttpGet("resources/{resourceId}/users")]
    public async Task<ListResult<TUserRole>> ListUsers(TResourceId resourceId,
        Guid? roleId = null, Guid? userId = null,
        string? search = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userRoles = await RoleService.GetUserRoles(resourceId: ToResourceId(resourceId),
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

    [HttpPost("resources/{resourceId}/bots")]
    public async Task<UserApiKey> AddNewBot(TResourceId resourceId, TeamAddBotParam addParam)
    {
        await VerifyWritePermissionOnRole(resourceId, addParam.RoleId);

        if (!RoleService.RoleControllersOptions.AllowBotAppOwner && await RoleService.IsResourceOwnerRole(ToResourceId(resourceId), addParam.RoleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        var res = await RoleService.AddNewBot(ToResourceId(resourceId), addParam);
        return res;
    }

    [HttpPost("resources/{resourceId}/bots/{userId:guid}/reset-api-key")]
    public async Task<UserApiKey> ResetBotApiKey(TResourceId resourceId, Guid userId)
    {
        var userRoles = await VerifyWritePermissionOnUser(resourceId, userId);

        // check is a bot user
        var user = userRoles.First().User;
        if (user is not { IsBot: true })
            throw new InvalidOperationException("Only a bot ApiKey can be reset by this api.");

        var res = await RoleService.ResetUserApiKey(userId);
        return res;
    }

    [HttpPost("resources/{resourceId}/users")]
    public async Task<TUserRole> AddUser(TResourceId resourceId, TeamAddUserParam addParam)
    {
        await VerifyWritePermissionOnRole(resourceId, addParam.RoleId);

        var user = await RoleService.FindUserByEmail(addParam.Email);
        if (user?.IsBot == true)
            throw new InvalidOperationException("Bot can not be added. You need to create a new one or update it.");

        var res = await RoleService.AddUserByEmail(ToResourceId(resourceId), addParam.RoleId, addParam.Email);
        return ToDto(res);
    }

    [HttpGet("resources/{resourceId}/users/{userId:guid}")]
    public async Task<TUserRole> GetUser(TResourceId resourceId, Guid userId)
    {
        await VerifyReadPermissionOnRole(resourceId);

        var res = await RoleService.GetUserRoles(resourceId: ToResourceId(resourceId), userId: userId);
        return ToDto(res.Items.First());
    }

    [HttpPost("resources/{resourceId}/users/{userId:guid}")]
    public async Task<TUserRole> UpdateUser(TResourceId resourceId, Guid userId, TeamUpdateUserParam updateParam)
    {
        var userRoles = await VerifyWritePermissionOnUser(resourceId, userId);

        if (updateParam.RoleId != null)
        {
            await VerifyWritePermissionOnRole(resourceId, updateParam.RoleId);
            await VerifyAppOwnerPolicy(resourceId, userId, updateParam.RoleId);

            // remove from other roles
            foreach (var userRole in userRoles.Where(x => x.Role.RoleId != updateParam.RoleId))
                await RoleService.RemoveUser(ToResourceId(resourceId), userRole.Role.RoleId, userId);

            // add to role
            if (userRoles.All(x => x.Role.RoleId != updateParam.RoleId))
                await RoleService.AddUser(ToResourceId(resourceId), updateParam.RoleId, userId);

            // delete if user does not have any more roles in the system
            if (!(await RoleService.GetUserRoles(userId: userId)).Items.Any())
                await RoleService.DeleteUser(userId);
        }

        var res = await RoleService.GetUserRoles(resourceId: ToResourceId(resourceId), userId: userId);
        return ToDto(res.Items.Single()); //throw error if it is more than one
    }

    [HttpDelete("resources/{resourceId}/users/{userId:guid}")]
    public async Task RemoveUser(TResourceId resourceId, Guid userId)
    {
        var userRoles = await VerifyWritePermissionOnUser(resourceId, userId);

        // Check owner policy
        await VerifyAppOwnerPolicy(resourceId, userId, null);

        // remove from all roles
        foreach (var userRole in userRoles)
            await RoleService.RemoveUser(ToResourceId(resourceId), userRole.Role.RoleId, userRole.UserId);

        // delete if user does not have any more roles in the system
        if (!(await RoleService.GetUserRoles(userId: userId)).Items.Any())
            await RoleService.DeleteUser(userId);
    }

    protected Task VerifyReadPermissionOnRole(TResourceId resourceId)
    {
        return RoleService.VerifyRoleReadPermission(User, ToResourceId(resourceId));
    }

    protected Task<UserRole[]> VerifyWritePermissionOnUser(TResourceId resourceId, Guid userId)
    {
        return RoleService.VerifyWritePermissionOnUser(User, ToResourceId(resourceId), userId);
    }

    protected Task VerifyWritePermissionOnRole(TResourceId resourceId, Guid roleId)
    {
        return RoleService.VerifyWritePermissionOnRole(User, ToResourceId(resourceId), roleId);
    }

    protected Task VerifyAppOwnerPolicy(TResourceId resourceId, Guid userId, Guid? newRoleId)
    {
        return RoleService.VerifyAppOwnerPolicy(User, ToResourceId(resourceId), userId, newRoleId);
    }
}

public abstract class TeamControllerBase<TResource, TResourceId>
    : TeamControllerBase<TResource, TResourceId, User, UserRole, Role> where TResourceId : notnull
{
    protected TeamControllerBase(RoleService roleService) : base(roleService)
    {
    }

    protected override User ToDto(User user) => new(user);
    protected override Role ToDto(Role role) => new(role);
    protected override UserRole ToDto(UserRole userRole) => userRole;
}
