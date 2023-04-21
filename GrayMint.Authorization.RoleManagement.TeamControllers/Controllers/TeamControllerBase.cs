﻿using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[Authorize]
[Route("/api/v{version:apiVersion}/team")]
public abstract class TeamControllerBase<TUser, TUserRole, TRole> : ControllerBase 
{
    private readonly TeamService _teamService;
    protected abstract TUser ToDto(User user);
    protected abstract TRole ToDto(Role role);
    protected abstract TUserRole ToDto(UserRole user);

    protected TeamControllerBase(
        TeamService teamService)
    {
        _teamService = teamService;
    }

    [HttpPost("users/system/api-key")]
    [AllowAnonymous]
    public async Task<UserApiKey> CreateSystemApiKey()
    {
        if (!_teamService.TeamControllersOptions.IsTestEnvironment)
            throw new UnauthorizedAccessException();

        var res = await _teamService.CreateSystemApiKey();
        return res;
    }

    [HttpPost("users/current/register")]
    [Authorize]
    public virtual async Task<TUser> RegisterCurrentUser()
    {
        if (!_teamService.TeamControllersOptions.AllowUserSelfRegister)
            throw new UnauthorizedAccessException("Self-Register is not enabled.");

        var res = await _teamService.Register(User);
        return ToDto(res);
    }

    [HttpGet("users/current")]
    [Authorize]
    public async Task<TUser> GetCurrentUser()
    {
        var userId = await _teamService.GetUserId(User);
        var ret = await _teamService.GetUser(userId);
        return ToDto(ret);
    }

    [HttpPost("users/current/reset-api-key")]
    [Authorize]
    public async Task<UserApiKey> ResetCurrentUserApiKey()
    {
        var userId = await _teamService.GetUserId(User);
        var res = await _teamService.ResetUserApiKey(userId);
        return res;
    }

    [Authorize]
    [HttpGet("users/current/resources")]
    public async Task<IEnumerable<string>> ListCurrentUserResources()
    {
        var userId = await _teamService.GetUserId(User);
        var userRoles = await _teamService.GetUserRoles(userId: userId);
        var resourceIds = userRoles.Items
            .Select(x => x.ResourceId)
            .Distinct();

        return resourceIds;
    }

    [HttpPost("users/{userId:guid}/reset-api-key")]
    public async Task<UserApiKey> ResetBotApiKey(Guid userId)
    {
        var userRoles = await _teamService.GetUserRoles(userId: userId);
        var user = userRoles.Items.FirstOrDefault()?.User;
        if (user == null)
            throw new UnauthorizedAccessException("UserId does not belong to any role.");

        // check is a bot user
        if (user is not { IsBot: true })
            throw new InvalidOperationException("Only a bot ApiKey can be reset by this api.");

        // check reset permission
        await VerifyWritePermissionOnBot(userId);
        var res = await _teamService.ResetUserApiKey(userId);
        return res;
    }

    [HttpGet("resources/{resourceId}/roles")]
    public async Task<IEnumerable<TRole>> ListRoles(string resourceId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var roles = await _teamService.GetRoles(ToResourceId(resourceId));
        return roles.Select(ToDto);
    }

    [HttpGet("resources/{resourceId}/users")]
    public async Task<ListResult<TUserRole>> ListUserRoles(string resourceId,
        Guid? roleId = null, Guid? userId = null,
        string? search = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var userRoles = await _teamService.GetUserRoles(resourceId: ToResourceId(resourceId),
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

    [HttpPost("resources/{resourceId}/roles/{roleId:guid}/bots")]
    public async Task<UserApiKey> AddNewBot(string resourceId, Guid roleId, TeamAddBotParam addParam)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        var res = await _teamService.AddNewBot(ToResourceId(resourceId), roleId, addParam);
        return res;
    }

    [HttpPost("resources/{resourceId}/roles/{roleId:guid}/users/email:{email}")]
    public async Task<TUserRole> AddUserByEmail(string resourceId, Guid roleId, string email, TeamAddEmailParam? addParam = null)
    {
        _ = addParam; //reserved

        var user = await _teamService.FindUserByEmail(email);
        if (user != null)
            return await AddUser(resourceId, roleId, user.UserId);

        await VerifyWritePermissionOnRole(resourceId, roleId);
        var res = await _teamService.AddUserByEmail(ToResourceId(resourceId), roleId, email);
        return ToDto(res);
    }

    [HttpPost("resources/{resourceId}/roles/{roleId:guid}/users/{userId:guid}")]
    public async Task<TUserRole> AddUser(string resourceId, Guid roleId, Guid userId)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        await VerifyWritePermissionOnUser(resourceId, userId);
        await VerifyAppOwnerPolicy(resourceId, userId, roleId, true);


        // check write permission on bot
        var user = await _teamService.GetUser(userId);
        if (user.IsBot)
            await VerifyWritePermissionOnBot(userId: userId);

        var res = await _teamService.AddUser(ToResourceId(resourceId), roleId, userId);
        return ToDto(res);
    }


    [HttpDelete("resources/{resourceId}/roles/{roleId:guid}/users/{userId:guid}")]
    public async Task RemoveUser(string resourceId, Guid roleId, Guid userId)
    {
        await VerifyWritePermissionOnRole(resourceId, roleId);
        await VerifyWritePermissionOnUser(resourceId, userId);
        await VerifyAppOwnerPolicy(resourceId, userId, roleId, false);
        await _teamService.RemoveUser(ToResourceId(resourceId), roleId, userId);
    }

    private async Task VerifyWritePermissionOnBot(Guid userId)
    {
        // check is user have permission over all resources that the bot belong to
        var userRoles = await _teamService.GetUserRoles(userId: userId);
        var resourceIds = userRoles.Items.Select(x => x.ResourceId).Distinct();
        foreach (var resId in resourceIds)
            await _teamService.VerifyWritePermissionOnUser(User, resId, userId);
    }

    private static string ToResourceId(string resourceId)
    {
        return resourceId;
    }

    protected Task VerifyReadPermissionOnRole(string resourceId)
    {
        return _teamService.VerifyRoleReadPermission(User, ToResourceId(resourceId));
    }

    protected Task<UserRole[]> VerifyWritePermissionOnUser(string resourceId, Guid userId)
    {
        return _teamService.VerifyWritePermissionOnUser(User, ToResourceId(resourceId), userId);
    }

    protected Task VerifyWritePermissionOnRole(string resourceId, Guid roleId)
    {
        return _teamService.VerifyWritePermissionOnRole(User, ToResourceId(resourceId), roleId);
    }

    protected Task VerifyAppOwnerPolicy(string resourceId, Guid userId, Guid targetRoleId, bool isAdding)
    {
        return _teamService.VerifyAppOwnerPolicy(User, ToResourceId(resourceId), userId, targetRoleId, isAdding);
    }

    protected string GetRootResourceId()
    {
        return _teamService.GetRootResourceId();
    }
}

public abstract class TeamControllerBase
    : TeamControllerBase<User, UserRole, Role>
{
    protected TeamControllerBase(TeamService teamService) : base(teamService)
    {
    }

    protected override User ToDto(User user) => new(user);
    protected override Role ToDto(Role role) => new(role);
    protected override UserRole ToDto(UserRole userRole) => userRole;
}