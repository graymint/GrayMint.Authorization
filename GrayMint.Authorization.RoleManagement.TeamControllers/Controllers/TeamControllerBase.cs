using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Authentication;
using System.Text;
using System.Web;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[Authorize]
[Route("/api/v{version:apiVersion}/team")]
public abstract class TeamControllerBase<TUser, TUserRole, TRole> : ControllerBase
{
    private readonly TeamService _teamService;
    protected abstract TUser ToDto(TeamUser user);
    protected abstract TRole ToDto(TeamRole role);
    protected abstract TUserRole ToDto(TeamUserRole user);

    protected TeamControllerBase(
        TeamService teamService)
    {
        _teamService = teamService;
    }

    [HttpPost("users/current/signin")]
    [Authorize]
    public virtual async Task<UserApiKey> SignIn(bool longExpiration = false)
    {
        var apiKey = await _teamService.SignIn(User, longExpiration);
        return apiKey;
    }

    [HttpPost("users/current/signup")]
    [Authorize]
    public virtual async Task<UserApiKey> SignUp()
    {
        if (!_teamService.TeamControllersOptions.AllowUserSelfRegister)
            throw new UnauthorizedAccessException("Self-Register is not enabled.");

        await _teamService.Register(User);
        return await _teamService.SignIn(User, false);
    }

    [HttpPost("users/current/signout-all")]
    [Authorize]
    public virtual async Task SignOutAll()
    {
        var userId = await _teamService.GetUserId(User);
        await _teamService.ResetAuthorizationCode(userId);
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
        var res = await _teamService.ResetApiKey(userId);
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

    [Authorize]
    [HttpGet("users/current/resources/{resourceId}/permissions")]
    public async Task<IEnumerable<string>> ListCurrentUserPermissions(string resourceId)
    {
        var userId = await _teamService.GetUserId(User);
        var permissions = await _teamService.GetUserPermissions(resourceId, userId);
        return permissions;
    }

    [HttpPost("users/{userId:guid}/bot/reset-api-key")]
    public async Task<UserApiKey> ResetBotApiKey(Guid userId)
    {
        await VerifyWritePermissionOnBot(userId);
        var res = await _teamService.ResetApiKey(userId);
        return res;
    }

    [HttpPatch("users/{userId:guid}/bot")]
    public async Task<TUser> UpdateBot(Guid userId, TeamUpdateBotParam updateParam)
    {
        await VerifyWritePermissionOnBot(userId);
        var user = await _teamService.UpdateBot(userId, updateParam);
        return ToDto(new TeamUser(user));

    }


    [HttpGet("resources/{resourceId}/roles")]
    public async Task<IEnumerable<TRole>> ListRoles(string resourceId)
    {
        await VerifyReadPermissionOnRole(resourceId);
        var roles = await _teamService.GetRoles(ToResourceId(resourceId));
        return roles.Select(ToDto);
    }

    [HttpGet("resources/{resourceId}/user-roles")]
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
        //await VerifyWritePermissionOnUser(resourceId, userId); any user can be added to a resource except bots
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

    // ReSharper disable once UnusedMethodReturnValue.Local
    private async Task<IEnumerable<TeamUserRole>> VerifyWritePermissionOnBot(Guid userId)
    {
        var userRoles = await _teamService.GetUserRoles(userId: userId);

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
            await _teamService.VerifyWritePermissionOnUser(User, resId, userId);

        return userRoles.Items;
    }

    private static string ToResourceId(string resourceId)
    {
        return resourceId;
    }

    protected Task VerifyReadPermissionOnRole(string resourceId)
    {
        return _teamService.VerifyRoleReadPermission(User, ToResourceId(resourceId));
    }

    protected Task<TeamUserRole[]> VerifyWritePermissionOnUser(string resourceId, Guid userId)
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

    [HttpPost("system/api-key")]
    [AllowAnonymous]
    public async Task<UserApiKey> CreateSystemApiKey()
    {
        if (!_teamService.TeamControllersOptions.IsTestEnvironment)
            throw new UnauthorizedAccessException();

        var res = await _teamService.CreateSystemApiKey();
        return res;
    }

    [HttpPost("system/google/signin-handler")]
    [AllowAnonymous]
    public async Task<IActionResult> GoogleSignInHandler()
    {
        // read all request to string
        using var reader = new StreamReader(Request.Body, Encoding.UTF8);
        var queryString = await reader.ReadToEndAsync();

        // read queryString to dictionary
        var queryDictionary = HttpUtility.ParseQueryString(queryString);
        var idToken = queryDictionary["credential"] ?? throw new AuthenticationException("Email is not verified.");
        var tokenInfo = await _teamService.GetIdTokenFromGoogle(idToken);

        // Adding a parameter
        ArgumentNullException.ThrowIfNull(_teamService.TeamControllersOptions.SignInRedirectUrl);
        var uriBuilder = new UriBuilder(_teamService.TeamControllersOptions.SignInRedirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);
        query["id_token"] = tokenInfo.Token;
        uriBuilder.Query = query.ToString();

        return Redirect(uriBuilder.ToString());
    }

    [HttpGet("system/google/id-token")]
    [AllowAnonymous]
    public virtual async Task<string> GetIdTokenFromGoogle(string idToken)
    {
        var tokenInfo = await _teamService.GetIdTokenFromGoogle(idToken);
        return tokenInfo.Token;
    }
}

public abstract class TeamControllerBase
    : TeamControllerBase<TeamUser, TeamUserRole, TeamRole>
{
    protected TeamControllerBase(TeamService teamService) : base(teamService)
    {
    }

    protected override TeamUser ToDto(TeamUser user) => new(user);
    protected override TeamRole ToDto(TeamRole role) => new(role);
    protected override TeamUserRole ToDto(TeamUserRole userRole) => userRole;
}
