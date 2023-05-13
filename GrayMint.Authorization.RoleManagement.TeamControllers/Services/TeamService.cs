using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications.BotAuthentication;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Exceptions;
using GrayMint.Authorization.RoleManagement.TeamControllers.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Generics;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Services;

public class TeamService
{
    private readonly IRoleProvider _roleProvider;
    private readonly IUserProvider _userProvider;
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly BotAuthenticationTokenBuilder _botAuthenticationTokenBuilder;
    private readonly RoleAuthorizationService _roleAuthorizationService;
    public TeamControllerOptions TeamControllersOptions { get; }
    public string GetRootResourceId() => _roleProvider.GetRootResourceId();

    public TeamService(
        IRoleProvider roleProvider,
        IUserProvider userProvider,
        IAuthorizationProvider authorizationProvider,
        IOptions<TeamControllerOptions> teamControllersOptions,
        BotAuthenticationTokenBuilder botAuthenticationTokenBuilder,
        RoleAuthorizationService roleAuthorizationService)
    {
        _roleProvider = roleProvider;
        _userProvider = userProvider;
        _authorizationProvider = authorizationProvider;
        _botAuthenticationTokenBuilder = botAuthenticationTokenBuilder;
        _roleAuthorizationService = roleAuthorizationService;
        TeamControllersOptions = teamControllersOptions.Value;
    }

    public async Task<bool> IsResourceOwnerRole(string resourceId, Guid roleId)
    {
        if (resourceId == _roleProvider.GetRootResourceId()) return false; //SystemResource can not be owned

        var permissions = await _roleProvider.GetRolePermissions(resourceId, roleId);
        return permissions.Contains(RolePermissions.RoleWriteOwner);
    }
    public async Task<IUser> UpdateBot(Guid userId, TeamUpdateBotParam updateParam)
    {
        var user = await _userProvider.Update(userId, new UserUpdateRequest
        {
            FirstName = updateParam.Name,
        });

        return user;
    }

    public async Task<UserApiKey> AddNewBot(string resourceId, Guid roleId, TeamAddBotParam addParam)
    {
        // check bot policy
        if (!TeamControllersOptions.AllowBotAppOwner && await IsResourceOwnerRole(resourceId, roleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        // create
        var email = $"{Guid.NewGuid()}@bot";
        var user = await _userProvider.Create(new UserCreateRequest
        {
            Email = email,
            FirstName = addParam.Name,
            IsBot = true
        });

        await _roleProvider.AddUser(roleId: roleId, userId: user.UserId, resourceId: resourceId);
        var authenticationHeader = await _botAuthenticationTokenBuilder.CreateAuthenticationHeader(user.UserId.ToString(), user.Email);
        var ret = new UserApiKey
        {
            UserId = user.UserId,
            Authorization = authenticationHeader.ToString()
        };
        return ret;
    }

    public async Task<UserApiKey> ResetUserApiKey(Guid userId)
    {
        var user = await _userProvider.Get(userId);

        // check AllowUserApiKey for user
        if (!user.IsBot && !TeamControllersOptions.AllowUserApiKey)
            throw new UnauthorizedAccessException("User ApiKey is not enabled.");

        // reset the api key
        await _userProvider.ResetAuthorizationCode(user.UserId);
        var authenticationHeader = await _botAuthenticationTokenBuilder.CreateAuthenticationHeader(user.UserId.ToString(), user.Email);
        var ret = new UserApiKey
        {
            UserId = userId,
            Authorization = authenticationHeader.ToString(),
        };

        return ret;
    }

    public async Task<UserRole> AddUserByEmail(string resourceId, Guid roleId, string email)
    {
        // create user if not found
        var user = await _userProvider.FindByEmail(email);
        user ??= await _userProvider.Create(new UserCreateRequest { Email = email });
        return await AddUser(resourceId, roleId, user.UserId);
    }

    public async Task<UserRole> AddUser(string resourceId, Guid roleId, Guid userId)
    {
        // check bot policy
        var user = await _userProvider.Get(userId);
        if (user.IsBot && !TeamControllersOptions.AllowBotAppOwner && await IsResourceOwnerRole(resourceId, roleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        // check is already exists
        var userRoles = await _roleProvider.GetUserRoles(resourceId: resourceId, userId: userId);
        if (userRoles.Items.Any(x => x.Role.RoleId == roleId))
            throw new AlreadyExistsException("Users");

        // add to role
        await _roleProvider.AddUser(resourceId: resourceId, roleId: roleId, userId: userId);

        // remove from other roles if MultipleRoles is not allowed
        if (!TeamControllersOptions.AllowUserMultiRole)
            foreach (var userRole in userRoles.Items.Where(x => x.Role.RoleId != roleId))
                await RemoveUser(resourceId, userRole.Role.RoleId, userId);

        var userRoleList = await GetUserRoles(resourceId: resourceId, roleId: roleId, userId: userId);
        return userRoleList.Items.Single(x => x.UserId == userId);
    }

    public async Task<IUser?> FindUserByEmail(string email)
    {
        return await _userProvider.FindByEmail(email);
    }

    public async Task<Guid> GetUserId(ClaimsPrincipal user)
    {
        return await _authorizationProvider.GetUserId(user) ?? throw new UnregisteredUser();
    }

    public async Task<User> GetUser(Guid userId)
    {
        var user = await _userProvider.Get(userId);
        return new User(user);
    }

    public Task<string[]> GetUserPermissions(string resourceId, Guid userId)
    {
        return _roleProvider.GetUserPermissions(resourceId: resourceId, userId: userId);
    }

    public async Task<ListResult<UserRole>> GetUserRoles(
        string? resourceId = null, Guid? roleId = null, Guid? userId = null,
        string? search = null, string? firstName = null, string? lastName = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        // get userRoles
        var userRoleList = await _roleProvider.GetUserRoles(
            resourceId: resourceId, roleId: roleId, userId: userId);

        // get users of userRoles
        var userList = await _userProvider.GetUsers(search: search, firstName: firstName, lastName: lastName,
            userIds: userRoleList.Items.Select(x => x.UserId), isBot: isBot);

        // attach user to UserRoles
        var userRoles = userRoleList.Items
            .Select(x => new UserRole(x, userList.Items.SingleOrDefault(y => y.UserId == x.UserId)))
            .OrderBy(x=>x.User?.FirstName)
            .ToArray();

        // filter user search
        if (search != null || isBot != null)
            userRoles = userRoles.Where(x => x.User != null).ToArray();

        // create the result
        var ret = new ListResult<UserRole>
        {
            Items = userRoles.Skip(recordIndex).Take(recordCount ?? int.MaxValue),
            TotalCount = userRoles.Length
        };
        return ret;
    }

    public async Task RemoveUser(string resourceId, Guid roleId, Guid userId)
    {
        await _roleProvider.RemoveUser(resourceId: resourceId, roleId, userId);

        // delete if user does not have any more roles in the system
        var userRoles = await GetUserRoles(userId: userId, recordCount: 1);
        if (!userRoles.Items.Any())
            await DeleteUser(userId);
    }

    public Task DeleteUser(Guid userId)
    {
        return _userProvider.Remove(userId);
    }

    public async Task<IEnumerable<Role>> GetRoles(string resourceId)
    {
        var roles = await _roleProvider.GetRoles(resourceId);
        return roles.Select(x => new Role(x));
    }

    public async Task<UserApiKey> CreateSystemApiKey()
    {
        var rootResourceId = _roleProvider.GetRootResourceId();
        var systemRoles = await _roleProvider.GetRoles(rootResourceId);
        if (!systemRoles.Any())
            throw new NotExistsException("Could not find any system roles.");

        foreach (var systemRole in systemRoles)
        {
            var permissions = await _roleProvider.GetRolePermissions(resourceId: rootResourceId, roleId: systemRole.RoleId);
            if (permissions.Contains(RolePermissions.RoleWrite))
            {
                var user = await AddNewBot(rootResourceId, systemRole.RoleId, new TeamAddBotParam { Name = $"TestAdmin_{Guid.NewGuid()}" });
                return user;
            }
        }

        throw new NotExistsException($"Could not find {nameof(RolePermissions.RoleWrite)} in any system roles.");
    }

    public async Task<User> Register(ClaimsPrincipal caller)
    {
        var email =
            caller.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Email)?.Value.ToLower()
            ?? throw new UnauthorizedAccessException("Could not find user's email claim!");

        var ret = await _userProvider.Create(new UserCreateRequest
        {
            Email = email,
            FirstName = caller.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.GivenName)?.Value,
            LastName = caller.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Surname)?.Value,
            Description = null
        });

        return new User(ret);
    }

    public async Task<bool> CheckUserPermission(ClaimsPrincipal caller, string resourceId, string permission)
    {
        var ret = await _roleAuthorizationService.AuthorizePermissionAsync(caller, resourceId, permission);
        return ret.Succeeded;
    }

    public async Task VerifyRoleReadPermission(ClaimsPrincipal caller, string resourceId)
    {
        if (!await CheckUserPermission(caller, resourceId, RolePermissions.RoleRead))
            throw new UnauthorizedAccessException();
    }

    public async Task<UserRole[]> VerifyWritePermissionOnUser(ClaimsPrincipal caller, string resourceId, Guid userId)
    {
        // check user permission over all of the user roles
        var userRoles = await GetUserRoles(resourceId: resourceId, userId: userId);
        if (!userRoles.Items.Any())
            throw new UnauthorizedAccessException();

        foreach (var userRole in userRoles.Items)
            await VerifyWritePermissionOnRole(caller, resourceId, userRole.Role.RoleId);

        return userRoles.Items.ToArray();
    }

    public async Task VerifyWritePermissionOnRole(ClaimsPrincipal caller, string resourceId, Guid roleId)
    {
        if (!await CheckUserPermission(caller, resourceId, RolePermissions.RoleWrite))
            throw new UnauthorizedAccessException();

        //Check AppTeamWriteOwner
        if (await IsResourceOwnerRole(resourceId, roleId) &&
            !await CheckUserPermission(caller, resourceId, RolePermissions.RoleWriteOwner))
            throw new UnauthorizedAccessException();
    }


    // can not change its own owner role unless it has global TeamWrite permission
    public async Task VerifyAppOwnerPolicy(ClaimsPrincipal caller, string resourceId, Guid userId, Guid targetRoleId, bool isAdding)
    {

        // check is AllowOwnerSelfRemove allowed
        if (TeamControllersOptions.AllowOwnerSelfRemove)
            return;

        // check is caller changing himself
        var callerUserId = await _authorizationProvider.GetUserId(caller);
        if (callerUserId != userId)
            return;

        // check is caller the owner of the resource
        var callerUserRoles = await GetUserRoles(resourceId: resourceId, userId: callerUserId);
        var isCallerOwner = false;
        foreach (var callerUserRole in callerUserRoles.Items)
            isCallerOwner |= await IsResourceOwnerRole(resourceId, callerUserRole.Role.RoleId);
        if (!isCallerOwner)
            return;

        var exception = new InvalidOperationException("You are an owner and can not remove yourself. Ask other owners or delete the project.");
        var targetRoleIsOwner = await IsResourceOwnerRole(resourceId, targetRoleId);

        // check is owner going to remove himself; newRoleId can be any if AllowMultipleRoles is on because
        // the old roles won't be changed
        if (TeamControllersOptions.AllowUserMultiRole)
        {
            if (!isAdding && targetRoleIsOwner)
                throw exception;
            return;
        }

        // MultiRole is not enable 
        if ((isAdding && !targetRoleIsOwner) || // Owners can't change his role to any other non owner role
            (!isAdding && targetRoleIsOwner))   // Owners can't remove hos owner role
            throw new InvalidOperationException("You are an owner and can not remove yourself. Ask other owners or delete the project.");
    }
}