using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.Authentications.Utils;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using UserRole = GrayMint.Authorization.RoleManagement.TeamControllers.Dtos.UserRole;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Services;

public class TeamService
{
    private readonly IRoleProvider _roleProvider;
    private readonly IUserProvider _userProvider;
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly IAuthorizationService _authorizationService;
    private readonly GrayMintAuthentication _grayMintAuthentication;
    private readonly TeamControllerOptions _teamControllersOptions;

    public TeamService(
        IRoleProvider roleProvider,
        IUserProvider userProvider,
        IAuthorizationProvider authorizationProvider,
        IOptions<TeamControllerOptions> teamControllersOptions,
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        GrayMintAuthentication grayMintAuthentication,
        IAuthorizationService authorizationService)
    {
        _roleProvider = roleProvider;
        _userProvider = userProvider;
        _authorizationProvider = authorizationProvider;
        _authenticationOptions = authenticationOptions.Value;
        _grayMintAuthentication = grayMintAuthentication;
        _authorizationService = authorizationService;
        _teamControllersOptions = teamControllersOptions.Value;
    }

    public async Task<bool> IsResourceOwnerRole(string resourceId, string roleId)
    {
        //SystemResource can not be owned
        if (resourceId == GetRootResourceId())
            return false;

        var permissions = await _roleProvider.GetRolePermissions(resourceId, roleId);
        return permissions.Contains(RolePermissions.RoleWriteOwner);
    }
    public async Task<User> UpdateBot(string userId, TeamUpdateBotParam updateParam)
    {
        var user = await _userProvider.Update(userId, new UserUpdateRequest
        {
            FirstName = updateParam.Name,
        });

        return user;
    }

    public async Task<ApiKey> AddNewBot(string resourceId, string roleId, TeamAddBotParam addParam)
    {
        // check bot policy
        if (!_teamControllersOptions.AllowBotAppOwner && await IsResourceOwnerRole(resourceId, roleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        // create
        var email = $"{Guid.NewGuid()}@bot.local";
        var user = await _userProvider.Create(new UserCreateRequest
        {
            Email = email,
            FirstName = addParam.Name,
            IsBot = true
        });

        await _roleProvider.AddUserRole(roleId: roleId, userId: user.UserId, resourceId: resourceId);

        // create the access token
        var claimIdentity = new ClaimsIdentity(new Claim[] { new (JwtRegisteredClaimNames.Sub, user.UserId)});
        var apiKey = await _grayMintAuthentication
            .CreateApiKey(claimIdentity, new ApiKeyOptions
            {
                ValidateOptions = new ValidateOptions
                {
                    ValidateSubject = true,
                    ValidateAuthCode = true,
                },
                AccessTokenExpirationTime = JwtUtil.UtcNow.AddYears(13)
            });

        return apiKey;
    }

    public async Task<ApiKey> ResetBotApiKey(string userId)
    {
        var user = await _userProvider.Get(userId);

        // check AllowUserApiKey for user
        if (!user.IsBot)
            throw new UnauthorizedAccessException("User ApiKey is not enabled.");

        // reset the api key
        await _userProvider.ResetAuthorizationCode(user.UserId);
        
        // Create a new api key
        var claimIdentity = new ClaimsIdentity(new Claim[] { new(JwtRegisteredClaimNames.Sub, user.UserId) });
        var apiKey = await _grayMintAuthentication
            .CreateApiKey(claimIdentity, new ApiKeyOptions
            {
                AccessTokenExpirationTime = JwtUtil.UtcNow.AddYears(13)
            });

        return apiKey;
    }

    public async Task<UserRole> AddUserByEmail(string resourceId, string roleId, string email)
    {
        // create user if not found
        var user = await _userProvider.FindByEmail(email);
        user ??= await _userProvider.Create(new UserCreateRequest { Email = email });
        return await AddUser(resourceId, roleId, user.UserId);
    }

    public async Task<UserRole> AddUser(string resourceId, string roleId, string userId)
    {
        // check bot policy
        var user = await _userProvider.Get(userId);
        if (user.IsBot && !_teamControllersOptions.AllowBotAppOwner && await IsResourceOwnerRole(resourceId, roleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        // check is already exists
        var userRoles = await _roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resourceId, UserId = userId });
        if (userRoles.Any(x => x.Role.RoleId == roleId))
            throw new AlreadyExistsException("Users");

        // add to role
        await _roleProvider.AddUserRole(resourceId: resourceId, roleId: roleId, userId: userId);

        // remove from other roles if MultipleRoles is not allowed
        if (!_teamControllersOptions.AllowUserMultiRole)
            foreach (var userRole in userRoles.Where(x => x.Role.RoleId != roleId))
                await RemoveUser(resourceId, userRole.Role.RoleId, userId);

        var userRoleList = await GetUserRoles(resourceId: resourceId, roleId: roleId, userId: userId);
        return userRoleList.Items.Single(x => x.UserId == userId);
    }

    public async Task<User?> FindUserByEmail(string email)
    {
        return await _userProvider.FindByEmail(email);
    }

    public async Task<string> GetUserId(ClaimsPrincipal user)
    {
        var userId = await _authorizationProvider.GetUserId(user) ?? throw new UnregisteredUserException();
        return userId;
    }

    public async Task<User> GetUser(string userId)
    {
        var user = await _userProvider.Get(userId);

        //AccessedTime should not be set for user due security reason and sharing user account among projects,
        user.AccessedTime = null;
        return user;
    }

    public Task<string[]> GetUserPermissions(string resourceId, string userId)
    {
        return _roleProvider.GetUserPermissions(resourceId: resourceId, userId: userId);
    }

    public async Task<ListResult<UserRole>> GetUserRoles(
        string? resourceId = null, string? roleId = null, string? userId = null,
        string? search = null, string? firstName = null, string? lastName = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        // get userRoles
        var userRoleList = await _roleProvider.GetUserRoles(
            new UserRoleCriteria { ResourceId = resourceId, RoleId = roleId, UserId = userId });

        // get users of userRoles
        var userList = await _userProvider.GetUsers(search: search, firstName: firstName, lastName: lastName,
            userIds: userRoleList.Select(x => x.UserId), isBot: isBot);

        // attach user to UserRoles
        var userRoles = userRoleList
            .Select(x => new UserRole
            {
                ResourceId = x.ResourceId,
                Role = x.Role,
                UserId = x.UserId,
                User = userList.Items.SingleOrDefault(y => y.UserId == x.UserId)
            })
            .OrderBy(x => x.User?.FirstName)
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

    public async Task RemoveUser(string resourceId, string roleId, string userId)
    {
        await _roleProvider.RemoveUserRoles(
            new UserRoleCriteria { ResourceId = resourceId, RoleId = roleId, UserId = userId });

        // delete if user does not have any more roles in the system
        var userRoles = await GetUserRoles(userId: userId, recordCount: 1);
        if (!userRoles.Items.Any())
            await DeleteUser(userId);
    }

    public Task DeleteUser(string userId)
    {
        return _userProvider.Remove(userId);
    }

    public async Task<IEnumerable<Role>> GetRoles(string resourceId)
    {
        var roles = await _roleProvider.GetRoles(resourceId);
        return roles;
    }

    public async Task<ApiKey> CreateSystemApiKey(string secret)
    {
        if (!Convert.FromBase64String(secret).SequenceEqual((_authenticationOptions.Secret)))
            throw new UnauthorizedAccessException("Bad secret.");

        var rootResourceId = GetRootResourceId();
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

    public async Task<bool> CheckUserPermission(ClaimsPrincipal caller, string resourceId, string permission)
    {
        if (caller.Identity?.IsAuthenticated == false)
            return false;

        var ret = await _authorizationService.AuthorizeAsync(caller, resourceId,
            new PermissionAuthorizationRequirement { Permission = permission });

        return ret.Succeeded;
    }

    public async Task VerifyRoleReadPermission(ClaimsPrincipal caller, string resourceId)
    {
        if (!await CheckUserPermission(caller, resourceId, RolePermissions.RoleRead))
            throw new UnauthorizedAccessException();
    }

    public async Task<UserRole[]> VerifyWritePermissionOnUser(ClaimsPrincipal caller, string resourceId, string userId)
    {
        // check user permission over all of the user roles on this resource
        var userRoles = await GetUserRoles(resourceId: resourceId, userId: userId);
        if (!userRoles.Items.Any())
            throw new UnauthorizedAccessException();

        foreach (var userRole in userRoles.Items)
            await VerifyWritePermissionOnRole(caller, resourceId, userRole.Role.RoleId);

        return userRoles.Items.ToArray();
    }

    public async Task VerifyWritePermissionOnRole(ClaimsPrincipal caller, string resourceId, string roleId)
    {
        if (!await CheckUserPermission(caller, resourceId, RolePermissions.RoleWrite))
            throw new UnauthorizedAccessException();

        //Check AppTeamWriteOwner
        if (await IsResourceOwnerRole(resourceId, roleId) &&
            !await CheckUserPermission(caller, resourceId, RolePermissions.RoleWriteOwner))
            throw new UnauthorizedAccessException();
    }


    // can not change its own owner role unless it has global TeamWrite permission
    public async Task VerifyAppOwnerPolicy(ClaimsPrincipal caller, string resourceId, string userId, string targetRoleId, bool isAdding)
    {

        // check is AllowOwnerSelfRemove allowed
        if (_teamControllersOptions.AllowOwnerSelfRemove)
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
        if (_teamControllersOptions.AllowUserMultiRole)
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

    public string GetRootResourceId()
    {
        return AuthorizationConstants.RootResourceId;
    }
}