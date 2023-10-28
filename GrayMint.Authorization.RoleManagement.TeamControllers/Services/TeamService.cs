using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Generics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Services;

public class TeamService
{
    private readonly IRoleProvider _roleProvider;
    private readonly IUserProvider _userProvider;
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly IAuthorizationService _authorizationService;
    private readonly GrayMintAuthentication _authenticationTokenBuilder;

    public TeamControllerOptions TeamControllersOptions { get; }

    public TeamService(
        IRoleProvider roleProvider,
        IUserProvider userProvider,
        IAuthorizationProvider authorizationProvider,
        IOptions<TeamControllerOptions> teamControllersOptions,
        GrayMintAuthentication authenticationTokenBuilder,
        IAuthorizationService authorizationService)
    {
        _roleProvider = roleProvider;
        _userProvider = userProvider;
        _authorizationProvider = authorizationProvider;
        _authenticationTokenBuilder = authenticationTokenBuilder;
        _authorizationService = authorizationService;
        TeamControllersOptions = teamControllersOptions.Value;
    }

    public async Task<bool> IsResourceOwnerRole(string resourceId, Guid roleId)
    {
        //SystemResource can not be owned
        if (resourceId == GetRootResourceId())
            return false;

        var permissions = await _roleProvider.GetRolePermissions(resourceId, roleId);
        return permissions.Contains(RolePermissions.RoleWriteOwner);
    }
    public async Task<User> UpdateBot(Guid userId, TeamUpdateBotParam updateParam)
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
        var email = $"{Guid.NewGuid()}@bot.local";
        var user = await _userProvider.Create(new UserCreateRequest
        {
            Email = email,
            FirstName = addParam.Name,
            IsBot = true
        });

        var expirationTime = DateTime.UtcNow.AddYears(14);
        await _roleProvider.AddUser(roleId: roleId, userId: user.UserId, resourceId: resourceId);
        var tokenInfo = await _authenticationTokenBuilder
            .CreateToken(new CreateTokenParams
            {
                Subject = user.UserId.ToString(),
                ExpirationTime = expirationTime
            });

        var ret = new UserApiKey
        {
            ExpirationTime = expirationTime,
            UserId = user.UserId,
            Authorization = tokenInfo.ToAuthorization().ToString(),
        };
        return ret;
    }

    public async Task<User> ResetAuthorizationCode(Guid userId)
    {
        var user = await _userProvider.Get(userId);
        await _userProvider.ResetAuthorizationCode(user.UserId);
        return user;
    }

    public async Task<UserApiKey> ResetApiKey(Guid userId)
    {
        var user = await _userProvider.Get(userId);

        // check AllowUserApiKey for user
        if (!user.IsBot && !TeamControllersOptions.AllowUserApiKey)
            throw new UnauthorizedAccessException("User ApiKey is not enabled.");

        // reset the api key
        var expirationTime = DateTime.UtcNow.AddYears(14);
        await _userProvider.ResetAuthorizationCode(user.UserId);
        var authenticationHeader = await _authenticationTokenBuilder
            .CreateAuthenticationHeader(new CreateTokenParams
            {
                Subject = user.UserId.ToString(),
                Email = user.Email,
                ExpirationTime = expirationTime
            });

        var ret = new UserApiKey
        {
            ExpirationTime = expirationTime,
            UserId = userId,
            Authorization = authenticationHeader.ToString(),
        };

        return ret;
    }

    private async Task UpdateUserByClaims(User user, ClaimsPrincipal claimsPrincipal)
    {
        var updateRequest = new UserUpdateRequest();
        var isUpdated = false;

        var email = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
        if (email != null && user.Email != email) { updateRequest.Email = email; isUpdated = true; }

        var name = claimsPrincipal.FindFirstValue(ClaimTypes.Name);
        if (name != null && user.Name != name) { updateRequest.Name = name; isUpdated = true; }

        var firstName = claimsPrincipal.FindFirstValue(ClaimTypes.GivenName);
        if (firstName != null && user.FirstName != firstName) { updateRequest.FirstName = firstName; isUpdated = true; }

        var lastName = claimsPrincipal.FindFirstValue(ClaimTypes.Surname);
        if (lastName != null && user.LastName != lastName) { updateRequest.LastName = lastName; isUpdated = true; }

        var phone = claimsPrincipal.FindFirstValue(ClaimTypes.MobilePhone);
        if (phone != null && user.Name != phone) { updateRequest.Phone = phone; isUpdated = true; }

        var pictureUrl = claimsPrincipal.FindFirstValue("picture");
        if (pictureUrl != null && user.PictureUrl != pictureUrl) { updateRequest.PictureUrl = pictureUrl; isUpdated = true; }

        var isEmailVerified = claimsPrincipal.FindFirstValue("email_verified");
        if (isEmailVerified != null && user.IsEmailVerified != bool.Parse(isEmailVerified)) { updateRequest.IsEmailVerified = bool.Parse(isEmailVerified); isUpdated = true; }

        if (isUpdated)
            await _userProvider.Update(user.UserId, updateRequest);
    }

    public async Task<UserApiKey> SignIn(ClaimsPrincipal claimsPrincipal, bool longExpiration)
    {
        var userId = await GetUserId(claimsPrincipal);
        var user = await GetUser(userId);

        if (user.IsBot)
            throw new InvalidOperationException("Can not use this method for bots.");

        var tokenInfo = await _authenticationTokenBuilder
            .SignIn(claimsPrincipal, longExpiration);

        if (claimsPrincipal.FindFirstValue("token_use") == "id")
            await UpdateUserByClaims(user, claimsPrincipal);

        var ret = new UserApiKey
        {
            ExpirationTime = tokenInfo.ExpirationTime,
            UserId = userId,
            Authorization = tokenInfo.ToAuthorization().ToString(),
        };

        return ret;
    }

    public async Task<TeamUserRole> AddUserByEmail(string resourceId, Guid roleId, string email)
    {
        // create user if not found
        var user = await _userProvider.FindByEmail(email);
        user ??= await _userProvider.Create(new UserCreateRequest { Email = email });
        return await AddUser(resourceId, roleId, user.UserId);
    }

    public async Task<TeamUserRole> AddUser(string resourceId, Guid roleId, Guid userId)
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

    public async Task<User?> FindUserByEmail(string email)
    {
        return await _userProvider.FindByEmail(email);
    }

    public async Task<Guid> GetUserId(ClaimsPrincipal user)
    {
        var userId = await _authorizationProvider.GetUserId(user) ?? throw new UnregisteredUser();
        return Guid.Parse(userId);
    }

    public async Task<User> GetUser(Guid userId)
    {
        var user = await _userProvider.Get(userId);

        //AccessedTime should not be set for user due security reason and sharing user account among projects,
        user.AccessedTime = null;
        return user;
    }

    public Task<string[]> GetUserPermissions(string resourceId, Guid userId)
    {
        return _roleProvider.GetUserPermissions(resourceId: resourceId, userId: userId);
    }

    public async Task<ListResult<TeamUserRole>> GetUserRoles(
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
            .Select(x => new TeamUserRole(x, userList.Items.SingleOrDefault(y => y.UserId == x.UserId)))
            .OrderBy(x => x.User?.FirstName)
            .ToArray();

        // filter user search
        if (search != null || isBot != null)
            userRoles = userRoles.Where(x => x.User != null).ToArray();

        // create the result
        var ret = new ListResult<TeamUserRole>
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

    public async Task<IEnumerable<TeamRole>> GetRoles(string resourceId)
    {
        var roles = await _roleProvider.GetRoles(resourceId);
        return roles.Select(x => new TeamRole(x));
    }

    public async Task<UserApiKey> CreateSystemApiKey()
    {
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

    public async Task<User> SignUp(ClaimsPrincipal claimsPrincipal)
    {
        var email =
            claimsPrincipal.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Email)?.Value.ToLower()
            ?? throw new UnauthorizedAccessException("Could not find user's email claim!");

        var user = await _userProvider.Create(new UserCreateRequest { Email = email });

        if (claimsPrincipal.FindFirstValue("token_use") == "id")
            await UpdateUserByClaims(user, claimsPrincipal);

        return user;
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

    public async Task<TeamUserRole[]> VerifyWritePermissionOnUser(ClaimsPrincipal caller, string resourceId, Guid userId)
    {
        // check user permission over all of the user roles on this resource
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
        var callerUserIdStr = await _authorizationProvider.GetUserId(caller);
        if (!Guid.TryParse(callerUserIdStr, out var callerUserId) || callerUserId != userId)
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

    public string GetRootResourceId()
    {
        return AuthorizationConstants.RootResourceId;
    }

    public Task<AccessTokenInfo> GetIdTokenFromGoogle(string idToken)
    {
        return _authenticationTokenBuilder.CreateIdTokenFromGoogle(idToken);
    }
    public Task<AccessTokenInfo> GetIdTokenFromCognito(string idToken)
    {
        return _authenticationTokenBuilder.CreateIdTokenFromCognito(idToken);
    }

}