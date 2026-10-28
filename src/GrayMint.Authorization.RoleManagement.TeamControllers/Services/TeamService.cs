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

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Services;

public class TeamService(
    IRoleProvider roleProvider,
    IUserProvider userProvider,
    IAuthorizationProvider authorizationProvider,
    IOptions<TeamControllerOptions> teamControllersOptions,
    IOptions<GrayMintAuthenticationOptions> authenticationOptions,
    GrayMintAuthentication grayMintAuthentication,
    IAuthorizationService authorizationService,
    IHostEnvironment hostEnvironment)
{
    private readonly GrayMintAuthenticationOptions _authenticationOptions = authenticationOptions.Value;
    private readonly TeamControllerOptions _teamControllersOptions = teamControllersOptions.Value;

    public async Task<bool> IsResourceOwnerRole(string resourceId, string roleId)
    {
        //SystemResource can not be owned
        if (resourceId == GetRootResourceId())
            return false;

        var permissions = await roleProvider.GetRolePermissions(resourceId, roleId);
        return permissions.Contains(RolePermissions.RoleWriteOwner);
    }

    public async Task<User> UpdateBot(string userId, TeamUpdateBotParam updateParam)
    {
        var user = await userProvider.Update(userId, new UserUpdateRequest {
            FirstName = updateParam.Name
        });

        return HideInternalFields(user);
    }

    // teammates see a user's profile, never the token revocation code or the app's own notes on them
    private static User HideInternalFields(User user)
    {
        user.AuthorizationCode = null;
        user.Description = null;
        user.ExData = null;
        return user;
    }

    // a person shows on a resource's team by the email they were added by until their first request to it,
    // so adding an email tells no one whether it has an account, or anything of its profile
    private static User HideProfile(User user)
    {
        HideInternalFields(user);
        user.Name = null;
        user.FirstName = null;
        user.LastName = null;
        user.PictureUrl = null;
        user.Phone = null;
        user.CreatedTime = default;
        user.AccessedTime = null;
        user.IsDisabled = false;
        user.IsEmailVerified = false;
        user.IsPhoneVerified = false;
        return user;
    }

    // takes the user's own roles on the resource; a bot is the team's own, so it always shows
    private static bool IsProfileHidden(User user, IEnumerable<UserRole> userRoles)
    {
        var roles = userRoles.ToArray();
        return !user.IsBot && roles.Length > 0 && roles.All(x => x.ConfirmedTime == null);
    }

    // a hidden profile is found only by what shows of it: its email or id
    private static bool MatchesHiddenProfile(User user, string? search, string? firstName, string? lastName)
    {
        if (firstName != null || lastName != null)
            return false;

        search = search?.Trim();
        return string.IsNullOrEmpty(search) ||
               user.Email?.StartsWith(search, StringComparison.OrdinalIgnoreCase) == true ||
               (Guid.TryParse(search, out var searchGuid) && Guid.TryParse(user.UserId, out var userGuid) &&
                searchGuid == userGuid);
    }

    public async Task<ApiKey> AddNewBot(string resourceId, string roleId, TeamAddBotParam addParam)
    {
        // check bot policy
        if (!_teamControllersOptions.AllowBotAppOwner && await IsResourceOwnerRole(resourceId, roleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        // create
        var email = $"{Guid.NewGuid()}@bot.local";
        var user = await userProvider.Create(new UserCreateRequest {
            Email = email,
            FirstName = addParam.Name,
            IsBot = true
        });

        await roleProvider.AddUserRole(roleId: roleId, userId: user.UserId, resourceId: resourceId);

        // create the access token
        var claimIdentity = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, user.UserId)]);
        var apiKey = await grayMintAuthentication
            .CreateApiKey(claimIdentity, new ApiKeyOptions {
                ValidateOptions = new ValidateOptions {
                    ValidateSubject = true,
                    ValidateAuthCode = true
                },
                AccessTokenExpirationTime = JwtUtil.UtcNow.AddYears(13)
            });

        return apiKey;
    }

    public async Task<ApiKey> ResetBotApiKey(string userId)
    {
        var user = await userProvider.Get(userId);

        // check AllowUserApiKey for user
        if (!user.IsBot)
            throw new UnauthorizedAccessException("User ApiKey is not enabled.");

        // reset the api key
        await userProvider.ResetAuthorizationCode(user.UserId);

        // Create a new api key
        var claimIdentity = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, user.UserId)]);
        var apiKey = await grayMintAuthentication
            .CreateApiKey(claimIdentity, new ApiKeyOptions {
                AccessTokenExpirationTime = JwtUtil.UtcNow.AddYears(13)
            });

        return apiKey;
    }

    public async Task<TeamUserRole> AddUserByEmail(string resourceId, string roleId, string email,
        ClaimsPrincipal? caller = null)
    {
        // a role the resource can't hold fails before an account is made for the email
        var roles = await roleProvider.GetRoles(resourceId);
        if (roles.All(x => x.RoleId != roleId))
            throw new InvalidOperationException("This role can not be added on this resource.");

        // create user if not found
        email = NormalizeEmail(email);
        var user = await userProvider.FindByEmail(email);
        user ??= await userProvider.Create(new UserCreateRequest { Email = email });
        return await AddUser(resourceId, roleId, user.UserId, caller);
    }

    // takes away the user's other roles on the resource unless AllowUserMultiRole; given the caller, it first
    // checks their rights over the very roles it takes away, or an admin could strip an owner by a lesser role
    public async Task<TeamUserRole> AddUser(string resourceId, string roleId, string userId,
        ClaimsPrincipal? caller = null)
    {
        // check bot policy
        var user = await userProvider.Get(userId);
        if (user.IsBot && !_teamControllersOptions.AllowBotAppOwner && await IsResourceOwnerRole(resourceId, roleId))
            throw new InvalidOperationException("Bot can not be an owner.");

        // the user's own id from here on, as the caller may have written it another way
        userId = user.UserId;

        // check is already exists
        var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria
            { ResourceId = resourceId, UserId = userId });
        if (userRoles.Any(x => x.Role.RoleId == roleId))
            throw new AlreadyExistsException("Users");

        // the roles the new one replaces if MultipleRoles is not allowed
        var replacedRoles = _teamControllersOptions.AllowUserMultiRole
            ? []
            : userRoles.Where(x => x.Role.RoleId != roleId).ToArray();

        if (caller != null)
            foreach (var userRole in replacedRoles)
                await VerifyWritePermissionOnRole(caller, resourceId, userRole.Role.RoleId);

        // add to role
        await roleProvider.AddUserRole(resourceId: resourceId, roleId: roleId, userId: userId);

        // remove from the roles it replaces
        foreach (var userRole in replacedRoles)
            await RemoveUser(resourceId, userRole.Role.RoleId, userId);

        var userRoleList = await GetUserRoles(resourceId: resourceId, roleId: roleId, userId: userId);
        return userRoleList.Items.Single(x => x.UserId == userId);
    }

    public Task<User?> FindUserByEmail(string email)
    {
        return userProvider.FindByEmail(NormalizeEmail(email));
    }

    // as sign-up stores it, so an added email answers in one form whether or not an account held it
    private static string NormalizeEmail(string email)
    {
        return email.Trim().ToLowerInvariant();
    }

    public async Task<string> GetUserId(ClaimsPrincipal user)
    {
        var userId = await authorizationProvider.GetUserId(user) ?? throw new UnregisteredUserException();
        return userId;
    }

    public async Task<User> GetUser(string userId)
    {
        var user = await userProvider.Get(userId);

        //AccessedTime should not be set for user due security reason and sharing user account among projects,
        user.AccessedTime = null;
        return user;
    }

    public Task<string[]> GetUserPermissions(string resourceId, string userId)
    {
        return roleProvider.GetUserPermissions(resourceId: resourceId, userId: userId);
    }

    public async Task<ListResult<TeamUserRole>> GetUserRoles(
        string? resourceId = null, string? roleId = null, string? userId = null,
        string? search = null, string? firstName = null, string? lastName = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        // get userRoles
        var userRoleList = await roleProvider.GetUserRoles(
            new UserRoleCriteria { ResourceId = resourceId, RoleId = roleId, UserId = userId });

        // get users of userRoles; on a resource's team, one who hasn't used it yet shows by email only; users and
        // roles are matched by lookup, not by scans, so a large team costs no more than its size
        var rolesByUser = userRoleList.ToLookup(x => x.UserId);
        var userList = await userProvider.GetUsers(search: search, firstName: firstName, lastName: lastName,
            userIds: userRoleList.Select(x => x.UserId), isBot: isBot);
        var users = userList.Items
            .Select(x => new {
                User = x,
                IsHidden = resourceId != null && IsProfileHidden(x, rolesByUser[x.UserId])
            })
            .Where(x => !x.IsHidden || MatchesHiddenProfile(x.User, search, firstName, lastName))
            .Select(x => x.IsHidden ? HideProfile(x.User) : HideInternalFields(x.User))
            .ToDictionary(x => x.UserId);

        // attach user to UserRoles
        var userRoles = userRoleList
            .Select(x => new TeamUserRole {
                ResourceId = x.ResourceId,
                Role = x.Role,
                UserId = x.UserId,
                ConfirmedTime = x.ConfirmedTime,
                User = users.GetValueOrDefault(x.UserId)
            })
            .OrderBy(x => x.User?.FirstName)
            .ToArray();

        // filter user search
        if (search != null || firstName != null || lastName != null || isBot != null)
            userRoles = [.. userRoles.Where(x => x.User != null)];

        // create the result
        var ret = new ListResult<TeamUserRole> {
            Items = [.. userRoles.Skip(recordIndex).Take(recordCount ?? int.MaxValue)],
            TotalCount = userRoles.Length
        };
        return ret;
    }

    public async Task<TeamUser> GetUser(string resourceId, string userId)
    {
        var user = await userProvider.FindById(userId);
        return await GetTeamUser(resourceId, user);
    }

    public async Task<TeamUser> GetUserByEmail(string resourceId, string email)
    {
        var user = await userProvider.FindByEmail(NormalizeEmail(email));
        return await GetTeamUser(resourceId, user);
    }

    // a resource's readers find only its own team, not even learning whether anyone else exists;
    // the root resource's readers already read every team, so they find any user
    private async Task<TeamUser> GetTeamUser(string resourceId, User? user)
    {
        var userRoles = user != null
            ? await roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resourceId, UserId = user.UserId })
            : [];

        if (user == null || (userRoles.Length == 0 && resourceId != GetRootResourceId()))
            throw new NotExistsException("There is no such user in this resource.");

        return new TeamUser {
            User = IsProfileHidden(user, userRoles) ? HideProfile(user) : HideInternalFields(user),
            Roles = [.. userRoles.Select(x => x.Role)]
        };
    }

    public async Task RemoveUser(string resourceId, string roleId, string userId)
    {
        await roleProvider.RemoveUserRoles(
            new UserRoleCriteria { ResourceId = resourceId, RoleId = roleId, UserId = userId });

        // with its last role goes a bot, or an account an email add made and no one has used; a person who has
        // signed in keeps theirs, as leaving one team must not delete them
        var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { UserId = userId });
        if (userRoles.Length > 0)
            return;

        // read, then deleted, left so: a first sign-in, or another team's add, at that very moment can still lose
        // the account, costing a new sign-up, or a new add (that team keeps a role without a user)
        var user = await userProvider.Get(userId);
        if (user.IsBot || (user.AccessedTime == null && !user.IsEmailVerified))
            await DeleteUser(userId);
    }

    public Task DeleteUser(string userId)
    {
        return userProvider.Remove(userId);
    }

    public async Task<IEnumerable<Role>> GetRoles(string resourceId)
    {
        var roles = await roleProvider.GetRoles(resourceId);
        return roles;
    }

    public async Task<ApiKey> CreateSystemApiKey(string secret)
    {
        // checked before the secret, so a server where it is off never even compares it
        if (!_authenticationOptions.IsSystemApiKeyAllowed(hostEnvironment.IsDevelopment()))
            throw new UnauthorizedAccessException("The system api key is disabled.");

        if (!_authenticationOptions.MatchesSecret(secret))
            throw new UnauthorizedAccessException("Bad secret.");

        var rootResourceId = GetRootResourceId();
        var systemRoles = await roleProvider.GetRoles(rootResourceId);
        if (!systemRoles.Any())
            throw new NotExistsException("Could not find any system roles.");

        foreach (var systemRole in systemRoles) {
            var permissions =
                await roleProvider.GetRolePermissions(resourceId: rootResourceId, roleId: systemRole.RoleId);
            if (permissions.Contains(RolePermissions.RoleWrite)) {
                var apiKey = await AddNewBot(rootResourceId, systemRole.RoleId,
                    new TeamAddBotParam { Name = $"TestAdmin_{Guid.NewGuid()}" });
                return apiKey;
            }
        }

        throw new NotExistsException($"Could not find {nameof(RolePermissions.RoleWrite)} in any system roles.");
    }

    public async Task<bool> CheckUserPermission(ClaimsPrincipal caller, string resourceId, string permission)
    {
        if (caller.Identity?.IsAuthenticated == false)
            return false;

        var ret = await authorizationService.AuthorizeAsync(caller, resourceId,
            new PermissionAuthorizationRequirement { Permission = permission });

        return ret.Succeeded;
    }

    public async Task VerifyRoleReadPermission(ClaimsPrincipal caller, string resourceId)
    {
        if (!await CheckUserPermission(caller, resourceId, RolePermissions.RoleRead))
            throw new UnauthorizedAccessException();
    }

    public async Task<TeamUserRole[]> VerifyWritePermissionOnUser(ClaimsPrincipal caller, string resourceId,
        string userId)
    {
        // check user permission over all the user roles on this resource
        var userRoles = await GetUserRoles(resourceId: resourceId, userId: userId);
        if (!userRoles.Items.Any())
            throw new UnauthorizedAccessException();

        foreach (var userRole in userRoles.Items)
            await VerifyWritePermissionOnRole(caller, resourceId, userRole.Role.RoleId);

        return [.. userRoles.Items];
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
    public async Task VerifyAppOwnerPolicy(ClaimsPrincipal caller, string resourceId, string userId,
        string targetRoleId, bool isAdding)
    {
        // check is AllowOwnerSelfRemove allowed
        if (_teamControllersOptions.AllowOwnerSelfRemove)
            return;

        // check is caller changing himself, however the id is written
        var callerUserId = await authorizationProvider.GetUserId(caller);
        if (!IsSameUserId(callerUserId, userId))
            return;

        // check is caller the owner of the resource
        var callerUserRoles = await GetUserRoles(resourceId: resourceId, userId: callerUserId);
        var isCallerOwner = false;
        foreach (var callerUserRole in callerUserRoles.Items)
            isCallerOwner |= await IsResourceOwnerRole(resourceId, callerUserRole.Role.RoleId);
        if (!isCallerOwner)
            return;

        var exception =
            new InvalidOperationException(
                "You are an owner and cannot give up your owner role yourself. Another owner can remove you or change your role. " +
                "If you are the only one, make someone else an owner first.");
        var targetRoleIsOwner = await IsResourceOwnerRole(resourceId, targetRoleId);

        // check is owner going to remove himself; newRoleId can be any if AllowMultipleRoles is on because
        // the old roles won't be changed
        if (_teamControllersOptions.AllowUserMultiRole) {
            if (!isAdding && targetRoleIsOwner)
                throw exception;
            return;
        }

        // MultiRole is not enable 
        if ((isAdding && !targetRoleIsOwner) || // Owners can't change his role to any other non owner role
            (!isAdding && targetRoleIsOwner)) // Owners can't remove hos owner role
            throw exception;
    }

    public string GetRootResourceId()
    {
        return AuthorizationConstants.RootResourceId;
    }

    // a Guid id may be written several ways (upper case, no hyphens); any other id compares as written
    private static bool IsSameUserId(string? userId1, string userId2)
    {
        return Guid.TryParse(userId1, out var guid1) && Guid.TryParse(userId2, out var guid2)
            ? guid1 == guid2
            : userId1 == userId2;
    }
}