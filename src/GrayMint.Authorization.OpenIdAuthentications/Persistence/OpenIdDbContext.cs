using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.OpenIdAuthentications.Models;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.OpenIdAuthentications.Persistence;

// ReSharper disable once PartialTypeWithSinglePart
public partial class OpenIdDbContext : DbContext
{
    public const string Schema = AuthorizationConstants.DatabaseSchemePrefix + "openid";

    // the longest id of an account that OpenID Connect allows
    public const int MaxSubjectLength = 255;

    internal virtual DbSet<UserBindingModel> UserBindings { get; set; } = null!;

    public OpenIdDbContext()
    {
    }

    public OpenIdDbContext(DbContextOptions<OpenIdDbContext> options)
        : base(options)
    {
    }

    protected override void ConfigureConventions(
        ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTime>()
            .HavePrecision(0);

        configurationBuilder.Properties<string>()
            .HaveMaxLength(400);
    }

    private bool IsSchemaSupported =>
        Database.ProviderName?.Contains("Sqlite") == false &&
        Database.ProviderName?.Contains("InMemory") == false;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // add default schema only for supported databases
        if (IsSchemaSupported)
            modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<UserBindingModel>(entity => {
            entity.HasKey(x => new { x.Provider, x.Subject });

            entity.Property(x => x.Provider)
                .HasMaxLength(OpenIdProviderOptions.MaxNameLength);

            entity.Property(x => x.Subject)
                .HasMaxLength(MaxSubjectLength);

            // A user is one account's. Of two accounts that come for the same user at the same moment, the
            // database lets one in; with no such key both would be tied, each by an address alone.
            entity.HasIndex(x => x.UserId)
                .IsUnique();
        });

        // ReSharper disable once InvocationIsSkipped
        OnModelCreatingPartial(modelBuilder);
    }

    // ReSharper disable once PartialMethodWithSinglePart
    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
