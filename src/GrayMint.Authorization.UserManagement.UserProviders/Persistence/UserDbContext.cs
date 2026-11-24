using System.Data;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.UserProviders.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace GrayMint.Authorization.UserManagement.UserProviders.Persistence;

public class UserDbContext : DbContext
{
    public const string Schema = AuthorizationConstants.DatabaseSchemePrefix + "user";
    internal virtual DbSet<UserModel> Users => Set<UserModel>();

    public UserDbContext()
    {
    }

    public UserDbContext(DbContextOptions<UserDbContext> options)
        : base(options)
    {
    }

    public async Task<IDbContextTransaction?> WithNoLockTransaction(CancellationToken cancellationToken)
    {
        return Database.CurrentTransaction == null && Database.IsRelational()
            ? await Database.BeginTransactionAsync(IsolationLevel.ReadUncommitted, cancellationToken)
            : null;
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

        // Where a database names a default (SQL Server), EF names it DF_<table>_<column> rather than the database
        // naming it at random; PostgreSQL names none.
        modelBuilder.Model.UseNamedDefaultConstraints(true);

        // add default schema only for supported databases
        if (IsSchemaSupported)
            modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<UserModel>(entity => {
            entity.HasKey(x => x.UserId);

            entity.Property(e => e.UserId)
                .HasMaxLength(50);

            entity.Property(e => e.IsDisabled)
                .HasDefaultValue(false);

            entity.HasIndex(e => e.Email)
                .IsUnique();

            entity.HasIndex(e => e.FirstName);
            entity.HasIndex(e => e.LastName);

            entity.Property(e => e.IsBot)
                .HasDefaultValue(false);

            entity.Property(e => e.IsEmailVerified)
                    .HasDefaultValue(false);

            entity.Property(e => e.IsPhoneVerified)
                .HasDefaultValue(false);

            entity.Property(e => e.ExData)
                .HasMaxLength(int.MaxValue);

            // Google's profile picture URLs can exceed the 400 default.
            // Existing databases: ALTER TABLE gmuser.Users ALTER COLUMN PictureUrl nvarchar(2000) NULL;
            entity.Property(e => e.PictureUrl)
                .HasMaxLength(2000);
        });
    }
}