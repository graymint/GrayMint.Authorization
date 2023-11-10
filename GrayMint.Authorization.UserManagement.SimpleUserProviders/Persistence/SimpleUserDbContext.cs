using System.Data;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders.Persistence;

// ReSharper disable once PartialTypeWithSinglePart
public partial class SimpleUserDbContext : DbContext
{
    public const string Schema = AuthorizationConstants.DatabaseSchemePrefix + "user";
    internal virtual DbSet<UserModel> Users { get; set; } = default!;

    public SimpleUserDbContext()
    {
    }

    public SimpleUserDbContext(DbContextOptions<SimpleUserDbContext> options)
        : base(options)
    {
    }

    public async Task<IDbContextTransaction?> WithNoLockTransaction()
    {
        return Database.CurrentTransaction == null ? await Database.BeginTransactionAsync(IsolationLevel.ReadUncommitted) : null;
    }

    protected override void ConfigureConventions(
        ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTime>()
            .HavePrecision(0);

        configurationBuilder.Properties<string>()
            .HaveMaxLength(400);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<UserModel>(entity =>
        {
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

            entity.Property(e => e.ExData)
                .HasMaxLength(int.MaxValue);
        });

        // ReSharper disable once InvocationIsSkipped
        OnModelCreatingPartial(modelBuilder);
    }

    // ReSharper disable once PartialMethodWithSinglePart
    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}