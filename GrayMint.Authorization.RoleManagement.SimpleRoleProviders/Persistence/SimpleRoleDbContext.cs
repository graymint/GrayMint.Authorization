using System;
using System.Data;
using System.Threading.Tasks;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Persistence;

// ReSharper disable once PartialTypeWithSinglePart
public partial class SimpleRoleDbContext : DbContext
{
    public const string Schema = "smrole";

    internal virtual DbSet<UserRoleModel> UserRoles { get; set; } = default!;
    internal virtual DbSet<ResourceModel> Resources { get; set; } = default!;

    public SimpleRoleDbContext()
    {
    }

    public SimpleRoleDbContext(DbContextOptions<SimpleRoleDbContext> options)
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

        modelBuilder.Entity<UserRoleModel>(entity =>
        {
            entity.HasKey(e => new { AppId = e.ResourceId, e.UserId, e.RoleId });

            entity.Property(x => x.ResourceId)
                .HasMaxLength(100);

            entity.HasOne(d => d.Resource)
                .WithMany(p => p!.UserRoles)
                .HasForeignKey(d => d.ResourceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ResourceModel>(entity =>
        {
            entity.HasKey(e => new { AppId = e.ResourceId });

            entity.Property(x => x.ResourceId)
                .HasMaxLength(100);

            entity.Property(x => x.ParentResourceId)
                .HasMaxLength(100);

            entity.HasData(new ResourceModel
            {
                ResourceId = AuthorizationConstants.RootResourceId,
                ParentResourceId = null
            });
        });

        // ReSharper disable once InvocationIsSkipped
        OnModelCreatingPartial(modelBuilder);
    }

    // ReSharper disable once PartialMethodWithSinglePart
    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}