﻿using System;
using System.Data;
using System.Threading.Tasks;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.RoleProviders.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace GrayMint.Authorization.RoleManagement.RoleProviders.Persistence;

// ReSharper disable once PartialTypeWithSinglePart
public partial class RoleDbContext : DbContext
{
    public const string Schema = AuthorizationConstants.DatabaseSchemePrefix + "role";

    internal virtual DbSet<UserRoleModel> UserRoles { get; set; } = default!;

    public RoleDbContext()
    {
    }

    public RoleDbContext(DbContextOptions<RoleDbContext> options)
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
            entity.HasKey(ex => new { AppId = ex.ResourceId, ex.UserId, ex.RoleId });

            entity.Property(x => x.ResourceId)
                .HasMaxLength(100);
        });

        // ReSharper disable once InvocationIsSkipped
        OnModelCreatingPartial(modelBuilder);
    }

    // ReSharper disable once PartialMethodWithSinglePart
    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}