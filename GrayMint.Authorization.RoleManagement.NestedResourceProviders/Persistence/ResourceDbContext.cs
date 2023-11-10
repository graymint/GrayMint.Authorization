﻿using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Models;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.RoleManagement.NestedResourceProviders.Persistence;

public class ResourceDbContext : DbContext
{
    public const string Schema = AuthorizationConstants.DatabaseSchemePrefix + "nres";

    internal virtual DbSet<ResourceModel> Resources { get; set; } = default!;

    public ResourceDbContext()
    {
    }

    public ResourceDbContext(DbContextOptions<ResourceDbContext> options)
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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<ResourceModel>(entity =>
        {
            entity.HasKey(ex => new { AppId = ex.ResourceId });

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
    }
}