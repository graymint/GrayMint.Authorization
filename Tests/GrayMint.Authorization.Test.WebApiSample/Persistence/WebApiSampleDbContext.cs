using GrayMint.Authorization.Test.WebApiSample.Models;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample.Persistence;

// ReSharper disable once PartialTypeWithSinglePart
public partial class WebApiSampleDbContext : DbContext
{
    public const string Schema = "dbo";

    public virtual DbSet<App> Apps { get; set; } = default!;
    public virtual DbSet<Item> Items { get; set; } = default!;

    public WebApiSampleDbContext()
    {
    }

    public WebApiSampleDbContext(DbContextOptions<WebApiSampleDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<App>(entity =>
        {
            entity.HasKey(e => e.AppId);
            entity.HasIndex(e => e.AppName)
                .IsUnique();
        });

        modelBuilder.Entity<Item>(entity =>
        {
            entity.HasKey(e => e.ItemId);
        });

        // ReSharper disable once InvocationIsSkipped
        OnModelCreatingPartial(modelBuilder);
    }

    // ReSharper disable once PartialMethodWithSinglePart
    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        base.ConfigureConventions(configurationBuilder);

        configurationBuilder.Properties<string>()
            .HaveMaxLength(4000);

        configurationBuilder.Properties<decimal>()
            .HavePrecision(19, 4);
    }
}