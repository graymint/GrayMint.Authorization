using GrayMint.Authorization.Test.ItemServices.Models;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.ItemServices.Persistence;

public class AppDbContext : DbContext
{
    public virtual DbSet<AppModel> Apps => Set<AppModel>();
    public virtual DbSet<ItemModel> Items => Set<ItemModel>();

    public AppDbContext()
    {
    }

    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AppModel>(entity => {
            entity.HasKey(e => e.AppId);
            entity.HasIndex(e => e.AppName)
                .IsUnique();
        });

        modelBuilder.Entity<ItemModel>(entity => { entity.HasKey(e => e.ItemId); });
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        base.ConfigureConventions(configurationBuilder);

        configurationBuilder.Properties<string>()
            .HaveMaxLength(4000);

        configurationBuilder.Properties<decimal>()
            .HavePrecision(19, 4);
    }
}