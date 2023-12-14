using GrayMint.Common.Utils;

namespace GrayMint.Authorization.Test.MicroserviceSample.Dtos;

public class ItemUpdateRequest
{
    public Patch<string>? ItemName { get; init; }
}