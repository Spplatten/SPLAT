using System.Threading.Tasks;
using Xunit;

namespace MissionController.Tests;

public class EndToEndVerificationTests
{
    [Fact]
    public async Task DiagnosticVerificationRunner_ExecutesEndToEndSuccessfully()
    {
        bool success = await DiagnosticVerificationRunner.RunVerificationAsync();
        Assert.True(success);
    }
}
