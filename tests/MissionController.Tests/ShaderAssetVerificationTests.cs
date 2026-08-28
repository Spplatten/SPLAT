using System.IO;
using Xunit;

namespace MissionController.Tests;

public class ShaderAssetVerificationTests
{
    private static string FindSolutionRoot()
    {
        var current = AppContext.BaseDirectory;
        while (!string.IsNullOrEmpty(current))
        {
            if (File.Exists(Path.Combine(current, "MissionController.sln")))
            {
                return current;
            }
            current = Directory.GetParent(current)?.FullName;
        }
        return @"c:\C_AGENT_BUILDER";
    }

    [Theory]
    [InlineData("Effects/Win2D/MissionControllerGlow.hlsl")]
    [InlineData("Effects/Win2D/MissionControllerRadarScan.hlsl")]
    [InlineData("Effects/Win2D/MissionControllerCyberGrid.hlsl")]
    [InlineData("Effects/Win2D/MissionControllerElectricShield.hlsl")]
    [InlineData("Effects/Win2D/MissionControllerNeuralSynapse.hlsl")]
    [InlineData("Graphics/Shaders/MissionControllerComposite.hlsl")]
    public void ShaderFiles_Exist_AndContainValidEntrypoints(string relativePath)
    {
        var root = FindSolutionRoot();
        var fullPath = Path.Combine(root, "src", "MissionController.UI", relativePath);

        Assert.True(File.Exists(fullPath), $"Shader file should exist at {fullPath}");

        var content = File.ReadAllText(fullPath);
        Assert.NotEmpty(content);

        // Win2D shaders must declare D2D_PS_ENTRY or D2D_ENTRY
        // Direct3D shaders must declare VSMain/PSMain
        var hasValidEntry = content.Contains("D2D_PS_ENTRY") || 
                             content.Contains("PSMain") || 
                             content.Contains("VSMain");
        Assert.True(hasValidEntry, $"Shader {relativePath} must contain valid HLSL entry points.");
    }

    [Fact]
    public void Win2DTargets_And_Props_AreConfigured()
    {
        var root = FindSolutionRoot();
        var targetsPath = Path.Combine(root, "src", "MissionController.UI", "Effects", "Win2D", "MissionController.Win2D.targets");
        var propsPath = Path.Combine(root, "src", "MissionController.UI", "Effects", "Win2D", "MissionController.Win2D.props");

        Assert.True(File.Exists(targetsPath));
        Assert.True(File.Exists(propsPath));

        var targetsContent = File.ReadAllText(targetsPath);
        Assert.Contains("CompileMissionControllerWin2DShader", targetsContent);
    }
}
