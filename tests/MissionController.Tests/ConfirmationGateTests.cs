using System;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

public class ConfirmationGateTests
{
    private readonly ConfirmationGate _gate = new();

    private const string ToolName = "webhook-register-github";
    private const string Summary = "Register a webhook on org/repo pointing to https://receiver.example.com/hook";
    private const string MutationVerb = "POST /repos/org/repo/hooks";
    private const string EgressTarget = "140.82.121.3:443";
    private const string SecretScope = "oauth-token/github";
    private const string RequestHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    private const string Actor = "operator@machine";

    [Fact]
    public async Task Request_ReturnsTokenBoundToRequest()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor);

        Assert.NotNull(pending.Token);
        Assert.Equal(64, pending.Token.Length);
        Assert.Equal(RequestHash, pending.RequestHash);
        Assert.Equal(ToolName, pending.ToolName);
        Assert.Equal(Actor, pending.RequestingActor);
        Assert.True(pending.ExpiresUtc > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Consume_GrantsOnMatchingHash()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor);

        var outcome = await _gate.ConsumeAsync(pending.Token, RequestHash);

        Assert.Equal(ConfirmationOutcome.Granted, outcome);
    }

    [Fact]
    public async Task Consume_RejectsWrongHash()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor);

        var outcome = await _gate.ConsumeAsync(pending.Token, "wrong_hash_0000000000000000000000000000000000000000000000000000000000");

        Assert.Equal(ConfirmationOutcome.RequestMismatch, outcome);
    }

    [Fact]
    public async Task Consume_RejectsDoubleUse()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor);

        await _gate.ConsumeAsync(pending.Token, RequestHash);
        var second = await _gate.ConsumeAsync(pending.Token, RequestHash);

        Assert.Equal(ConfirmationOutcome.AlreadyConsumed, second);
    }

    [Fact]
    public async Task Consume_RejectsExpiredToken()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor,
            ttl: TimeSpan.FromMilliseconds(50));

        await Task.Delay(100);

        var outcome = await _gate.ConsumeAsync(pending.Token, RequestHash);

        Assert.Equal(ConfirmationOutcome.Expired, outcome);
    }

    [Fact]
    public async Task Consume_NotFound_ForBogusToken()
    {
        var outcome = await _gate.ConsumeAsync("0000000000000000000000000000000000000000000000000000000000000000", RequestHash);

        Assert.Equal(ConfirmationOutcome.NotFound, outcome);
    }

    [Fact]
    public async Task ListPending_ShowsOnlyLiveTokensForActor()
    {
        await _gate.RequestAsync(ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor);
        await _gate.RequestAsync(ToolName, "Other mutation", "DELETE /repos/org/repo", EgressTarget, null, "otherhash0000000000000000000000000000000000000000000000000000000", Actor);
        // Different actor — should not appear
        await _gate.RequestAsync(ToolName, "Another actor", MutationVerb, EgressTarget, null, RequestHash, "other-actor@machine");

        var pending = await _gate.ListPendingAsync(Actor);

        Assert.Equal(2, pending.Count);
        Assert.All(pending, p => Assert.Equal(Actor, p.RequestingActor));
    }

    [Fact]
    public async Task ListPending_ExcludesConsumedTokens()
    {
        var p1 = await _gate.RequestAsync(ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor);
        await _gate.RequestAsync(ToolName, "Still pending", MutationVerb, EgressTarget, null, "hash2000000000000000000000000000000000000000000000000000000000000", Actor);

        await _gate.ConsumeAsync(p1.Token, RequestHash);

        var pending = await _gate.ListPendingAsync(Actor);

        Assert.Single(pending);
        Assert.Equal("Still pending", pending[0].Summary);
    }

    [Fact]
    public async Task ZeroOrNegativeTtl_DefaultsToFiveMinutes()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor,
            ttl: TimeSpan.Zero);

        // Zero TTL defaults to 5 minutes
        Assert.True(pending.ExpiresUtc >= DateTimeOffset.UtcNow.AddMinutes(4));
        Assert.True(pending.ExpiresUtc <= DateTimeOffset.UtcNow.AddMinutes(6));
    }

    [Fact]
    public async Task TtlIsClamped_ToMaximumFifteenMinutes()
    {
        var pending = await _gate.RequestAsync(
            ToolName, Summary, MutationVerb, EgressTarget, SecretScope, RequestHash, Actor,
            ttl: TimeSpan.FromHours(1));

        Assert.True(pending.ExpiresUtc <= DateTimeOffset.UtcNow.AddMinutes(16));
    }
}
