using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SplatMcp;

public static class McpProtocolVersion
{
    public const string Current = "2024-11-05";
}

public class McpJsonRpcMessage
{
    [JsonPropertyName("jsonrpc")]
    public string JsonRpc { get; set; } = "2.0";

    [JsonPropertyName("id")]
    public JsonElement? Id { get; set; }

    [JsonPropertyName("method")]
    public string? Method { get; set; }

    [JsonPropertyName("params")]
    public JsonElement? Params { get; set; }

    [JsonPropertyName("result")]
    public JsonElement? Result { get; set; }

    [JsonPropertyName("error")]
    public McpError? Error { get; set; }
}

public class McpError
{
    [JsonPropertyName("code")]
    public int Code { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("data")]
    public object? Data { get; set; }
}

public class McpInitializeParams
{
    [JsonPropertyName("protocolVersion")]
    public string? ProtocolVersion { get; set; }

    [JsonPropertyName("clientInfo")]
    public McpImplementation? ClientInfo { get; set; }
}

public class McpImplementation
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;
}

public class McpServerCapabilities
{
    [JsonPropertyName("tools")]
    public McpToolsCapability? Tools { get; set; }

    [JsonPropertyName("logging")]
    public object? Logging { get; set; }
}

public class McpToolsCapability
{
    [JsonPropertyName("listChanged")]
    public bool? ListChanged { get; set; }
}

public class McpInitializeResult
{
    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; set; } = McpProtocolVersion.Current;

    [JsonPropertyName("capabilities")]
    public McpServerCapabilities Capabilities { get; set; } = new();

    [JsonPropertyName("serverInfo")]
    public McpImplementation ServerInfo { get; set; } = new()
    {
        Name = "splat-mcp",
        Version = "1.0.0"
    };

    [JsonPropertyName("instructions")]
    public string? Instructions { get; set; } =
        "SPLAT: Kernel-Sandboxed Execution & Audit Trust Layer. " +
        "All commands, scripts, and file access execute under ephemeral capability leases enforced by BPF-LSM and cgroups.";
}

public class McpToolDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("inputSchema")]
    public JsonElement InputSchema { get; set; }
}

public class McpToolCallParams
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("arguments")]
    public JsonElement? Arguments { get; set; }
}

public class McpToolCallResult
{
    [JsonPropertyName("content")]
    public List<McpContentItem> Content { get; set; } = new();

    [JsonPropertyName("isError")]
    public bool IsError { get; set; }
}

public class McpContentItem
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "text";

    [JsonPropertyName("text")]
    public string Text { get; set; } = string.Empty;
}
