// Minimal fullscreen pass for the native D3D11/12 backend behind
// SwapChainPanelHost. The managed project owns lifecycle only; a native
// renderer can compile this file for ps_5_0 (or the matching shader model)
// and present it through a DXGI flip-discard swap chain.

cbuffer FrameConstants : register(b0)
{
    float2 Resolution;
    float Time;
    float Intensity;
    float4 AccentColor;
};

RWStructuredBuffer<float4> StyleOutput : register(u0);

struct FullscreenVertex
{
    float2 Position : POSITION;
    float2 Uv : TEXCOORD0;
};

struct PixelInput
{
    float4 Position : SV_Position;
    float2 Uv : TEXCOORD0;
};

PixelInput VSMain(FullscreenVertex input)
{
    PixelInput output;
    output.Position = float4(input.Position, 0.0f, 1.0f);
    output.Uv = input.Uv;
    return output;
}

float4 PSMain(PixelInput input) : SV_Target
{
    float2 safeResolution = max(Resolution, float2(1.0f, 1.0f));
    float2 centered = (input.Uv - 0.5f) * float2(safeResolution.x / safeResolution.y, 1.0f);
    float distanceFromCenter = length(centered);
    float pulse = 0.82f + 0.18f * sin(Time * 8.0f);
    float alpha = saturate((1.0f - smoothstep(0.0f, 0.75f, distanceFromCenter)) * Intensity * pulse);
    return float4(AccentColor.rgb * alpha, AccentColor.a * alpha);
}

[numthreads(64, 1, 1)]
void CSMain(uint3 dispatchId : SV_DispatchThreadID)
{
    // Optional compute pass for a native backend that wants to pre-bake a
    // learned style/material field before the fullscreen pixel pass.
    float phase = (float)dispatchId.x * 0.017f + Time;
    float value = saturate(0.5f + 0.5f * sin(phase) * Intensity);
    StyleOutput[dispatchId.x] = float4(value, value, value, 1.0f);
}
