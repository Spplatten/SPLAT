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
    float4 SecondaryColor;
    uint EffectMode;
    float EffectScale;
    float EffectSpeed;
    uint StyleSampleCount;
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
    float safeScale = clamp(EffectScale, 0.25f, 4.0f);
    float safeSpeed = clamp(EffectSpeed, 0.0f, 2.0f);
    float phase = Time * safeSpeed;
    float alpha;
    float3 effectColor = AccentColor.rgb;

    if (EffectMode == 1)
    {
        // Two low-frequency bands create a calm aurora without strobing or
        // high-frequency detail that would compete with operational data.
        float waveA = sin((input.Uv.x * 5.0f + phase * 0.7f) * safeScale);
        float waveB = sin((input.Uv.x * 3.2f - phase * 0.45f) * safeScale + 1.7f);
        float ribbon = 1.0f - smoothstep(0.04f, 0.34f, abs(input.Uv.y - 0.56f - waveA * 0.07f - waveB * 0.035f));
        alpha = saturate(ribbon * Intensity * 0.52f);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, saturate(input.Uv.x + waveB * 0.12f));
    }
    else if (EffectMode == 2)
    {
        float sweepPosition = frac(phase * 0.11f) * 1.4f - 0.2f;
        float sweep = 1.0f - smoothstep(0.0f, 0.075f, abs(input.Uv.y - sweepPosition));
        float grid = smoothstep(0.94f, 1.0f, sin(input.Uv.x * safeResolution.x * 0.12f) * 0.5f + 0.5f);
        alpha = saturate((sweep * 0.72f + grid * sweep * 0.15f) * Intensity);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, sweep * 0.35f);
    }
    else if (EffectMode == 3)
    {
        float2 noiseCell = floor(input.Uv * safeResolution / max(2.0f, 5.0f / safeScale));
        float noise = frac(sin(dot(noiseCell, float2(12.9898f, 78.233f))) * 43758.5453f);
        float vignette = 1.0f - smoothstep(0.28f, 0.82f, distanceFromCenter);
        alpha = saturate((0.025f + noise * 0.055f + vignette * 0.08f) * Intensity);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, noise * 0.28f);
    }
    else if (EffectMode == 4)
    {
        // Tactical Radar Scan
        float angle = atan2(centered.y, centered.x);
        if (angle < 0.0f) angle += 6.2831853f;
        float sweep = fmod(phase * 2.5f, 6.2831853f);
        float diff = sweep - angle;
        if (diff < 0.0f) diff += 6.2831853f;
        float trail = exp(-diff * 2.5f);
        float rings = smoothstep(0.94f, 0.99f, abs(sin(distanceFromCenter * 20.0f))) * 0.35f;
        float aperture = smoothstep(0.52f, 0.49f, distanceFromCenter);
        alpha = saturate((trail * 0.7f + rings + smoothstep(0.04f, 0.0f, diff)) * aperture * Intensity);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, trail * 0.6f);
    }
    else if (EffectMode == 5)
    {
        // 3D Perspective Cyberspace Grid
        float deltaY = input.Uv.y - 0.38f;
        float grid = 0.0f;
        if (deltaY > 0.005f)
        {
            float z = 1.0f / max(deltaY, 0.001f);
            float x = (input.Uv.x - 0.5f) * z;
            float fwd = smoothstep(0.85f, 0.98f, frac(z * 0.15f - phase * 0.6f));
            float lat = smoothstep(0.88f, 0.98f, frac(x * 0.3f)) + smoothstep(0.12f, 0.02f, frac(x * 0.3f));
            grid = (fwd * 0.8f + lat * 0.5f) * smoothstep(0.0f, 0.2f, deltaY);
        }
        float horizon = exp(-abs(input.Uv.y - 0.38f) * 20.0f) * 0.75f;
        alpha = saturate((grid + horizon) * Intensity);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, input.Uv.y);
    }
    else if (EffectMode == 6)
    {
        // High-Energy Electric Containment Aura
        float2 d = abs(input.Uv - 0.5f) - 0.5f;
        float distToEdge = -max(d.x, d.y);
        float edgeGlow = smoothstep(0.0f, 0.08f, distToEdge) * smoothstep(0.16f, 0.04f, distToEdge);
        float noise = frac(sin(dot(floor(input.Uv * 40.0f + phase * 4.0f), float2(12.9898f, 78.233f))) * 43758.5453f);
        float electric = pow(abs(sin((noise * 4.0f + phase * 6.0f) * 3.14159f)), 8.0f) * edgeGlow * 1.6f;
        alpha = saturate((edgeGlow * 0.7f + electric) * Intensity);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, electric * 0.8f);
    }
    else if (EffectMode == 7)
    {
        // Neural Synapse Network
        float2 n0 = float2(0.35f, 0.40f) + float2(0.04f * sin(phase * 0.9f), 0.03f * cos(phase * 1.1f));
        float2 n1 = float2(0.65f, 0.60f) + float2(0.03f * cos(phase * 1.2f), 0.04f * sin(phase * 0.8f));
        float d0 = length(input.Uv - n0);
        float d1 = length(input.Uv - n1);
        float node = exp(-d0 * 35.0f) + exp(-d1 * 35.0f);
        float packet = exp(-length(input.Uv - lerp(n0, n1, frac(phase * 0.7f))) * 50.0f) * 1.5f;
        alpha = saturate((node + packet) * Intensity);
        effectColor = lerp(AccentColor.rgb, SecondaryColor.rgb, packet * 0.7f);
    }
    else
    {
        float pulse = 0.88f + 0.12f * sin(phase * 4.0f);
        alpha = saturate((1.0f - smoothstep(0.0f, 0.75f / safeScale, distanceFromCenter)) * Intensity * pulse);
    }

    float outputAlpha = alpha * AccentColor.a;
    return float4(effectColor * outputAlpha, outputAlpha);
}

[numthreads(64, 1, 1)]
void CSMain(uint3 dispatchId : SV_DispatchThreadID)
{
    if (dispatchId.x >= StyleSampleCount)
    {
        return;
    }

    // Optional compute pass for a native backend that wants to pre-bake a
    // learned style/material field before the fullscreen pixel pass.
    float phase = (float)dispatchId.x * 0.017f + Time;
    float value = saturate(0.5f + 0.5f * sin(phase) * Intensity);
    StyleOutput[dispatchId.x] = float4(value, value, value, 1.0f);
}
