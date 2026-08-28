#define D2D_INPUT_COUNT 0
#define D2D_REQUIRES_SCENE_POSITION

#include "d2d1effecthelpers.hlsli"

// The shader is deliberately source-free: Win2D rasterizes it over the draw
// destination and the CPU only updates the small constant buffer below.
float2 resolution;
float time;
float intensity;
float4 color;
float2 pressOrigin;
float radius;
float softness;
int mode;
float4 accentColor;
float weights[8];

float saturateSafe(float value)
{
    return saturate(value);
}

float hash12(float2 point)
{
    point = frac(point * float2(123.34, 345.45));
    point += dot(point, point + 34.345);
    return frac(point.x * point.y);
}

float valueNoise(float2 point)
{
    float2 cell = floor(point);
    float2 local = frac(point);
    local = local * local * (3.0 - 2.0 * local);

    float bottom = lerp(hash12(cell), hash12(cell + float2(1.0, 0.0)), local.x);
    float top = lerp(hash12(cell + float2(0.0, 1.0)), hash12(cell + float2(1.0, 1.0)), local.x);
    return lerp(bottom, top, local.y);
}

float glowField(float2 uv)
{
    float distanceFromOrigin = distance(uv, pressOrigin);
    float safeRadius = max(radius, 0.001);
    float safeSoftness = max(softness, 0.001);
    float ring = 1.0 - smoothstep(safeRadius, safeRadius + safeSoftness, distanceFromOrigin);
    float core = 1.0 - smoothstep(0.0, safeRadius * 0.78, distanceFromOrigin);
    float directionalBias = weights[5] * (uv.x - 0.5) + weights[6] * (uv.y - 0.5);
    return saturateSafe(weights[0] * core + weights[1] * ring + weights[2] + directionalBias + weights[7] * 0.01);
}

float auroraField(float2 uv)
{
    float waveA = sin(uv.x * 7.0 + sin(uv.y * 5.0 - time * 0.55) * 1.7 + time * 0.7);
    float waveB = sin(uv.x * 11.0 - time * 0.38 + uv.y * 3.0);
    float bandA = exp(-abs(uv.y - 0.50 - waveA * 0.075) * 18.0);
    float bandB = exp(-abs(uv.y - 0.64 - waveB * 0.045) * 24.0);
    float cloud = valueNoise(uv * 5.0 + float2(time * 0.08, -time * 0.04));
    return saturateSafe((bandA * 0.72 + bandB * 0.48) * (0.82 + cloud * 0.18));
}

float scanSweepField(float2 uv)
{
    float progress = frac(time * 0.24);
    float distanceFromSweep = abs(uv.x - progress);
    float sweep = exp(-distanceFromSweep * 52.0);
    float trail = exp(-distanceFromSweep * 13.0) * 0.25;
    float scanLines = 0.76 + 0.24 * sin(uv.y * 180.0);
    return saturateSafe((sweep + trail) * scanLines);
}

float glassNoiseField(float2 uv)
{
    float noise = valueNoise(uv * 18.0 + float2(time * 0.03, time * 0.02));
    float edge = min(min(uv.x, 1.0 - uv.x), min(uv.y, 1.0 - uv.y));
    float bevel = 1.0 - smoothstep(0.0, 0.08, edge);
    float sheen = smoothstep(0.10, 0.42, uv.x + uv.y * 0.22) * (1.0 - smoothstep(0.42, 0.84, uv.x + uv.y * 0.22));
    return saturateSafe(noise * 0.18 + bevel * 0.22 + sheen * 0.44);
}

float radarScanField(float2 uv, float2 safeResolution)
{
    float2 centered = (uv - 0.5) * float2(safeResolution.x / min(safeResolution.x, safeResolution.y), safeResolution.y / min(safeResolution.x, safeResolution.y));
    float dist = length(centered);
    float angle = atan2(centered.y, centered.x);
    if (angle < 0.0) angle += 6.2831853;
    float currentSweep = fmod(time * 2.5, 6.2831853);
    float angleDiff = currentSweep - angle;
    if (angleDiff < 0.0) angleDiff += 6.2831853;
    float trail = exp(-angleDiff * 2.2);
    float beam = smoothstep(0.05, 0.0, angleDiff);
    float rings = smoothstep(0.95, 0.99, abs(sin(dist * 24.0))) * 0.4;
    float aperture = smoothstep(0.52, 0.49, dist);
    return saturateSafe((trail * 0.75 + beam + rings) * aperture);
}

float cyberGridField(float2 uv)
{
    float horizon = 0.35;
    float deltaY = uv.y - horizon;
    float grid = 0.0;
    if (deltaY > 0.005)
    {
        float z = 1.0 / max(deltaY, 0.001);
        float x = (uv.x - 0.5) * z;
        float fwd = smoothstep(0.85, 0.98, frac(z * 0.15 - time * 0.6));
        float lat = smoothstep(0.88, 0.98, frac(x * 0.3)) + smoothstep(0.12, 0.02, frac(x * 0.3));
        float pulse = 0.75 + 0.25 * sin(z * 0.4 - time * 3.0);
        float depthFog = smoothstep(0.0, 0.2, deltaY) * smoothstep(1.0, 0.6, uv.y);
        grid = (fwd * 0.8 + lat * 0.6) * depthFog * pulse;
    }
    float horizonGlow = exp(-abs(uv.y - horizon) * 20.0) * 0.8;
    return saturateSafe(grid + horizonGlow);
}

float electricShieldField(float2 uv)
{
    float2 d = abs(uv - 0.5) - 0.5;
    float distToEdge = -max(d.x, d.y);
    float edgeGlow = smoothstep(0.0, 0.08, distToEdge) * smoothstep(0.16, 0.04, distToEdge);
    float n = valueNoise(uv * 14.0 + float2(time * 3.0, -time * 2.0));
    float arc = pow(abs(sin((n * 6.0 + time * 5.0) * 3.14159)), 10.0) * edgeGlow * 1.5;
    float inner = smoothstep(0.25, 0.0, distToEdge) * 0.25;
    return saturateSafe((edgeGlow * 0.8 + arc + inner) * (0.85 + 0.15 * sin(time * 4.0)));
}

float neuralSynapseField(float2 uv)
{
    float2 n0 = float2(0.3, 0.35) + float2(0.03 * sin(time * 0.9), 0.02 * cos(time * 1.1));
    float2 n1 = float2(0.7, 0.30) + float2(0.02 * cos(time * 1.2), 0.03 * sin(time * 0.8));
    float2 n2 = float2(0.65, 0.70) + float2(0.03 * sin(time * 1.4), 0.02 * cos(time * 1.0));
    float2 nCenter = float2(0.5, 0.5);
    float nodeGlow = exp(-length(uv - n0) * 45.0) + exp(-length(uv - n1) * 45.0) + exp(-length(uv - n2) * 45.0) + exp(-length(uv - nCenter) * 38.0) * 1.3;
    float packet0 = exp(-length(uv - lerp(n0, nCenter, frac(time * 0.6))) * 60.0);
    float packet1 = exp(-length(uv - lerp(nCenter, n1, frac(time * 0.6 + 0.33))) * 60.0);
    float packet2 = exp(-length(uv - lerp(nCenter, n2, frac(time * 0.6 + 0.66))) * 60.0);
    return saturateSafe(nodeGlow * 0.8 + (packet0 + packet1 + packet2) * 1.2);
}

D2D_PS_ENTRY(main)
{
    float2 pixel = D2DGetScenePosition().xy;
    float2 safeResolution = max(resolution, float2(1.0, 1.0));
    float2 uv = pixel / safeResolution;
    float pulse = weights[3] + weights[4] * sin(time * 8.0);
    float field;
    float3 outputColor;

    if (mode == 1)
    {
        field = auroraField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(field * 0.82));
    }
    else if (mode == 2)
    {
        field = scanSweepField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(uv.x * 0.72 + field * 0.28));
    }
    else if (mode == 3)
    {
        field = glassNoiseField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(field * 0.60));
    }
    else if (mode == 4)
    {
        field = radarScanField(uv, safeResolution);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(field * 0.90));
    }
    else if (mode == 5)
    {
        field = cyberGridField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(uv.y * 0.65 + field * 0.35));
    }
    else if (mode == 6)
    {
        field = electricShieldField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(field * 0.95));
    }
    else if (mode == 7)
    {
        field = neuralSynapseField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(field * 0.85));
    }
    else
    {
        // A short-lived expanding ring gives press feedback without requiring
        // a second image source or a per-frame CPU-generated bitmap.
        field = glowField(uv);
        outputColor = lerp(color.rgb, accentColor.rgb, saturateSafe(field * 0.24));
    }

    float alpha = saturateSafe(field * intensity * saturateSafe(pulse));

    // Win2D image effects expect premultiplied output.
    float outputAlpha = alpha * color.a;
    return float4(outputColor * outputAlpha, outputAlpha);
}
