#define D2D_INPUT_COUNT 0
#define D2D_REQUIRES_SCENE_POSITION

#include "d2d1effecthelpers.hlsli"

// High-Energy Electric Shield & Plasma Border Aura Shader for Win2D
// Constant buffer parameters
float2 resolution;
float time;
float intensity;
float4 color;
float borderThickness;
float cornerRadius;
float arcFrequency;
float weights[8]; // weights[0]: plasma noise speed, weights[1]: discharge intensity, weights[2]: inner glow width, weights[3]: pulse speed, weights[4..7]: harmonic phases

#define PI 3.14159265359

float saturateSafe(float value)
{
    return saturate(value);
}

// Pseudo-random noise helper
float hash(float2 p)
{
    float3 p3 = frac(float3(p.xyx) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return frac((p3.x + p3.y) * p3.z);
}

// Simple 2D procedural value noise
float noise(float2 p)
{
    float2 i = floor(p);
    float2 f = frac(p);
    float2 u = f * f * (3.0 - 2.0 * f);
    return lerp(lerp(hash(i + float2(0.0, 0.0)), hash(i + float2(1.0, 0.0)), u.x),
                lerp(hash(i + float2(0.0, 1.0)), hash(i + float2(1.0, 1.0)), u.x), u.y);
}

D2D_PS_ENTRY(main)
{
    float2 pixel = D2DGetScenePosition().xy;
    float2 safeResolution = max(resolution, float2(1.0, 1.0));
    float2 uv = pixel / safeResolution;
    
    // Signed distance to a ROUNDED border.
    //
    // This was a plain rectangular SDF (abs(uv - 0.5) - 0.5), which drew a hard-cornered box - and
    // the cornerRadius constant declared above was never referenced, so it did nothing. Wrapped
    // around a pill-shaped control the box was obvious at the corners.
    //
    // Worked in PIXELS rather than UV on purpose: a radius expressed in UV space is stretched by the
    // aspect ratio, so a wide control would get elliptical corners instead of circular ones.
    float2 halfSizePx = max(safeResolution * 0.5, float2(1.0, 1.0));
    float2 centeredPx = (uv - 0.5) * safeResolution;
    float maxRadiusPx = min(halfSizePx.x, halfSizePx.y);

    // cornerRadius is a fraction (0..1) of the shortest half-dimension. Zero means "fully rounded",
    // i.e. a capsule - which is exactly what an aura around a pill-shaped button needs, so the
    // default requires no plumbing from the host control.
    float radiusPx = (cornerRadius <= 0.0)
        ? maxRadiusPx
        : clamp(cornerRadius, 0.0, 1.0) * maxRadiusPx;

    // Standard rounded-box SDF: negative inside, positive outside.
    float2 q = abs(centeredPx) - halfSizePx + radiusPx;
    float roundedSdf = min(max(q.x, q.y), 0.0) + length(max(q, 0.0)) - radiusPx;

    // Renormalize to the same 0..0.5 range the original UV distance produced, so the edge-thickness
    // and inner-glow thresholds below keep their tuned values.
    float minDimension = max(min(safeResolution.x, safeResolution.y), 1.0);
    float distToEdge = -roundedSdf / minDimension; // Positive inside, negative outside
    
    float edgeThickness = (borderThickness <= 0.0) ? 0.08 : borderThickness;
    float edgeGlow = smoothstep(0.0, edgeThickness, distToEdge) * smoothstep(edgeThickness * 2.0, edgeThickness * 0.5, distToEdge);
    
    // Dynamic plasma & lightning discharge
    float noiseSpeed = (weights[0] > 0.0) ? weights[0] : 2.5;
    float freq = (arcFrequency <= 0.0) ? 12.0 : arcFrequency;
    float n1 = noise(uv * freq + float2(time * noiseSpeed, -time * noiseSpeed * 0.7));
    float n2 = noise(uv * (freq * 2.0) - float2(time * noiseSpeed * 1.2, time * noiseSpeed * 0.5));
    float plasma = (n1 * 0.6 + n2 * 0.4);
    
    // High-frequency electric arcs near the perimeter
    float electricArc = pow(abs(sin((plasma * 8.0 + time * 6.0) * PI)), 12.0) * edgeGlow * max(weights[1], 1.2);
    
    // Core breathing glow
    float pulseSpeed = (weights[3] > 0.0) ? weights[3] : 4.0;
    float pulse = 0.85 + 0.15 * sin(time * pulseSpeed);
    
    // Inner shield shimmer
    float innerWidth = (weights[2] > 0.0) ? weights[2] : 0.25;
    float innerGlow = smoothstep(innerWidth, 0.0, distToEdge) * 0.3 * pulse;
    
    // Confine everything to the rounded shape. Rounding introduced regions of the quad that lie
    // OUTSIDE the border - the four corners - where distToEdge goes negative. innerGlow uses a
    // reversed smoothstep, which returns 1.0 for negative input, so without this mask the corners
    // would light up: exactly the square outline the rounded SDF was added to remove.
    // The narrow band gives one antialiased pixel of falloff instead of a stair-stepped edge.
    float aaWidth = 1.5 / minDimension;
    float shapeMask = smoothstep(-aaWidth, aaWidth, distToEdge);

    float totalEnergy = (edgeGlow * 0.8 + electricArc + innerGlow) * pulse * shapeMask;
    float alpha = saturateSafe(totalEnergy * intensity);
    
    float4 tintColor = (color.a <= 0.0) ? float4(0.0, 0.9, 1.0, 1.0) : color;
    float outputAlpha = alpha * tintColor.a;
    return float4(tintColor.rgb * outputAlpha, outputAlpha);
}
