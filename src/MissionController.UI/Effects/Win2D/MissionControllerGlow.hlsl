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
float weights[8];

float saturateSafe(float value)
{
    return saturate(value);
}

D2D_PS_ENTRY(main)
{
    float2 pixel = D2DGetScenePosition().xy;
    float2 safeResolution = max(resolution, float2(1.0, 1.0));
    float2 uv = pixel / safeResolution;
    float distanceFromOrigin = distance(uv, pressOrigin);
    float safeRadius = max(radius, 0.001);
    float safeSoftness = max(softness, 0.001);

    // A short-lived expanding ring gives press feedback without requiring a
    // second image source or a per-frame CPU-generated bitmap.
    float ring = 1.0 - smoothstep(safeRadius, safeRadius + safeSoftness, distanceFromOrigin);
    float core = 1.0 - smoothstep(0.0, safeRadius * 0.78, distanceFromOrigin);
    float pulse = weights[3] + weights[4] * sin(time * 8.0);
    float directionalBias = weights[5] * (uv.x - 0.5) + weights[6] * (uv.y - 0.5);
    float learnedShape = saturateSafe(weights[0] * core + weights[1] * ring + weights[2] + directionalBias + weights[7] * 0.01);
    float alpha = saturateSafe(learnedShape * intensity * pulse);

    // Win2D image effects expect premultiplied output.
    float outputAlpha = alpha * color.a;
    return float4(color.rgb * outputAlpha, outputAlpha);
}
