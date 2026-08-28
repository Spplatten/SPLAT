#define D2D_INPUT_COUNT 0
#define D2D_REQUIRES_SCENE_POSITION

#include "d2d1effecthelpers.hlsli"

// Tactical Radar & Sonar Sweep Shader for Win2D
// Constant buffer parameters for real-time agent telemetry scanning
float2 resolution;
float time;
float intensity;
float4 color;
float2 center;
float sweepSpeed;
float ringCount;
float weights[8]; // weights[0]: trail length, weights[1]: ring intensity, weights[2]: blip intensity, weights[3]: crosshair intensity, weights[4..7]: target blip coordinates

#define PI 3.14159265359
#define TWO_PI 6.28318530718

float saturateSafe(float value)
{
    return saturate(value);
}

D2D_PS_ENTRY(main)
{
    float2 pixel = D2DGetScenePosition().xy;
    float2 safeResolution = max(resolution, float2(1.0, 1.0));
    float2 uv = pixel / safeResolution;
    
    float2 scanCenter = (center.x == 0.0 && center.y == 0.0) ? float2(0.5, 0.5) : center;
    float2 aspectCorrection = float2(safeResolution.x / min(safeResolution.x, safeResolution.y), 
                                     safeResolution.y / min(safeResolution.x, safeResolution.y));
    float2 centeredUv = (uv - scanCenter) * aspectCorrection;
    
    float dist = length(centeredUv);
    float angle = atan2(centeredUv.y, centeredUv.x); // -PI to PI
    if (angle < 0.0)
    {
        angle += TWO_PI;
    }
    
    float speed = (sweepSpeed <= 0.0) ? 2.2 : sweepSpeed;
    float currentSweep = fmod(time * speed, TWO_PI);
    
    // Calculate angular distance behind the sweep beam for the decaying phosphor trail
    float angleDiff = currentSweep - angle;
    if (angleDiff < 0.0)
    {
        angleDiff += TWO_PI;
    }
    
    float trailLength = (weights[0] > 0.0) ? weights[0] : 1.8;
    float trail = exp(-angleDiff * (TWO_PI / trailLength));
    
    // Sharp leading sweep line
    float sweepBeam = smoothstep(0.06, 0.0, angleDiff);
    
    // Concentric range rings
    float rings = (ringCount <= 0.0) ? 4.0 : ringCount;
    float ringPattern = abs(sin(dist * rings * PI * 2.0));
    float ringSharp = smoothstep(0.94, 0.99, ringPattern) * 0.45 * max(weights[1], 0.3);
    
    // Outer boundary ring
    float outerRing = smoothstep(0.48, 0.50, dist) * smoothstep(0.52, 0.50, dist) * 0.8;
    
    // Subtle Crosshair reticle
    float crosshairWidth = 0.003;
    float crosshair = (smoothstep(crosshairWidth, 0.0, abs(centeredUv.x)) + 
                       smoothstep(crosshairWidth, 0.0, abs(centeredUv.y))) * 0.25 * max(weights[3], 0.3);
    
    // Dynamic Agent / Subprocess Target Blips
    float blips = 0.0;
    float2 blip1 = float2(weights[4], weights[5]);
    float2 blip2 = float2(weights[6], weights[7]);
    if (length(blip1) > 0.001)
    {
        float d1 = length(uv - blip1);
        blips += exp(-d1 * 48.0) * (0.6 + 0.4 * sin(time * 6.0));
    }
    if (length(blip2) > 0.001)
    {
        float d2 = length(uv - blip2);
        blips += exp(-d2 * 54.0) * (0.6 + 0.4 * cos(time * 7.5));
    }
    blips *= max(weights[2], 0.5);
    
    // Circular aperture mask to constrain the radar scope
    float aperture = smoothstep(0.52, 0.49, dist);
    
    // Combine total luminance
    float sweepField = (trail * 0.75 + sweepBeam * 1.0 + ringSharp + crosshair + blips) * aperture;
    float alpha = saturateSafe(sweepField * intensity);
    
    // Premultiplied alpha output for Win2D
    float4 tintColor = (color.a <= 0.0) ? float4(0.0, 0.9, 1.0, 1.0) : color;
    float outputAlpha = alpha * tintColor.a;
    return float4(tintColor.rgb * outputAlpha, outputAlpha);
}
