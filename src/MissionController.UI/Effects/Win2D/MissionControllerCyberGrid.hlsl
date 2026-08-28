#define D2D_INPUT_COUNT 0
#define D2D_REQUIRES_SCENE_POSITION

#include "d2d1effecthelpers.hlsli"

// Cyberspace Perspective Grid & Horizon Energy Wave Shader for Win2D
// Constant buffer parameters
float2 resolution;
float time;
float intensity;
float4 color;
float horizonY;
float gridSpacing;
float speed;
float weights[8]; // weights[0]: horizon glow, weights[1]: perspective depth, weights[2]: wave amplitude, weights[3]: wave frequency, weights[4..7]: secondary harmonics

#define PI 3.14159265359

float saturateSafe(float value)
{
    return saturate(value);
}

D2D_PS_ENTRY(main)
{
    float2 pixel = D2DGetScenePosition().xy;
    float2 safeResolution = max(resolution, float2(1.0, 1.0));
    float2 uv = pixel / safeResolution;
    
    float horizon = (horizonY <= 0.0) ? 0.35 : horizonY;
    float flowSpeed = (speed <= 0.0) ? 1.0 : speed;
    
    // Check if pixel is below horizon (the 3D floor) or above horizon (sky / energy field)
    float deltaY = uv.y - horizon;
    
    float gridVal = 0.0;
    float horizonGlowVal = 0.0;
    
    if (deltaY > 0.005)
    {
        // 3D Perspective Projection
        float depth = max(deltaY, 0.001);
        float z = 1.0 / depth;
        float x = (uv.x - 0.5) * z * max(weights[1], 1.0);
        
        // Flowing forward grid lines
        float forwardGrid = frac(z * 0.15 - time * flowSpeed * 0.5);
        float forwardLine = smoothstep(0.85, 0.98, forwardGrid);
        
        // Longitudinal perspective lines
        float lateralSpacing = (gridSpacing <= 0.0) ? 0.25 : gridSpacing;
        float lateralGrid = frac(x * lateralSpacing);
        float lateralLine = smoothstep(0.88, 0.98, lateralGrid) + smoothstep(0.12, 0.02, lateralGrid);
        
        // Cyber dynamic pulse wave
        float waveAmp = (weights[2] > 0.0) ? weights[2] : 0.3;
        float waveFreq = (weights[3] > 0.0) ? weights[3] : 4.0;
        float energyPulse = 0.7 + waveAmp * sin(z * 0.4 - time * 3.0 + x * waveFreq);
        
        // Depth atmospheric fog / fade toward horizon and far edge
        float depthFog = smoothstep(0.0, 0.2, deltaY) * smoothstep(1.0, 0.6, uv.y);
        gridVal = (forwardLine * 0.8 + lateralLine * 0.6) * depthFog * energyPulse;
    }
    
    // Horizon glow aura
    float horizonDist = abs(uv.y - horizon);
    float glowCoeff = (weights[0] > 0.0) ? weights[0] : 0.8;
    horizonGlowVal = exp(-horizonDist * 18.0) * glowCoeff;
    
    // Add pulsing digital scan wave across whole canvas
    float scanline = 0.95 + 0.05 * sin(uv.y * safeResolution.y * 1.5 + time * 5.0);
    
    float totalEffect = (gridVal + horizonGlowVal) * scanline;
    float alpha = saturateSafe(totalEffect * intensity);
    
    float4 tintColor = (color.a <= 0.0) ? float4(0.0, 0.85, 1.0, 1.0) : color;
    float outputAlpha = alpha * tintColor.a;
    return float4(tintColor.rgb * outputAlpha, outputAlpha);
}
