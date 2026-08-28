#define D2D_INPUT_COUNT 0
#define D2D_REQUIRES_SCENE_POSITION

#include "d2d1effecthelpers.hlsli"

// Neural Synapse & Quantum Memory Node Network Shader for Win2D
// Constant buffer parameters
float2 resolution;
float time;
float intensity;
float4 color;
float nodeCount;
float connectionDistance;
float pulseSpeed;
float weights[8]; // weights[0]: node pulse scale, weights[1]: link brightness, weights[2]: packet speed, weights[3]: particle jitter, weights[4..7]: node state modulators

#define PI 3.14159265359

float saturateSafe(float value)
{
    return saturate(value);
}

// Distance from point p to line segment ab
float distToSegment(float2 p, float2 a, float2 b)
{
    float2 pa = p - a;
    float2 ba = b - a;
    float h = saturate(dot(pa, ba) / dot(ba, ba));
    return length(pa - ba * h);
}

D2D_PS_ENTRY(main)
{
    float2 pixel = D2DGetScenePosition().xy;
    float2 safeResolution = max(resolution, float2(1.0, 1.0));
    float2 uv = pixel / safeResolution;
    
    // Deterministic procedural node positions (4 interconnected neural clusters)
    float2 n0 = float2(0.25, 0.35) + float2(0.04 * sin(time * 0.8), 0.03 * cos(time * 0.9));
    float2 n1 = float2(0.75, 0.30) + float2(0.03 * cos(time * 1.1), 0.04 * sin(time * 0.7));
    float2 n2 = float2(0.65, 0.75) + float2(0.04 * sin(time * 1.3), 0.03 * cos(time * 1.0));
    float2 n3 = float2(0.30, 0.70) + float2(0.03 * cos(time * 0.7), 0.04 * sin(time * 1.2));
    float2 nCenter = float2(0.50, 0.50) + float2(0.02 * sin(time * 1.5), 0.02 * cos(time * 1.4));
    
    // Distance to each node and render glowing synaptic body
    float d0 = length(uv - n0);
    float d1 = length(uv - n1);
    float d2 = length(uv - n2);
    float d3 = length(uv - n3);
    float dc = length(uv - nCenter);
    
    float pulseMult = (weights[0] > 0.0) ? weights[0] : 1.0;
    float nodeGlow = 0.0;
    nodeGlow += exp(-d0 * 40.0) * (0.8 + 0.3 * sin(time * 3.0 * pulseMult));
    nodeGlow += exp(-d1 * 40.0) * (0.8 + 0.3 * sin(time * 3.5 * pulseMult + 1.0));
    nodeGlow += exp(-d2 * 40.0) * (0.8 + 0.3 * sin(time * 2.8 * pulseMult + 2.0));
    nodeGlow += exp(-d3 * 40.0) * (0.8 + 0.3 * sin(time * 3.2 * pulseMult + 3.0));
    nodeGlow += exp(-dc * 35.0) * (1.0 + 0.4 * sin(time * 4.0 * pulseMult));
    
    // Synaptic axon lines between nodes
    float linkBrightness = (weights[1] > 0.0) ? weights[1] : 0.6;
    float links = 0.0;
    float lineThickness = 0.004;
    
    float seg0c = distToSegment(uv, n0, nCenter);
    float seg1c = distToSegment(uv, n1, nCenter);
    float seg2c = distToSegment(uv, n2, nCenter);
    float seg3c = distToSegment(uv, n3, nCenter);
    float seg01 = distToSegment(uv, n0, n1);
    float seg23 = distToSegment(uv, n2, n3);
    
    links += smoothstep(lineThickness, 0.0, seg0c) * 0.7;
    links += smoothstep(lineThickness, 0.0, seg1c) * 0.7;
    links += smoothstep(lineThickness, 0.0, seg2c) * 0.7;
    links += smoothstep(lineThickness, 0.0, seg3c) * 0.7;
    links += smoothstep(lineThickness * 0.7, 0.0, seg01) * 0.4;
    links += smoothstep(lineThickness * 0.7, 0.0, seg23) * 0.4;
    links *= linkBrightness;
    
    // Travelling signal packets along axons
    float speed = (pulseSpeed <= 0.0) ? 1.5 : pulseSpeed;
    float packetSpeed = (weights[2] > 0.0) ? weights[2] : 1.0;
    float tPhase = frac(time * speed * packetSpeed * 0.4);
    
    float2 p0 = lerp(n0, nCenter, tPhase);
    float2 p1 = lerp(n1, nCenter, frac(tPhase + 0.25));
    float2 p2 = lerp(nCenter, n2, frac(tPhase + 0.5));
    float2 p3 = lerp(nCenter, n3, frac(tPhase + 0.75));
    
    float packetGlow = 0.0;
    packetGlow += exp(-length(uv - p0) * 60.0);
    packetGlow += exp(-length(uv - p1) * 60.0);
    packetGlow += exp(-length(uv - p2) * 60.0);
    packetGlow += exp(-length(uv - p3) * 60.0);
    packetGlow *= 1.2;
    
    // Ambient neural quantum field
    float ambient = 0.05 + 0.05 * sin(uv.x * 10.0 + uv.y * 10.0 + time);
    
    float totalNeural = nodeGlow + links + packetGlow + ambient;
    float alpha = saturateSafe(totalNeural * intensity);
    
    float4 tintColor = (color.a <= 0.0) ? float4(0.8, 0.4, 1.0, 1.0) : color;
    float outputAlpha = alpha * tintColor.a;
    return float4(tintColor.rgb * outputAlpha, outputAlpha);
}
