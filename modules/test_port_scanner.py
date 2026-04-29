"""
Quick test script for port scanner module
"""
from port_scanner import scan_ports

print("Testing port scanner...")
results = scan_ports()

# Quick checks
if results.get('listening_ports', {}).get('enumeration_successful'):
    print("✓ Port enumeration successful")
    print(f"  Found {results['listening_ports']['total_listening']} listening ports")
else:
    print("✗ Port enumeration failed - check admin privileges")

if results.get('dangerous_ports_found', {}).get('analysis_available'):
    dangerous = results['dangerous_ports_found']['total_dangerous_ports']
    print(f"✓ Found {dangerous} dangerous ports")
else:
    print("✗ Dangerous port analysis unavailable")

if results.get('risk_assessment', {}).get('analysis_available'):
    risk = results['risk_assessment']['overall_risk']
    score = results['risk_assessment']['risk_score']
    print(f"✓ Risk assessment: {risk} ({score}/10)")
else:
    print("✗ Risk assessment unavailable")