#!/usr/bin/env python3
"""
Quick test script to demonstrate IAM Policy Analyzer functionality.
Run this to verify everything is working correctly.
"""

import json
from pathlib import Path

from iam_policy_analyzer.analyzer import IAMAnalyzer
from iam_policy_analyzer.models import Severity

def run_demo():
    """Run a quick demo of the analyzer."""
    
    print("=" * 60)
    print("🔒 IAM Policy Analyzer - Demo")
    print("=" * 60)
    print()
    
    analyzer = IAMAnalyzer()
    
    # Test 1: Bad policy with wildcards
    print("📋 Test 1: Policy with wildcard permissions")
    print("-" * 60)
    
    bad_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "*",
            "Resource": "*"
        }]
    }
    
    result = analyzer.analyze_policy(
        analyzer.registry.get_all()[0].__class__.__bases__[0].__new__(
            type('PolicyDoc', (), {
                'policy_type': type('PolicyType', (), {'GENERIC': 'generic'})(),
                'raw_policy': bad_policy,
                'name': 'BadAdminPolicy',
                'resources': ['*'],
                'actions': ['*'],
                'principals': ['*'],
                'conditions': {},
                'effect': 'Allow',
                'metadata': {}
            })
        )
    )
    
    print(f"✓ Found {len(result.findings)} violations:")
    for finding in result.findings[:3]:  # Show first 3
        print(f"  • {finding.severity.value}: {finding.message}")
    print()
    
    # Test 2: Good policy
    print("📋 Test 2: Good least-privilege policy")
    print("-" * 60)
    
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/*"
        }]
    }
    
    from iam_policy_analyzer.models import PolicyDocument, PolicyType
    good_doc = PolicyDocument(
        policy_type=PolicyType.GENERIC,
        raw_policy=good_policy,
        name='GoodS3Policy',
        resources=['arn:aws:s3:::my-bucket/*'],
        actions=['s3:GetObject'],
        principals=[],
        conditions={},
        effect='Allow',
    )
    
    result = analyzer.analyze_policy(good_doc)
    print(f"✓ Found {len(result.findings)} violations")
    print()
    
    # Test 3: Example files
    print("📋 Test 3: Analyzing example files")
    print("-" * 60)
    
    examples_dir = Path("examples")
    if examples_dir.exists():
        for policy_file in sorted(examples_dir.glob("*.json")):
            try:
                result = analyzer.analyze_file(str(policy_file))
                print(f"✓ {policy_file.name}")
                print(f"  Findings: {result.summary['total']} " +
                      f"(Critical: {result.summary['critical']}, " +
                      f"High: {result.summary['high']})")
            except Exception as e:
                print(f"✗ {policy_file.name}: {e}")
    else:
        print("  (No examples directory found)")
    
    print()
    print("=" * 60)
    print("✓ Demo complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Try analyzing a policy file:")
    print("     iam-analyzer analyze examples/bad-policy-wildcards.json")
    print()
    print("  2. View all available commands:")
    print("     iam-analyzer --help")
    print()

if __name__ == "__main__":
    run_demo()
