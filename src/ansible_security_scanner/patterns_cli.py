#!/usr/bin/env python3
"""
CLI tools for Ansible Security Scanner pattern development
"""

import argparse
import sys
from pathlib import Path

import yaml

from .patterns_manager import patterns_manager


def validate_pattern_file(file_path: str) -> bool:
    """Validate a pattern file and print results"""
    path = Path(file_path)
    if not path.exists():
        print(f"❌ Error: File '{file_path}' does not exist")
        return False

    results = patterns_manager.validate_pattern_file(path)

    if results["valid"]:
        print(f"✅ Pattern file '{file_path}' is valid")
        print(f"   📊 Contains {results['pattern_count']} patterns")

        if results["warnings"]:
            print("   ⚠️  Warnings:")
            for warning in results["warnings"]:
                print(f"      - {warning}")
        return True
    print(f"❌ Pattern file '{file_path}' is invalid")
    if results["errors"]:
        print("   🚨 Errors:")
        for error in results["errors"]:
            print(f"      - {error}")
    if results["warnings"]:
        print("   ⚠️  Warnings:")
        for warning in results["warnings"]:
            print(f"      - {warning}")
    return False


def create_pattern_template(name: str, output_path: str) -> bool:
    """Create a new pattern file template"""
    template = {
        "name": f"{name} Patterns",
        "author": "contributor-name",
        "description": f"Security patterns for {name.lower()}",
        "patterns": [
            {
                "id": f"example_{name.lower().replace(' ', '_')}_pattern",
                "category": name.lower().replace(" ", "_"),
                "severity": "HIGH",
                "title": f"Example {name} Pattern",
                "description": f"Description of the {name.lower()} security issue",
                "regex": r"example_regex_pattern_here",
            }
        ],
    }

    try:
        with open(output_path, "w") as f:
            yaml.dump(template, f, default_flow_style=False, indent=2)
        print(f"✅ Created pattern template: {output_path}")
        print("   📝 Edit the file to add your specific patterns")
        print(
            f"   🧪 Test with: python -m ansible_security_scanner.src.plugin_cli validate {output_path}"
        )
        return True
    except Exception as e:
        print(f"❌ Error creating template: {e}")
        return False


def list_patterns() -> None:
    """List all loaded patterns"""
    try:
        pattern_data = patterns_manager.discover_and_load_patterns()
        patterns_info = patterns_manager.get_plugin_info()

        if not patterns_info:
            print("📭 No patterns found")
            return

        print(f"📦 Found {len(patterns_info)} pattern file(s):")
        for pattern_file in patterns_info:
            patterns_count = len(patterns_manager.get_patterns_by_plugin(pattern_file.name))
            print(f"   * {pattern_file.name} v{pattern_file.version}")
            print(f"     👤 Author: {pattern_file.author}")
            print(f"     📊 Patterns: {patterns_count}")
            print(f"     📄 Description: {pattern_file.description}")
            print(f"     📁 File: {pattern_file.file_path}")
            print()

        total_patterns = sum(len(patterns) for patterns in pattern_data.values())
        print(f"📈 Total patterns loaded: {total_patterns}")
        print(f"🏷️  Categories: {', '.join(pattern_data.keys())}")

    except Exception as e:
        print(f"❌ Error listing patterns: {e}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Ansible Security Scanner Pattern Tools",
        epilog="Examples:\n"
        "  python -m ansible_security_scanner.src.patterns_cli validate my_patterns.yml\n"
        "  python -m ansible_security_scanner.src.patterns_cli create 'Docker Security' docker_patterns.yml\n"
        "  python -m ansible_security_scanner.src.patterns_cli list",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    validate_parser = subparsers.add_parser("validate", help="Validate a pattern file")
    validate_parser.add_argument("file", help="Path to the pattern file to validate")

    create_parser = subparsers.add_parser("create", help="Create a new pattern file template")
    create_parser.add_argument(
        "name", help='Name for the pattern category (e.g., "Docker Security")'
    )
    create_parser.add_argument("output", help='Output file path (e.g., "docker_security.yml")')

    subparsers.add_parser("list", help="List all loaded patterns")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    success = True

    if args.command == "validate":
        success = validate_pattern_file(args.file)
    elif args.command == "create":
        success = create_pattern_template(args.name, args.output)
    elif args.command == "list":
        list_patterns()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
