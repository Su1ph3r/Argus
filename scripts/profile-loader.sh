#!/bin/bash
# ============================================================================
# Cloud Security Audit Stack - Profile Loader
# ============================================================================
# Loads scan profiles from YAML files and exports ENABLE_* environment variables
#
# Usage:
#   source profile-loader.sh
#   eval "$(load_profile quick)"
#
# Or in run-all-audits.sh:
#   if [ -n "$PROFILE" ]; then
#       source "$SCRIPT_DIR/profile-loader.sh"
#       eval "$(load_profile $PROFILE)"
#   fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="$(dirname "$SCRIPT_DIR")/profiles"

# List available profiles
list_profiles() {
    echo "Available scan profiles:"
    for profile_file in "$PROFILE_DIR"/*.yml; do
        if [ -f "$profile_file" ]; then
            local name=$(basename "$profile_file" .yml)
            local desc=$(grep "^description:" "$profile_file" | head -1 | sed 's/description: *//' | tr -d '"')
            local duration=$(grep "^duration_estimate:" "$profile_file" | head -1 | sed 's/duration_estimate: *//' | tr -d '"')
            printf "  %-20s %s (%s)\n" "$name" "$desc" "$duration"
        fi
    done
}

# Load a profile and output environment variable exports
load_profile() {
    local profile_name=$1
    local profile_file="$PROFILE_DIR/${profile_name}.yml"

    if [ ! -f "$profile_file" ]; then
        echo "# ERROR: Profile not found: $profile_name" >&2
        echo "# Available profiles:" >&2
        ls -1 "$PROFILE_DIR"/*.yml 2>/dev/null | xargs -n1 basename | sed 's/.yml$//' | sed 's/^/#   /' >&2
        return 1
    fi

    # Use Python to parse YAML and generate exports (more reliable than bash parsing)
    python3 << EOF
import yaml
import sys

try:
    with open('$profile_file') as f:
        profile = yaml.safe_load(f)
except Exception as e:
    print(f"# ERROR: Failed to parse profile: {e}", file=sys.stderr)
    sys.exit(1)

# Output profile info as comments
print(f"# Loading profile: {profile.get('name', '$profile_name')}")
print(f"# Description: {profile.get('description', 'N/A')}")
print(f"# Duration estimate: {profile.get('duration_estimate', 'Unknown')}")
print("")

# Export severity filter if specified
severity_filter = profile.get('severity_filter', '')
if severity_filter:
    print(f'export SEVERITY_FILTER="{severity_filter}"')

# Process tools configuration
tools = profile.get('tools', {})

# Tool name mapping (YAML key -> environment variable suffix)
tool_mapping = {
    # AWS
    'prowler': 'PROWLER',
    'scoutsuite': 'SCOUTSUITE',
    'cloudsploit': 'CLOUDSPLOIT',
    'custodian': 'CUSTODIAN',
    'cloudmapper': 'CLOUDMAPPER',
    'cartography': 'CARTOGRAPHY',
    # Kubernetes
    'kube_bench': 'KUBE_BENCH',
    'kubescape': 'KUBESCAPE',
    'kube_hunter': 'KUBE_HUNTER',
    'trivy': 'TRIVY',
    'grype': 'GRYPE',
    'popeye': 'POPEYE',
    'falco': 'FALCO',
    # IaC
    'checkov': 'CHECKOV',
    'terrascan': 'TERRASCAN',
    'tfsec': 'TFSEC'
}

# Process each category
for category, category_tools in tools.items():
    if not isinstance(category_tools, dict):
        continue

    print(f"# {category.upper()} tools")
    for tool_name, tool_config in category_tools.items():
        if not isinstance(tool_config, dict):
            continue

        env_name = tool_mapping.get(tool_name, tool_name.upper().replace('-', '_'))
        enabled = tool_config.get('enabled', False)
        enabled_str = 'true' if enabled else 'false'

        print(f'export ENABLE_{env_name}={enabled_str}')

        # Handle tool-specific options
        options = tool_config.get('options', {})
        if isinstance(options, dict):
            for opt_key, opt_value in options.items():
                opt_env = f"{env_name}_{opt_key.upper()}"
                if isinstance(opt_value, list):
                    opt_value = ','.join(str(v) for v in opt_value)
                print(f'export {opt_env}="{opt_value}"')

    print("")

print("# Profile loaded successfully")
EOF
}

# Show profile details
show_profile() {
    local profile_name=$1
    local profile_file="$PROFILE_DIR/${profile_name}.yml"

    if [ ! -f "$profile_file" ]; then
        echo "Profile not found: $profile_name"
        return 1
    fi

    echo "=== Profile: $profile_name ==="
    echo ""
    cat "$profile_file"
}

# Main - if script is run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        list)
            list_profiles
            ;;
        show)
            if [ -z "${2:-}" ]; then
                echo "Usage: $0 show <profile_name>"
                exit 1
            fi
            show_profile "$2"
            ;;
        load)
            if [ -z "${2:-}" ]; then
                echo "Usage: $0 load <profile_name>"
                echo "Note: Use 'eval \"\$(./profile-loader.sh load <name>)\"' to apply"
                exit 1
            fi
            load_profile "$2"
            ;;
        *)
            echo "Cloud Security Audit Stack - Profile Loader"
            echo ""
            echo "Usage: $0 <command> [args]"
            echo ""
            echo "Commands:"
            echo "  list              List available profiles"
            echo "  show <name>       Show profile configuration"
            echo "  load <name>       Output environment exports for a profile"
            echo ""
            echo "To apply a profile in your shell:"
            echo "  eval \"\$($0 load quick)\""
            echo ""
            list_profiles
            ;;
    esac
fi
