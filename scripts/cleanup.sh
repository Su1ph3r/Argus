#!/bin/bash
# ============================================================================
# Nubicustos - Cleanup Utility
# ============================================================================
# Clean up Docker containers, images, and volumes after docker compose down

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# CLI Options (defaults)
DRY_RUN=false
FORCE=false
DO_CONTAINERS=false
DO_IMAGES=false
DO_IMAGES_LOCAL=false
DO_VOLUMES=false
DO_PRUNE=false
DO_ALL=false
INTERACTIVE=false

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Named volumes used by the project
PROJECT_VOLUMES=(
    "nubicustos_postgres-data"
    "nubicustos_neo4j-data"
    "nubicustos_neo4j-logs"
    "nubicustos_neo4j-plugins"
    "nubicustos_pacu-data"
    "nubicustos_trivy-cache"
    "nubicustos_grype-cache"
    "nubicustos_cloudfox-data"
)

# ============================================================================
# Logging
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)    echo -e "${BLUE}[$timestamp]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[$timestamp]${NC} $message" ;;
        WARN)    echo -e "${YELLOW}[$timestamp]${NC} WARNING: $message" ;;
        ERROR)   echo -e "${RED}[$timestamp]${NC} ERROR: $message" >&2 ;;
        DRY)     echo -e "${YELLOW}[DRY-RUN]${NC} Would: $message" ;;
    esac
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    cat << EOF
Nubicustos - Cleanup Utility

Usage: $(basename "$0") [OPTIONS]

Clean up Docker containers, images, and volumes after docker compose down.
If no options specified, runs in interactive mode.

OPTIONS:
  --containers       Stop and remove all project containers
  --images           Remove all project images (built + pulled)
  --images-local     Remove only locally built images (api, frontend, etc.)
  --volumes          Remove named volumes (WARNING: deletes database data!)
  --prune            Run docker system prune (dangling images, networks, cache)
  --all              Complete cleanup (containers + images + volumes + prune)
  --dry-run          Show what would be removed without executing
  --force            Skip confirmation prompts
  -h, --help         Show this help message

EXAMPLES:
  $(basename "$0")                    # Interactive menu
  $(basename "$0") --containers       # Remove containers only (safe)
  $(basename "$0") --images           # Remove all project images
  $(basename "$0") --images-local     # Remove only locally built images
  $(basename "$0") --all              # Complete cleanup
  $(basename "$0") --all --force      # Complete cleanup without prompts
  $(basename "$0") --dry-run --all    # Preview complete cleanup

CLEANUP LEVELS:
  containers    Safe - just stops/removes containers
  images-local  Moderate - removes locally built images (api, frontend)
  images        Significant - removes all images (requires re-download)
  volumes       Data loss - removes databases and cache (PostgreSQL, Neo4j)
  prune         Cleanup - removes dangling resources

EOF
}

# ============================================================================
# Confirmation
# ============================================================================

confirm() {
    local message="$1"

    if [ "$FORCE" = true ]; then
        return 0
    fi

    echo -e "${YELLOW}$message${NC}"
    read -r -p "Continue? [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# ============================================================================
# Docker Info
# ============================================================================

show_disk_usage() {
    echo ""
    echo "Current Docker disk usage:"
    echo "=========================="
    docker system df 2>/dev/null || echo "  (Unable to retrieve disk usage)"
    echo ""
}

check_running_containers() {
    local running
    running=$(docker compose -f "$PROJECT_DIR/docker-compose.yml" ps -q 2>/dev/null | wc -l | tr -d ' ')

    if [ "$running" -gt 0 ]; then
        log WARN "There are $running running container(s)"
        return 1
    fi
    return 0
}

# ============================================================================
# Cleanup Functions
# ============================================================================

cleanup_containers() {
    log INFO "Stopping and removing containers..."

    if [ "$DRY_RUN" = true ]; then
        log DRY "docker compose -f $PROJECT_DIR/docker-compose.yml down"
        return 0
    fi

    cd "$PROJECT_DIR"
    docker compose down 2>&1
    log SUCCESS "Containers removed"
}

cleanup_images_local() {
    log INFO "Removing locally built images..."

    if [ "$DRY_RUN" = true ]; then
        log DRY "docker compose -f $PROJECT_DIR/docker-compose.yml down --rmi local"
        return 0
    fi

    cd "$PROJECT_DIR"
    docker compose down --rmi local 2>&1
    log SUCCESS "Local images removed"
}

cleanup_images_all() {
    log INFO "Removing all project images..."

    if [ "$DRY_RUN" = true ]; then
        log DRY "docker compose -f $PROJECT_DIR/docker-compose.yml down --rmi all"
        return 0
    fi

    cd "$PROJECT_DIR"
    docker compose down --rmi all 2>&1
    log SUCCESS "All images removed"
}

cleanup_volumes() {
    log WARN "This will delete all database data and caches!"
    echo ""
    echo "Volumes to be removed:"
    for vol in "${PROJECT_VOLUMES[@]}"; do
        if docker volume ls -q | grep -q "^${vol}$"; then
            echo "  - $vol (exists)"
        fi
    done
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log DRY "docker compose -f $PROJECT_DIR/docker-compose.yml down --volumes"
        return 0
    fi

    if ! confirm "Are you sure you want to delete all volumes?"; then
        log INFO "Volume cleanup cancelled"
        return 1
    fi

    cd "$PROJECT_DIR"
    docker compose down --volumes 2>&1
    log SUCCESS "Volumes removed"
}

cleanup_prune() {
    log INFO "Running docker system prune..."

    if [ "$DRY_RUN" = true ]; then
        log DRY "docker system prune -f"
        echo ""
        echo "This would remove:"
        docker system prune --dry-run 2>/dev/null || true
        return 0
    fi

    docker system prune -f 2>&1
    log SUCCESS "System pruned"
}

cleanup_all() {
    log INFO "Starting complete cleanup..."
    echo ""

    cleanup_containers
    cleanup_images_all
    cleanup_volumes
    cleanup_prune

    log SUCCESS "Complete cleanup finished"
}

# ============================================================================
# Interactive Menu
# ============================================================================

interactive_menu() {
    while true; do
        clear
        echo "============================================"
        echo "       Nubicustos Cleanup Utility"
        echo "============================================"
        echo ""

        show_disk_usage

        echo "Select cleanup level:"
        echo ""
        echo "  1) Containers only (safe)"
        echo "  2) Containers + locally built images"
        echo "  3) Containers + all images"
        echo "  4) Containers + images + volumes (DATA LOSS!)"
        echo "  5) Full cleanup (all above + system prune)"
        echo "  6) System prune only (dangling resources)"
        echo ""
        echo "  d) Dry-run mode (preview actions)"
        echo "  q) Quit"
        echo ""

        read -r -p "Choice: " choice

        case "$choice" in
            1)
                confirm "Remove containers?" && cleanup_containers
                ;;
            2)
                confirm "Remove containers and locally built images?" && {
                    cleanup_containers
                    cleanup_images_local
                }
                ;;
            3)
                confirm "Remove containers and ALL images? (will need to re-download)" && {
                    cleanup_containers
                    cleanup_images_all
                }
                ;;
            4)
                echo -e "${RED}WARNING: This will delete all database data!${NC}"
                confirm "Remove containers, images, AND volumes?" && {
                    cleanup_containers
                    cleanup_images_all
                    cleanup_volumes
                }
                ;;
            5)
                echo -e "${RED}WARNING: This is a complete cleanup with data loss!${NC}"
                confirm "Perform full cleanup?" && cleanup_all
                ;;
            6)
                confirm "Run system prune?" && cleanup_prune
                ;;
            d|D)
                DRY_RUN=true
                echo ""
                echo "Dry-run mode enabled. Select an option to preview:"
                read -r -p "Press Enter to continue..."
                ;;
            q|Q)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                echo "Invalid option"
                read -r -p "Press Enter to continue..."
                ;;
        esac

        echo ""
        read -r -p "Press Enter to continue..."
    done
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_args() {
    if [ $# -eq 0 ]; then
        INTERACTIVE=true
        return 0
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --containers)
                DO_CONTAINERS=true
                shift
                ;;
            --images)
                DO_IMAGES=true
                shift
                ;;
            --images-local)
                DO_IMAGES_LOCAL=true
                shift
                ;;
            --volumes)
                DO_VOLUMES=true
                shift
                ;;
            --prune)
                DO_PRUNE=true
                shift
                ;;
            --all)
                DO_ALL=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                echo ""
                show_help
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Main
# ============================================================================

main() {
    parse_args "$@"

    # Interactive mode
    if [ "$INTERACTIVE" = true ]; then
        interactive_menu
        exit 0
    fi

    # Non-interactive mode
    if [ "$DRY_RUN" = true ]; then
        log INFO "Running in dry-run mode - no changes will be made"
        echo ""
    fi

    # Complete cleanup
    if [ "$DO_ALL" = true ]; then
        if [ "$DRY_RUN" = false ]; then
            echo -e "${RED}WARNING: Complete cleanup will delete all data!${NC}"
            if ! confirm "Proceed with complete cleanup?"; then
                log INFO "Cleanup cancelled"
                exit 0
            fi
        fi
        cleanup_all
        exit 0
    fi

    # Selective cleanup
    if [ "$DO_CONTAINERS" = true ]; then
        cleanup_containers
    fi

    if [ "$DO_IMAGES_LOCAL" = true ]; then
        cleanup_images_local
    fi

    if [ "$DO_IMAGES" = true ]; then
        cleanup_images_all
    fi

    if [ "$DO_VOLUMES" = true ]; then
        cleanup_volumes
    fi

    if [ "$DO_PRUNE" = true ]; then
        cleanup_prune
    fi

    # If no action specified
    if [ "$DO_CONTAINERS" = false ] && [ "$DO_IMAGES" = false ] && \
       [ "$DO_IMAGES_LOCAL" = false ] && [ "$DO_VOLUMES" = false ] && \
       [ "$DO_PRUNE" = false ] && [ "$DO_ALL" = false ]; then
        log ERROR "No cleanup action specified"
        echo ""
        show_help
        exit 1
    fi

    log SUCCESS "Cleanup complete"
}

main "$@"
