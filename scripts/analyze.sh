#!/usr/bin/env bash
# ClearCage CLI wrapper — analyze files or URLs via curl
# Usage:
#   ./scripts/analyze.sh file /path/to/suspicious.exe
#   ./scripts/analyze.sh url https://suspicious.example.com
#   ./scripts/analyze.sh export <analysis_id> json|csv

set -euo pipefail

BASE_URL="${CLEARCAGE_URL:-http://localhost:8000}"

usage() {
    echo "ClearCage CLI — Threat Analysis"
    echo ""
    echo "Usage:"
    echo "  $0 file <path>       Analyze a local file"
    echo "  $0 url <url>         Analyze a URL"
    echo "  $0 status <id>       Check analysis status"
    echo "  $0 export <id> fmt   Export results (json|csv)"
    echo ""
    echo "Environment:"
    echo "  CLEARCAGE_URL  Backend URL (default: http://localhost:8000)"
    exit 1
}

[[ $# -lt 2 ]] && usage

MODE="$1"
shift

case "$MODE" in
    file)
        FILE_PATH="$1"
        if [[ ! -f "$FILE_PATH" ]]; then
            echo "Error: File not found: $FILE_PATH"
            exit 1
        fi

        echo "Uploading $(basename "$FILE_PATH") for analysis..."
        RESPONSE=$(curl -s -F "file=@${FILE_PATH}" "${BASE_URL}/api/analyze/file")

        # Extract analysis ID from HTML response
        ANALYSIS_ID=$(echo "$RESPONSE" | grep -oP '/analysis/\K[a-f0-9]+' | head -1)

        if [[ -z "$ANALYSIS_ID" ]]; then
            echo "Error: Failed to get analysis ID"
            echo "$RESPONSE"
            exit 1
        fi

        echo "Analysis queued: $ANALYSIS_ID"
        echo "View results: ${BASE_URL}/analysis/${ANALYSIS_ID}"
        ;;

    url)
        URL="$1"
        echo "Analyzing URL: $URL"
        RESPONSE=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "{\"url_input\": \"${URL}\"}" \
            "${BASE_URL}/api/analyze/url")

        ANALYSIS_ID=$(echo "$RESPONSE" | grep -oP '/analysis/\K[a-f0-9]+' | head -1)

        if [[ -z "$ANALYSIS_ID" ]]; then
            echo "Error: Failed to get analysis ID"
            echo "$RESPONSE"
            exit 1
        fi

        echo "Analysis queued: $ANALYSIS_ID"
        echo "View results: ${BASE_URL}/analysis/${ANALYSIS_ID}"
        ;;

    status)
        ANALYSIS_ID="$1"
        curl -s "${BASE_URL}/api/analysis/${ANALYSIS_ID}" | python3 -m json.tool 2>/dev/null \
            || curl -s "${BASE_URL}/api/analysis/${ANALYSIS_ID}"
        ;;

    export)
        if [[ $# -lt 2 ]]; then
            echo "Usage: $0 export <id> json|csv"
            exit 1
        fi
        ANALYSIS_ID="$1"
        FORMAT="$2"
        curl -s -o "clearcage-${ANALYSIS_ID}.${FORMAT}" \
            "${BASE_URL}/api/export/${ANALYSIS_ID}/${FORMAT}"
        echo "Exported to: clearcage-${ANALYSIS_ID}.${FORMAT}"
        ;;

    *)
        echo "Unknown mode: $MODE"
        usage
        ;;
esac
