# Bash completion for scripts/run_tests.sh and scripts/bridge.sh
_privmx_repo_root() {
    local cmd="${COMP_WORDS[0]}"
    if [[ "$cmd" == */* ]]; then
        (cd "$(dirname "$cmd")/.." 2>/dev/null && pwd)
    else
        git rev-parse --show-toplevel 2>/dev/null
    fi
}

_privmx_gtest_names() {
    local root="$1" dirs=("$1/test/tests")
    [[ " ${COMP_WORDS[*]} " == *" --unit-only "* ]] && dirs=("$root/test/tests/unit")
    [[ " ${COMP_WORDS[*]} " == *" --e2e-only "* ]] && dirs=("$root/test/tests/e2e")
    grep -rhoE '^(TEST|TEST_F|TEST_P)\([A-Za-z0-9_]+,[[:space:]]*[A-Za-z0-9_]+' "${dirs[@]}" 2>/dev/null |
        sed -E 's/^[A-Z_]+\(([A-Za-z0-9_]+),[[:space:]]*([A-Za-z0-9_]+)/\1.\2\n\1.*/' | sort -u
}

_privmx_datasets() {
    local ini
    for ini in "$1"/test/test_env/create_dataset/*/ServerData.ini; do
        [[ -f "$ini" ]] && basename "$(dirname "$ini")"
    done
}

_privmx_run_tests_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
    local opts="--unit-only --e2e-only --keep-bridge --filter --test --build-dir
                --bridge-image --dataset-dir --e2e-workers -h --help"

    case "$prev" in
        --filter|--test)
            COMPREPLY=($(compgen -W "$(_privmx_gtest_names "$(_privmx_repo_root)")" -- "$cur"))
            return ;;
        --build-dir|--dataset-dir)
            COMPREPLY=($(compgen -d -- "$cur"))
            return ;;
        --bridge-image|--e2e-workers)
            return ;;
    esac

    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
}

_privmx_bridge_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
    local opts="--dataset --index --bridge-image --keep-backend -h --help"

    case "$prev" in
        --dataset|--dataset-dir)
            if [[ "$cur" == */* || "$cur" == .* ]]; then
                COMPREPLY=($(compgen -d -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$(_privmx_datasets "$(_privmx_repo_root)")" -- "$cur"))
            fi
            return ;;
        --index)
            COMPREPLY=($(compgen -W "0 1 2 3" -- "$cur"))
            return ;;
        --bridge-image)
            return ;;
    esac

    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
}

complete -F _privmx_run_tests_completion run_tests.sh ./scripts/run_tests.sh scripts/run_tests.sh
complete -F _privmx_bridge_completion bridge.sh ./scripts/bridge.sh scripts/bridge.sh
