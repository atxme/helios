# Resource budgets for Helios builds on WSL. Source this file; do not execute it.
#
# WSL's VHD grows with every Cargo target directory and does not shrink after
# a `cargo clean`. Every build therefore goes through one cache, and the total
# of ALL Helios target directories (cache, the repository's `target/`,
# worktrees, fuzzing) is capped. Exceeding the cap requires an explicit request
# from the user: HELIOS_WSL_BUILD_OVER_BUDGET=1. An agent never sets it on its
# own initiative.
#
# Outside WSL (CI, target hosts, Windows) every function is a no-op.

helios_budget_default_warning_gib=40
helios_budget_default_maximum_gib=45

helios_budget_on_wsl() {
    grep -qiE '(microsoft|wsl)' /proc/sys/kernel/osrelease 2>/dev/null
}

helios_budget_over_allowed() {
    [ "${HELIOS_WSL_BUILD_OVER_BUDGET:-0}" = "1" ]
}

helios_budget_format_gib() {
    awk -v bytes="$1" 'BEGIN { printf "%.1f GiB", bytes / 1024 / 1024 / 1024 }'
}

# Available memory in KiB, constrained by both the WSL view and any cgroup
# limit. Keep 3 GiB for WSL/Linux and budget at most 2.5 GiB per rustc job.
helios_budget_available_memory_kib() {
    local available_kib limit_bytes current_bytes cgroup_available_kib
    available_kib="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)"

    if [ -r /sys/fs/cgroup/memory.max ] && [ -r /sys/fs/cgroup/memory.current ]; then
        read -r limit_bytes < /sys/fs/cgroup/memory.max
        read -r current_bytes < /sys/fs/cgroup/memory.current
        if [[ "$limit_bytes" =~ ^[0-9]+$ && "$current_bytes" =~ ^[0-9]+$ ]]; then
            if [ "$current_bytes" -ge "$limit_bytes" ]; then
                cgroup_available_kib=0
            else
                cgroup_available_kib=$(((limit_bytes - current_bytes) / 1024))
            fi
            [ "$cgroup_available_kib" -lt "$available_kib" ] && available_kib="$cgroup_available_kib"
        fi
    elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ] \
        && [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
        read -r limit_bytes < /sys/fs/cgroup/memory/memory.limit_in_bytes
        read -r current_bytes < /sys/fs/cgroup/memory/memory.usage_in_bytes
        if [[ "$limit_bytes" =~ ^[0-9]+$ && "$current_bytes" =~ ^[0-9]+$ ]] \
            && [ "$limit_bytes" -lt 9223372036854771712 ]; then
            if [ "$current_bytes" -ge "$limit_bytes" ]; then
                cgroup_available_kib=0
            else
                cgroup_available_kib=$(((limit_bytes - current_bytes) / 1024))
            fi
            [ "$cgroup_available_kib" -lt "$available_kib" ] && available_kib="$cgroup_available_kib"
        fi
    fi

    printf '%s\n' "$available_kib"
}

helios_budget_limit_cargo_jobs() {
    local available_kib reserve_kib per_job_kib safe_jobs requested_jobs cpu_count
    available_kib="$(helios_budget_available_memory_kib)"
    reserve_kib=$((3 * 1024 * 1024))
    per_job_kib=$((2560 * 1024))

    # Refuse to start even one compiler when it would consume the reserve
    # intended to keep WSL responsive under memory pressure.
    if [ "$available_kib" -lt $((reserve_kib + per_job_kib)) ]; then
        echo "Refus : seulement $(helios_budget_format_gib "$((available_kib * 1024))") de mémoire disponible dans WSL." >&2
        echo "  Fermez des processus ou attendez avant de lancer une compilation Helios." >&2
        exit 75
    fi

    safe_jobs=$(((available_kib - reserve_kib) / per_job_kib))
    [ "$safe_jobs" -gt 4 ] && safe_jobs=4
    cpu_count="$(nproc)"
    [ "$safe_jobs" -gt "$cpu_count" ] && safe_jobs="$cpu_count"
    requested_jobs="${CARGO_BUILD_JOBS:-$safe_jobs}"
    if ! [[ "$requested_jobs" =~ ^[1-9][0-9]*$ ]]; then
        echo "Refus : CARGO_BUILD_JOBS doit être un entier positif." >&2
        exit 2
    fi
    if [ "$requested_jobs" -gt "$safe_jobs" ]; then
        echo "Avertissement : CARGO_BUILD_JOBS=$requested_jobs réduit à $safe_jobs selon la mémoire WSL disponible." >&2
        requested_jobs="$safe_jobs"
    fi
    export CARGO_BUILD_JOBS="$requested_jobs"
    echo "==> Compilation Cargo WSL limitée à $CARGO_BUILD_JOBS job(s) ($(helios_budget_format_gib "$((available_kib * 1024))") disponibles, réserve de 3 GiB)" >&2
}

# Every Helios Cargo target this machine holds, one per line, deduplicated.
helios_budget_targets() {
    local repo_root="$1" worktree
    {
        echo "$helios_budget_target_dir"
        echo "$HOME/.cache/helios-target"
        echo "$HOME/.cache/helios-audit"
        echo "$repo_root/target"
        echo "$repo_root/fuzz/target"
        { git -C "$repo_root" worktree list --porcelain 2>/dev/null || true; } \
            | sed -n 's/^worktree //p' \
            | while IFS= read -r worktree; do
                echo "$worktree/target"
                echo "$worktree/fuzz/target"
            done
        if [ -d "$repo_root/../helios-worktrees" ]; then
            find "$repo_root/../helios-worktrees" -mindepth 2 -maxdepth 2 \
                -type d -name target 2>/dev/null
        fi
    } | while IFS= read -r target; do
        if [ -d "$target" ]; then
            realpath -- "$target"
        fi
    done | sort -u
}

helios_budget_total_bytes() {
    local targets
    targets="$(helios_budget_targets "$1")"
    if [ -z "$targets" ]; then
        echo 0
        return
    fi
    # One du call over every target: hard links shared between two of them
    # are counted once, as they are on disk.
    printf '%s\n' "$targets" | tr '\n' '\0' | du -sbc --files0-from=- 2>/dev/null \
        | awk '$2 == "total" { print $1 }'
}

helios_budget_report_targets() {
    local targets
    targets="$(helios_budget_targets "$1")"
    [ -n "$targets" ] || return 0
    printf '%s\n' "$targets" | tr '\n' '\0' | du -sh --files0-from=- 2>/dev/null \
        | sed 's/^/    /' >&2
}

# Validates the limits, pins CARGO_TARGET_DIR to the single cache and refuses
# to start a build when the total already reaches the budget.
#
# Usage: helios_budget_enter <repository root>
helios_budget_enter() {
    local repo_root="$1"
    helios_budget_on_wsl || return 0

    helios_budget_limit_cargo_jobs

    helios_budget_target_dir="${HELIOS_WSL_TARGET_DIR:-$HOME/.cache/helios-target}"
    helios_budget_warning_gib="${HELIOS_WSL_BUILD_WARNING_GIB:-$helios_budget_default_warning_gib}"
    helios_budget_maximum_gib="${HELIOS_WSL_BUILD_MAX_GIB:-$helios_budget_default_maximum_gib}"

    if ! [[ "$helios_budget_warning_gib" =~ ^[0-9]+$ && "$helios_budget_maximum_gib" =~ ^[0-9]+$ ]] \
        || [ "$helios_budget_warning_gib" -ge "$helios_budget_maximum_gib" ]; then
        echo "HELIOS_WSL_BUILD_WARNING_GIB et HELIOS_WSL_BUILD_MAX_GIB doivent être des entiers croissants." >&2
        exit 2
    fi
    # The limits may only be tightened: raising one is the same decision as
    # exceeding the budget, and it belongs to the user.
    if [ "$helios_budget_maximum_gib" -gt "$helios_budget_default_maximum_gib" ] \
        && ! helios_budget_over_allowed; then
        echo "Refus : HELIOS_WSL_BUILD_MAX_GIB=${helios_budget_maximum_gib} dépasse le budget de ${helios_budget_default_maximum_gib} GiB." >&2
        echo "  Le relever exige une demande explicite de l'utilisateur : HELIOS_WSL_BUILD_OVER_BUDGET=1." >&2
        exit 75
    fi
    # A second target directory is how the budget was exceeded before: the
    # single cache is the only one a build may write to.
    if [ -n "${CARGO_TARGET_DIR:-}" ] \
        && [ "$(realpath -m -- "$CARGO_TARGET_DIR")" != "$(realpath -m -- "$helios_budget_target_dir")" ] \
        && ! helios_budget_over_allowed; then
        echo "Refus : CARGO_TARGET_DIR=$CARGO_TARGET_DIR ouvrirait un second répertoire target." >&2
        echo "  Le cache unique est $helios_budget_target_dir ; retirez CARGO_TARGET_DIR." >&2
        exit 75
    fi
    export CARGO_TARGET_DIR="$helios_budget_target_dir"

    local before warning_bytes maximum_bytes
    before="$(helios_budget_total_bytes "$repo_root")"
    warning_bytes=$((helios_budget_warning_gib * 1024 * 1024 * 1024))
    maximum_bytes=$((helios_budget_maximum_gib * 1024 * 1024 * 1024))
    if [ "$before" -ge "$maximum_bytes" ]; then
        if helios_budget_over_allowed; then
            echo "Avertissement : budget de ${helios_budget_maximum_gib} GiB dépassé ($(helios_budget_format_gib "$before")), autorisé par HELIOS_WSL_BUILD_OVER_BUDGET=1." >&2
        else
            echo "Refus : les répertoires target Helios totalisent $(helios_budget_format_gib "$before"), budget ${helios_budget_maximum_gib} GiB." >&2
            helios_budget_report_targets "$repo_root"
            echo "  Nettoyez-les : bash scripts/clean-wsl-targets" >&2
            echo "  Dépasser le budget exige une demande explicite de l'utilisateur : HELIOS_WSL_BUILD_OVER_BUDGET=1." >&2
            exit 75
        fi
    elif [ "$before" -ge "$warning_bytes" ]; then
        echo "Avertissement : les répertoires target Helios totalisent $(helios_budget_format_gib "$before") (seuil ${helios_budget_warning_gib} GiB)." >&2
    fi
    echo "==> Cache Cargo WSL : $CARGO_TARGET_DIR (total Helios $(helios_budget_format_gib "$before") avant build)" >&2
}

# Reports the total after a build and fails when it crossed the budget, so the
# next build is refused before it starts rather than halfway through.
#
# Usage: helios_budget_leave <repository root>
helios_budget_leave() {
    local repo_root="$1" after maximum_bytes
    helios_budget_on_wsl || return 0
    after="$(helios_budget_total_bytes "$repo_root")"
    maximum_bytes=$((helios_budget_maximum_gib * 1024 * 1024 * 1024))
    echo "==> Cache Cargo WSL : total Helios $(helios_budget_format_gib "$after") après build" >&2
    if [ "$after" -ge "$maximum_bytes" ] && ! helios_budget_over_allowed; then
        echo "ERREUR : le budget de ${helios_budget_maximum_gib} GiB est dépassé ; nettoyez avant le prochain build : bash scripts/clean-wsl-targets" >&2
        return 75
    fi
}
