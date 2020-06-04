#!/usr/bin/env bash

# https://stackoverflow.com/a/246128
MY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
MY_NAME="$(basename "${BASH_SOURCE[0]}")"

DEVTOOL_PATCH="devtool.patch"

CORPUS_ZIP="$MY_DIR/corpus.zip"

FUZZ_INPUT_DIR="fuzz/in"
FUZZ_OUTPUT_DIR="fuzz/out"
FUZZ_QUEUE_DIR="tmin_queue"
FUZZ_CRASHES_DIR="tmin_crashes"
FUZZ_CRASHES_ZIP="crashes.zip"
FUZZ_KCOV_REPORT_DIR="kcov-report"
FUZZ_KCOV_REPORT_ZIP="kcov-report.zip"

# Send a text message to stderr
#
say_err() {
    [ -t 2 ] && [ -n "$TERM" ] \
        && echo "$(tput setaf 1)[$MY_NAME] $*$(tput sgr0)" 1>&2 \
        || echo "[$MY_NAME] $*" 1>&2
}

# Exit with an error message if the last exit code is not 0
#
ok_or_die() {
    code=$?
    [[ $code -eq 0 ]] || die -c $code "$@"
}

# Exit with an error message and (optional) code
# Usage: die [-c <error code>] <error message>
#
die() {
    code=1
    [[ "$1" = "-c" ]] && {
        code="$2"
        shift 2
    }
    say_err "$@"
    exit $code
}

# `$0 help`
# Show the detailed devtool usage information.
#
cmd_help() {
    echo ""
    echo "Firecracker $(basename $0)"
    echo "Usage: $(basename $0) <command> [<command args>]"
    echo ""
    echo "Available commands:"
    echo ""
    echo "    run_task [--debug|--release] [-l|--libc musl|gnu] [--cores <cores>] [--minimize]"
    echo "             [--max_total_time <time>] <fuzz_target>"
    echo "        Fuzz a target using AFL, collect the coverage, and send an email with the report."
    echo "        --debug                   Build the debug binary. This is the default."
    echo "        --release                 Build the release binary."
    echo "        -l, --libc musl|gnu       Choose the libc flavor against which the fuzz target will"
    echo "                                  be linked. Default is musl."
    echo "        --cores <cores>           Run AFL instances in parallel. Default value is 1."
    echo "        --minimize                Minimize AFL queue and crashing test cases using afl-cmin and"
    echo "                                  afl-tmin. afl-tmin is parallelized using the number of cores"
    echo "                                  specified by --cores option."
    echo "        --max_total_time <time>   Stop the AFL instance(s) after <time> seconds has passed. Default"
    echo "                                  is 5 minutes (300 seconds)."
    echo "        fuzz_target               Fuzz the specified target with AFL. Valid options are: \"block\","
    echo "                                  \"net\", \"vsock\" and \"api_server\"."
    echo ""
    echo "    schedule_task <crontab_expression> -- <run_task args>"
    echo "        Schedule a fuzzing session using crontab. All arguments after -- will be passed"
    echo "        through to run_task command."
    echo "        crontab_expression        The crontab schedule expression."
    echo ""
    echo "    help"
    echo "        Display this help message."
    echo ""
    echo ""
    echo "    list_tasks"
    echo "        Display the scheduled tasks. The output is the same as \"crontab -l\" output."
    echo ""
}
    
# `$0 schedule_task` - schedule a fuzzing task using crontab.
# Please see `$0 help` for more information.
#
cmd_schedule_task() {
    params=()
    cron_sched_expr=""

    # Parse any command line args.
    while [ $# -gt 0 ]; do
        case "$1" in
            "-h"|"--help")      { cmd_help; exit 1;   } ;;
            "--")               { shift; break;       } ;;
            *)                  { cron_sched_expr=$1; } ;;
        esac
        shift
    done

    if [ "$cron_sched_expr" = "" ]; then
        die "Schedule expression not provided! Please use --help for help."
    fi

    curr_cron="$(crontab -l 2>/dev/null)"
    cron_cmd="$MY_DIR/$MY_NAME run_task $@"
    cronjob="$cron_sched_expr $cron_cmd"

    # Add the cronjob to the crontab, with no duplication.
    (echo "$curr_cron" | grep -v -F "$cronjob" ; echo "$cronjob") | crontab - >/dev/null
    ret=$?

    # Check the return value and restore the crontab if we failed to add the task.
    [ $ret -ne 0 ] && {
        echo "$curr_cron" | crontab -
        say_err "Failed to schedule the task."
    }

    return $ret
}

# `$0 list_task` - show the scheduled tasks.
#
cmd_list_tasks() {
    crontab -l
}

# `$0 run_task` - run a fuzzing task and send an email with the results.
# Please see `$0 help` for more information.
#
cmd_run_task() {
    max_total_time=300
    build_args=()
    fuzz_args=()

    # Parse any command line args.
    while [ $# -gt 0 ]; do
        case "$1" in
            "-h"|"--help")  { cmd_help; exit 1;  } ;;
            "--")           { shift; break;      } ;;
            "-l"|"--libc")
                build_args+=("$1" "$2") 
                shift
                ;;
            "--debug"|"--release")
                build_args+=("$1")
                ;;
            "--cores")
                fuzz_args+=("$1" "$2")
                shift
                ;;
            "--minimize")
                fuzz_args+=("$1")
                ;;
            "--max_total_time")
                shift
                max_total_time="$1"
                ;;
            --*|-*)
                die "Unknown argument: $1. Please use --help for help."
                ;;
            *)
                fuzz_target="$1"
            ;;
        esac
        shift
    done

    [[ -z ${fuzz_target+x} ]] && \
        die "No fuzz target provided."

    # Create task directory, using the current date and hour.
    task_date="$(date +%Y-%m-%d-%H-%M)"
    task_dir="$MY_DIR/$fuzz_target-$task_date"
    rm -rf "$task_dir"
    mkdir "$task_dir"

    if [ $? -ne 0 ]; then
        die "Couldn't create task directory."
    fi

    # Clone the git repository.
    git clone \
        --branch devtool_fuzzing \
        --single-branch \
        https://github.com/batduck27/firecracker.git \
        "$task_dir"

    cd "$task_dir"

    fuzz_target_bin="$fuzz_target""_fuzz_target"

    # Build the fuzz target binary.
    ./tools/devtool build \
        --fuzz afl \
        "${build_args[@]}" \
        -- \
        --bin "$fuzz_target_bin"
    ret=$?

    [[ $ret -ne 0 ]] && \
        die "Failed to build the target."

    # Use the curent start input corspus if any is available.
    if [ -f $CORPUS_ZIP ]; then
        unzip -qo "$CORPUS_ZIP" "$fuzz_target/"* -d "$FUZZ_INPUT_DIR"
    fi

    # Start the fuzzing session.
    ./tools/devtool afl_fuzz \
        "${fuzz_args[@]}" \
        "$fuzz_target" \
        -- \
        --max_total_time="$max_total_time"
    ret=$?
    [[ $ret -ne 0 ]] && \
        die "Error ecountered while fuzzing."

    # Build the fuzz target binary to collect the coverage.
    ./tools/devtool build \
        --fuzz stdin \
        "${build_args[@]}" \
        -- \
        --bin "$fuzz_target_bin"
    ret=$?
    [[ $ret -ne 0 ]] && \
        die "Failed to build the target."

    # Collect coverage info.
    ./tools/devtool fuzz_coverage "$fuzz_target"
    ret=$?

    [[ $ret -ne 0 ]] && \
        die "Failed to get coverage."

    # If there are minimized test cases, then update the corpus.
    if [ -d "$FUZZ_OUTPUT_DIR/$FUZZ_QUEUE_DIR" ]; then
        zip -dq "$CORPUS_ZIP" "$fuzz_target/*"

        $(cd "$FUZZ_OUTPUT_DIR" ; \
          mv "$FUZZ_QUEUE_DIR" "$fuzz_target" && \
          zip -rq "$CORPUS_ZIP" "$fuzz_target" && \
          mv "$fuzz_target" "$FUZZ_QUEUE_DIR")
    fi

    crashes_no="$(ls $FUZZ_OUTPUT_DIR/$FUZZ_CRASHES_DIR)"
    attachments=()

    # Get the zip with the crashing input files.
    if [ -n "$crashes_no" ]; then
        $(cd "$FUZZ_OUTPUT_DIR" ; \
          zip -rjoq "$FUZZ_CRASHES_ZIP" "$FUZZ_CRASHES_DIR")
        attachments+=("$task_dir/$FUZZ_OUTPUT_DIR/$FUZZ_CRASHES_ZIP")
    fi

    # Get the zip with the coverage report/
    if [ -d "$FUZZ_OUTPUT_DIR/$FUZZ_KCOV_REPORT_DIR" ]; then
        $(cd "$FUZZ_OUTPUT_DIR" ; \
          zip -roq "$FUZZ_KCOV_REPORT_ZIP" "$FUZZ_KCOV_REPORT_DIR")
        attachments+=("$task_dir/$FUZZ_OUTPUT_DIR/$FUZZ_KCOV_REPORT_ZIP")
    fi

    git apply "$MY_DIR/$DEVTOOL_PATCH"

    cd "$MY_DIR"
    # Generate the fuzzing report and send it via email.
    python3 send_mail.py "$task_dir" "${attachments[@]}"
}

main() {
    if [ $# = 0 ]; then
    die "No command provided. Please use \`$0 help\` for help."
    fi

    # Parse main command line args.
    #
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)              { cmd_help; exit 1;     } ;;
            -*)
                die "Unknown arg: $1. Please use \`$0 help\` for help."
            ;;
            *)
                break
            ;;
        esac
        shift
    done

    # $1 is now a command name. Check if it is a valid command and, if so,
    # run it.
    #
    declare -f "cmd_$1" > /dev/null
    ok_or_die "Unknown command: $1. Please use \`$0 help\` for help."

    cmd=cmd_$1
    shift

    # $@ is now a list of command-specific args
    #
    $cmd "$@"
}

main "$@"
