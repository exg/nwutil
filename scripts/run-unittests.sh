#!/usr/bin/env bash

set -e

main () {
    cd "$(dirname "$(realpath "$0")")/.."
    if [ -n "$FSARCHS" ]; then
        local archs=()
        IFS=, read -ra archs <<< "$FSARCHS"
        for arch in "${archs[@]}" ; do
            run-tests "$arch"
        done
    else
        local os=$(uname -m -s)
        case $os in
            "Darwin arm64")
                run-tests darwin;;
            "Darwin x86_64")
                run-tests darwin;;
            "FreeBSD amd64")
                run-tests freebsd_amd64;;
            "Linux i686")
                run-tests linux32;;
            "Linux x86_64")
                run-tests linux64;;
            "OpenBSD amd64")
                run-tests openbsd_amd64;;
            *)
                echo "$0: Unknown OS architecture: $os" >&2
                exit 1
        esac
    fi
}

realpath () {
    python -c "import os.path, sys; print(os.path.realpath(sys.argv[1]))" "$1"
}

run-test () {
    local arch=$1
    shift
    case $arch in
        linux32 | linux64)
            valgrind -q --leak-check=full --error-exitcode=1 "$@"
            ;;
        *)
            "$@"
            ;;
    esac
}

run-tests () {
    local arch=$1
    local test_dir=stage/$arch/build/test
    run-test $arch $test_dir/test_url test/urltestdata.json
}

main
