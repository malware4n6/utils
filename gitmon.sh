#!/bin/bash

# quick and dirty git monitoring
#
# what it does: git pull origin --all for each project found in $ROOT_FOLDER
# if needed, set VERBOSE=1 in the function debug

function debug() {
    VERBOSE=0
    [[ "$VERBOSE" == "1" ]] && echo "[.] $@"
}

function info() {
    echo "[+] $@"
}

function warn() {
    echo "[!] $@"
}

function usage() {
    warn "Usage: gitmon.sh ROOT_FOLDER"
    exit 1
}

function update() {
    repo=$1
    debug "Update $repo "
    pushd . > /dev/null
    cd $repo
    # consider only git repositories
    if [[ ! -d .git ]]; then 
        popd > /dev/null
        debug "not a git repository"
        return
    fi

    # check existence of new branches
    git fetch --all
    res=`git pull --recurse-submodules --all`
    debug $res
    [[ $res == "Already up to date." ]] || info "$repo updated: $res"
    res=`git submodule update --remote`
    [[ $res == "" ]] || info "$repo submodule updated: $res"
    popd > /dev/null
}

export -f update debug info warn

[[ $# == 1 ]] || usage

ROOT_FOLDER=$1

pushd . > /dev/null
find $ROOT_FOLDER -maxdepth 1 -type d -print0| xargs -r0 -I {} bash -c 'update "{}"' _

popd > /dev/null
