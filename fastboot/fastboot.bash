# /* vim: set ai ts=4 ft=sh: */
#
# Copyright 2017, The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

_fastboot() {
    if ! check_type "$1" >/dev/null; then
        return
    fi

    if check_type _init_completion >/dev/null; then
        _init_completion || return
    fi

    local where i cur serial
    COMPREPLY=()

    serial="${ANDROID_SERIAL:-none}"
    where=OPTIONS
    for ((i=1; i <= COMP_CWORD; i++)); do
        cur="${COMP_WORDS[i]}"
        case "${cur}" in
            -s)
                where=OPT_SERIAL
                ;;
            --slot)
                where=OPT_SLOT
                ;;
            -*)
                where=OPTIONS
                ;;
            *)
                if [[ $where == OPT_SERIAL ]]; then
                    where=OPT_SERIAL_ARG
                    serial=${cur}
                elif [[ $where == OPT_SLOT ]]; then
                    where=OPT_SLOT_ARG
                else
                    where=COMMAND
                    break
                fi
                ;;
        esac
    done

    if [[ $where == COMMAND && $i -ge $COMP_CWORD ]]; then
        where=OPTIONS
    fi

    OPTIONS="-a -c --disable-verification --disable-verity -h --help -s --set-active --skip-secondary --skip-reboot --slot -u --version -w"
    COMMAND="continue devices erase flash flashall flashing format getvar get_staged help oem reboot stage update"

    case $where in
        OPTIONS|OPT_SERIAL)
            COMPREPLY=( $(compgen -W "$OPTIONS $COMMAND" -- "$cur") )
            ;;
        OPT_SERIAL_ARG)
            local devices=$(command fastboot devices 2> /dev/null | awk '{ print $1 }')
            COMPREPLY=( $(compgen -W "${devices}" -- ${cur}) )
            ;;
        OPT_SLOT_ARG)
            local slots="a all b other"
            COMPREPLY=( $(compgen -W "${slots}" -- ${cur}) )
            ;;
        COMMAND)
            if [[ $i -eq $COMP_CWORD ]]; then
                COMPREPLY=( $(compgen -W "$COMMAND" -- "$cur") )
            else
                i=$((i+1))
                case "${cur}" in
                    flash)
                        _fastboot_cmd_flash "$serial" $i
                        ;;
                    reboot)
                        if [[ $COMP_CWORD == $i ]]; then
                            args="bootloader"
                            COMPREPLY=( $(compgen -W "${args}" -- "${COMP_WORDS[i]}") )
                        fi
                        ;;
                    update)
                        _fastboot_cmd_update "$serial" $i
                        ;;
                esac
            fi
            ;;
    esac

    return 0
}

_fastboot_cmd_flash() {
    local serial i cur
    local partitions

    serial=$1
    i=$2

    cur="${COMP_WORDS[COMP_CWORD]}"
    if [[ $i -eq $COMP_CWORD ]]; then
        partitions="boot bootloader dtbo modem odm oem product radio recovery system vbmeta vendor"
        COMPREPLY=( $(compgen -W "$partitions" -- $cur) )
    else
        _fastboot_util_complete_local_file "${cur}" '!*.img'
    fi
}

_fastboot_cmd_update() {
    local serial i cur

    serial=$1
    i=$2

    cur="${COMP_WORDS[COMP_CWORD]}"

    _fastboot_util_complete_local_file "${cur}" '!*.zip'
}

_fastboot_util_complete_local_file() {
    local file xspec i j IFS=$'\n'
    local -a dirs files

    file=$1
    xspec=$2

    # Since we're probably doing file completion here, don't add a space after.
    if [[ $(check_type compopt) == "builtin" ]]; then
        compopt -o plusdirs
        if [[ "${xspec}" == "" ]]; then
            COMPREPLY=( ${COMPREPLY[@]:-} $(compgen -f -- "${cur}") )
        else
            compopt +o filenames
            COMPREPLY=( ${COMPREPLY[@]:-} $(compgen -f -X "${xspec}" -- "${cur}") )
        fi
    else
        # Work-around for shells with no compopt

        dirs=( $(compgen -d -- "${cur}" ) )

        if [[ "${xspec}" == "" ]]; then
            files=( ${COMPREPLY[@]:-} $(compgen -f -- "${cur}") )
        else
            files=( ${COMPREPLY[@]:-} $(compgen -f -X "${xspec}" -- "${cur}") )
        fi

        COMPREPLY=( $(
            for i in "${files[@]}"; do
                local skip=
                for j in "${dirs[@]}"; do
                    if [[ $i == $j ]]; then
                        skip=1
                        break
                    fi
                done
                [[ -n $skip ]] || printf "%s\n" "$i"
            done
        ))

        COMPREPLY=( ${COMPREPLY[@]:-} $(
            for i in "${dirs[@]}"; do
                printf "%s/\n" "$i"
            done
        ))
    fi
}

if [[ $(check_type compopt) == "builtin" ]]; then
    complete -F _fastboot fastboot
else
    complete -o nospace -F _fastboot fastboot
fi
