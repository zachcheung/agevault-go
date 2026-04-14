package main

const bashCompletion = `
# bash completion for agevault
_comp_cmd_agevault() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  local subcommands="encrypt decrypt cat reencrypt rotate edit run key-add key-get key-readd completion git-setup help"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
    return 0
  fi

  case "${COMP_WORDS[1]}" in
    encrypt)
      local has_self=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--self" ]] && has_self=true
      done
      if [[ "$has_self" == "true" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      else
        COMPREPLY=( $(compgen -W "--self" -f -- "$cur") )
      fi
      return 0
      ;;
    decrypt|cat|edit)
      COMPREPLY=( $(compgen -f -- "$cur") )
      return 0
      ;;
    run)
      local found_separator=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--" ]] && found_separator=true
      done

      if [[ "$found_separator" == "true" ]]; then
        COMPREPLY=( $(compgen -c -- "$cur") )
      elif [[ "$prev" == "--env" || "$prev" == "--decrypt" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      elif [[ "$prev" == "run" ]]; then
        COMPREPLY=( $(compgen -W "--env --decrypt --" -f -- "$cur") )
      else
        COMPREPLY=( $(compgen -W "--" -f -- "$cur") )
      fi
      return 0
      ;;
    reencrypt)
      local has_all=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--all" ]] && has_all=true
      done
      if [[ "$has_all" == "true" ]]; then
        COMPREPLY=()
      else
        COMPREPLY=( $(compgen -W "--all" -f -- "$cur") )
      fi
      return 0
      ;;
    rotate)
      local has_new_key=false has_keep_old_key=false has_all=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--new-key" ]]      && has_new_key=true
        [[ "$word" == "--keep-old-key" ]] && has_keep_old_key=true
        [[ "$word" == "--all" ]]          && has_all=true
      done

      if [[ "$prev" == "--new-key" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      elif [[ "$has_all" == "true" ]]; then
        COMPREPLY=()
      else
        local opts=""
        [[ "$has_new_key" == "false" ]]      && opts="--new-key"
        [[ "$has_keep_old_key" == "false" ]] && opts="$opts --keep-old-key"
        opts="$opts --all"
        COMPREPLY=( $(compgen -W "$opts" -f -- "$cur") )
      fi
      return 0
      ;;
    key-add|key-get|key-readd)
      return 0
      ;;
    git-setup)
      COMPREPLY=( $(compgen -W "--local --global --system" -- "$cur") )
      return 0
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
      return 0
      ;;
  esac
}
complete -F _comp_cmd_agevault -o filenames agevault
`

const zshCompletion = `
#compdef agevault

local -a subcommands_list
subcommands_list=(
  'cat:Decrypt and print to stdout'
  'completion:Generate completion scripts'
  'decrypt:Decrypt .age file(s)'
  'edit:Edit encrypted file in $EDITOR'
  'encrypt:Encrypt file(s)'
  'git-setup:Configure Git integration'
  'help:Show help'
  'key-add:Add public key from key server'
  'key-get:Fetch a public key from key server'
  'key-readd:Reset and re-add public key(s)'
  'reencrypt:Re-encrypt file(s)'
  'rotate:Rotate key and re-encrypt'
  'run:Run command with decrypted env'
)

_arguments -C \
  '1: :->command_selector' \
  '2: :->command_args' \
  '*:: :->general_args'

case $state in
  command_selector)
    _describe 'command' subcommands_list
    ;;

  command_args)
    case $words[2] in
      encrypt)
        _arguments \
          '--self[Encrypt using identity instead of recipients file]' \
          '*:files:_files'
        ;;
      decrypt|cat|edit)
        _files
        ;;
      run)
        if [[ ${words[*]} == *"--"* ]]; then
          _command_names
        elif [[ ${words[CURRENT-1]} == "--env" || ${words[CURRENT-1]} == "--decrypt" ]]; then
          _files -g "*.age"
        elif [[ $CURRENT -eq 3 && ${words[3]} != "--env" && ${words[3]} != "--decrypt" ]]; then
          _values 'option' --env --decrypt --
          _files -g "*.age"
        else
          _values 'separator' --
          _files -g "*.age"
        fi
        ;;
      reencrypt)
        _arguments \
          '--all[Re-encrypt all *.age files tracked by Git]' \
          '*:files:_files'
        ;;
      rotate)
        _arguments \
          '--new-key[Path to new age key file]:file:_files' \
          '--keep-old-key[Keep old key in recipients]' \
          '--all[Rotate all *.age files tracked by Git]' \
          '*:files:_files'
        ;;
      key-add|key-get|key-readd)
        _message 'Provide username(s)'
        ;;
      git-setup)
        _values 'scope' --local --global --system
        ;;
      completion)
        _values 'shell' bash zsh
        ;;
      help)
        _message 'No further arguments'
        ;;
    esac
    ;;
esac
`
