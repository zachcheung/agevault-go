package main

const bashCompletion = `
# bash completion for agevault
_comp_cmd_agevault() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  local subcommands="encrypt decrypt cat reencrypt rotate edit run agent agent-run agent-ping init keygen pubkey key-add key-get key-readd completion git-setup help"

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
    agent)
      if [[ "$prev" == "--socket" || "$prev" == "--env" || "$prev" == "--decrypt" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      else
        COMPREPLY=( $(compgen -W "--socket --env --decrypt" -- "$cur") )
      fi
      return 0
      ;;
    agent-run)
      local found_separator=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--" ]] && found_separator=true
      done
      if [[ "$found_separator" == "true" ]]; then
        COMPREPLY=( $(compgen -c -- "$cur") )
      elif [[ "$prev" == "--socket" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      else
        COMPREPLY=( $(compgen -W "--socket --secret --" -- "$cur") )
      fi
      return 0
      ;;
    agent-ping)
      if [[ "$prev" == "--socket" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      else
        COMPREPLY=( $(compgen -W "--socket" -- "$cur") )
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
      local has_new_key=false has_keep_old_key=false has_kms_out=false has_pq=false has_all=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--new-key" ]]      && has_new_key=true
        [[ "$word" == "--keep-old-key" ]] && has_keep_old_key=true
        [[ "$word" == "--kms-out" ]]      && has_kms_out=true
        [[ "$word" == "--pq" ]]           && has_pq=true
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
        [[ "$has_kms_out" == "false" ]]      && opts="$opts --kms-out"
        [[ "$has_pq" == "false" ]]           && opts="$opts --pq"
        opts="$opts --all"
        COMPREPLY=( $(compgen -W "$opts" -f -- "$cur") )
      fi
      return 0
      ;;
    init)
      local has_pq=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--pq" ]] && has_pq=true
      done
      [[ "$has_pq" == "false" ]] && COMPREPLY=( $(compgen -W "--pq" -- "$cur") )
      return 0
      ;;
    keygen)
      local has_pq=false has_y=false
      for word in "${COMP_WORDS[@]:1}"; do
        [[ "$word" == "--pq" ]] && has_pq=true
        [[ "$word" == "-y" ]]   && has_y=true
      done
      if [[ "$prev" == "-o" || "$prev" == "-y" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
      else
        local opts="-o"
        [[ "$has_pq" == "false" && "$has_y" == "false" ]] && opts="$opts --pq"
        [[ "$has_y" == "false" ]] && opts="$opts -y"
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
      fi
      return 0
      ;;
    key-add|key-get|key-readd|pubkey)
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
  'agent:Run a sidecar that decrypts once and serves over a socket'
  'agent-ping:Check whether an agevault agent is listening'
  'agent-run:Fetch decrypted content from an agevault agent, then run a command'
  'cat:Decrypt and print to stdout'
  'completion:Generate completion scripts'
  'decrypt:Decrypt .age file(s)'
  'edit:Edit encrypted file in $EDITOR'
  'encrypt:Encrypt file(s)'
  'git-setup:Configure Git integration'
  'help:Show help'
  'init:Generate a new age key pair at AGE_SECRET_KEY_FILE'
  'key-add:Add public key from key server'
  'keygen:Generate a new age key pair'
  'key-get:Fetch a public key from key server'
  'key-readd:Reset and re-add public key(s)'
  'pubkey:Print the public key of the current identity'
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
      agent)
        _arguments \
          '--socket[Unix socket to listen on]:file:_files' \
          '--env[Serve as environment variables]:file:_files' \
          '--decrypt[Serve as file content]:file:_files'
        ;;
      agent-run)
        if [[ ${words[*]} == *"--"* ]]; then
          _command_names
        elif [[ ${words[CURRENT-1]} == "--socket" ]]; then
          _files
        else
          _values 'option' --socket --secret --
        fi
        ;;
      agent-ping)
        _arguments \
          '--socket[Unix socket to check]:file:_files'
        ;;
      reencrypt)
        _arguments \
          '--all[Re-encrypt all *.age files tracked by Git]' \
          '*:files:_files'
        ;;
      rotate)
        _arguments \
          '--new-key[Path to new key file]:file:_files' \
          '--keep-old-key[Keep old key in recipients]' \
          '--kms-out[Write KMS-encrypted new key instead of plaintext]' \
          '--pq[Upgrade to post-quantum hybrid ML-KEM-768+X25519 key (all recipients must be hybrid; auto-preserved if already hybrid)]' \
          '--all[Rotate all *.age files tracked by Git]' \
          '*:files:_files'
        ;;
      init)
        _arguments \
          '--pq[Generate a post-quantum hybrid ML-KEM-768+X25519 key]'
        ;;
      keygen)
        _arguments \
          '-o[Write private key to file]:file:_files' \
          '--pq[Generate a post-quantum hybrid ML-KEM-768+X25519 key]' \
          '-y[Print public key of existing private key file]:file:_files'
        ;;
      key-add|key-get|key-readd)
        _message 'Provide username(s)'
        ;;
      pubkey)
        _message 'No further arguments'
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
