package main

const bashCompletion = `
# bash completion for agevault-agent
_comp_cmd_agevault_agent() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  local subcommands="serve add list clear completion version help"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
    return 0
  fi

  if [[ "$prev" == "--socket" ]]; then
    COMPREPLY=( $(compgen -f -- "$cur") )
    return 0
  fi

  case "${COMP_WORDS[1]}" in
    serve|list|clear)
      COMPREPLY=( $(compgen -W "--socket" -- "$cur") )
      return 0
      ;;
    add)
      # -t takes a duration (e.g. 8h); nothing useful to complete.
      [[ "$prev" == "-t" ]] && return 0
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--socket -t" -- "$cur") )
      else
        COMPREPLY=( $(compgen -f -- "$cur") )
      fi
      return 0
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
      return 0
      ;;
  esac
}
complete -F _comp_cmd_agevault_agent -o filenames agevault-agent
`

const zshCompletion = `#compdef agevault-agent

local -a subcommands_list
subcommands_list=(
  'add:Unlock a key file and add it to the agent'
  'clear:Remove all keys from the agent'
  'completion:Generate completion scripts'
  'help:Show help'
  'list:List the public keys of the keys held by the agent'
  'serve:Run the agent in the foreground'
  'version:Print the version'
)

_arguments -C \
  '1: :->command_selector' \
  '*:: :->command_args'

case $state in
  command_selector)
    _describe 'command' subcommands_list
    ;;

  command_args)
    case $words[1] in
      serve|list|clear)
        _arguments \
          '--socket[Unix socket path (default: $AGE_KEY_AGENT_SOCKET)]:socket:_files'
        ;;
      add)
        _arguments \
          '--socket[Unix socket path (default: $AGE_KEY_AGENT_SOCKET)]:socket:_files' \
          '-t[Forget the key after this long (e.g. 8h)]:duration:' \
          '1:key file:_files'
        ;;
      completion)
        _values 'shell' bash zsh
        ;;
    esac
    ;;
esac
`
