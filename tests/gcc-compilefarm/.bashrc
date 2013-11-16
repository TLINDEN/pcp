# .bashrc on gcc compile farm

if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

alias ll='ls -l'
alias la='ls -la'
alias l='ls -alF'
alias ls-l='ls -l'
alias o='less'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias .....='cd ../../../..'
alias rd=rmdir
alias md='mkdir -p'
alias which='type -p'
alias .='pwd'
alias less='less -i -P "?f%f:Standard input. %lb / %L ?e(END):>"'
alias les='less'
alias grip='egrep -i'

DATE () {
    echo -e "[`date +%d.%b" "%H:%M:%S`]"
}

JOBS () {
    NUM=`jobs|wc -l| awk '{print $1}'`
    case $NUM in
    	"0")
		;;
	*)
		echo -e " [&$NUM]"
		;;
    esac
}

empty () {
    #
    # clean functions for subshell
    unset -f DATE JOBS
}

case $UID in
        "0")
                CURSOR="#"
                ;;
        *)
                CURSOR="\$"
esac

case $TERM in
	*)
		PROMPT_COMMAND="PS1='\[\033]0;\u@\h:\w\007\]
\$(DATE) --- [\w]\$(JOBS) ---
\u@\h: $CURSOR '"
		;;
esac


PATH=/home/scip/bin:$PATH:/usr/local/bin:/usr/sbin
EDITOR=vi
LESSCHARSET=iso8859
GREP_OPTIONS="--binary-files=without-match --directories=skip"

export EDITOR PROMPT_COMMAND PATH LESSCHARSET GREP_OPTIONS


umask 022

shopt -s cdable_vars checkhash checkwinsize
