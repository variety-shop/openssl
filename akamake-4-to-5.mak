# AKAMAKE 5.x DEFINES FOR 4.x

ifndef quote-sh
quote-sh=$(squote)$(subst $(squote),$(squote)$(dquote)$(squote)$(dquote)$(squote),$1)$(squote)
endif

ifndef NL
define NL


endef
endif

ifndef alog-echo-e-info
alog-echo-e-info=$(shell echo -e $(call quote-sh,$(subst $(NL),\n,$1)) 1>&2)
endif

ifndef alog-multiline-info
alog-multiline-info=$(if $6,$(warning Call to alog-multiline-info contains a comma in arg 5))$(if $5,$(call alog-echo-e-info,$5))
endif

ifndef have-C
have-C=$(wildcard $(BASE_PATH)/$1/componentinfo.xml)
endif

ifndef include-if-exist
include-if-exist=$(eval -include $1)
endif

ifndef always-include-if-exist
always-include-if-exist=$(eval -include $1)
endif
