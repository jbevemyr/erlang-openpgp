.PHONY: all compile test dialyzer-plt dialyzer clean

EBIN=ebin
PLT=.dialyzer_plt
# public_key depends on asn1; Dialyzer/OTP may also need compiler/parsetools/syntax_tools for types.
DIALYZER_APPS=erts kernel stdlib crypto public_key asn1 compiler parsetools syntax_tools
DIALYZER_BEAMS=$(filter-out $(EBIN)/%_tests.beam,$(wildcard $(EBIN)/*.beam))

all: compile

compile:
	mkdir -p $(EBIN)
	erlc +debug_info -Wall -Werror -o $(EBIN) src/*.erl test/*.erl

test: compile
	erl -noshell -pa $(EBIN) -eval 'eunit:test([openpgp_format_tests, gpg_integration_tests], [verbose]), halt().'

dialyzer-plt:
	test -f $(PLT) || (dialyzer --build_plt --output_plt $(PLT) --apps $(DIALYZER_APPS) || test $$? -eq 2)

dialyzer: compile dialyzer-plt
	dialyzer --plt $(PLT) -pa $(EBIN) -c $(DIALYZER_BEAMS)

clean:
	rm -rf $(EBIN) $(PLT)


