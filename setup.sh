#!/bin/bash
# Copyright 2016 Tim van de Kamp. All rights reserved.
# Use of this source code is governed by the MIT license that can be
# found in the LICENSE file.
command -v bro >/dev/null 2>&1 || {
	echo >&2 "[WARN] To run the preformance evaluation Bro needs to be installed."
}

if [ ! -f "outside.tcpdump" ]; then
	# Get the DARPA dataset
	URL="https://www.ll.mit.edu/ideval/data/1998/training/four_hours/tcpdump.gz"
	WGET="$(command -v wget)"
	CURL="$(command -v curl)"
	if [ -x "$WGET" ]; then
		$WGET -O tcpdump.gz.tar "$URL"
	elif [ -x "$CURL" ]; then
		$CURL -o tcpdump.gz.tar "$URL"
	else
		echo >&2 "[ERROR] No program found to download the DARPA 1998 \
Intrusion Detection Evaluation Data Set"
	fi

	# Extract the dataset
	TAR="$(command -v tar)"
	GUNZIP="$(command -v gunzip)"
	if [ -x "$TAR" ] && [ -x "$GUNZIP" ]; then
		$TAR -xf tcpdump.gz.tar && rm tcpdump.gz.tar
		$GUNZIP outside.tcpdump.gz
	else
		echo >&2 "[ERROR] No program found to inflate the compressed \
DARPA 1998 Intrusion Detection Evaluation Data Set"
	fi
fi

# Check for python3
PYTHON="$(command -v python3)"
if [ ! -x "$PYTHON" ]; then
	echo >&2 "[ERROR] Make sure to have Python 3 installed"
else
	if [ ! -d "rules/" ]; then
		echo "Creating example rules in 'rules/'"
		./create-rule.py -f rules/plaintext-sample.rule --plaintext \
			"resp_p=tcp/80" "This is an example rule for connections \
over TCP port 80"
		./create-rule.py -f rules/sample-hkdf.rule \
			"resp_h=207.25.71.142" "resp_p=tcp/80" \
			"This is an example rule using HKDF for connections to \
IP address 207.25.71.142 over TCP port 80"
		./create-rule.py -f rules/sample-pbkdf2.rule --iterations 100000 \
			"resp_h=207.25.71.142" "resp_p=tcp/80" \
			"This is an example rule using PBKDF2 for connections to \
IP address 207.25.71.142 over TCP port 80"

		# Some more rules, used to evaluate the efficienty of the
		# construction.
		INDEX=1
		for OBSERVABLE in "orig_p=1024/tcp" "resp_h=207.25.71.142" \
				"resp_bytes=12908" "conn_state=SF" "resp_p=80/tcp"; do
			OBSERVABLES="${OBSERVABLES} ${OBSERVABLE}"

			# HKDF rule (including plaintext)
			./create-rule.py -f rules/sample-hkdf-${INDEX}.rule \
				--plaintext $OBSERVABLES \
				"This is an example rule using HKDF with ${INDEX} \
observable(s)."
			# PDKDF2 rule
			./create-rule.py -f rules/sample-hkdf-${INDEX}.rule \
				--iterations 100000 $OBSERVABLES \
				"This is an example rule using HKDF with ${INDEX} \
observable(s)."
			INDEX=$((INDEX+1))
		done
	fi
	echo "Use create-rule.py to create cryptographic rules"
	./create-rule.py --help
	echo
	echo "Evaluate cryptographic rules using match-rule.py"
	./match-rule.py --help
	echo
	if [ -f "rules/sample-hkdf.rule" ]; then
		echo "An example run of the matching"
		./match-rule.py rules/sample-hkdf.rule
	fi
fi
