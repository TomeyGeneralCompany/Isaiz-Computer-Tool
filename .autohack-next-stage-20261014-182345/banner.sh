#!/usr/bin/env bash
if [ -t 1 ] && [ -n "${TERM:-}" ] && [ "${TERM}" != dumb ]; then
  printf '\033[1;31m'
fi
cat "$(dirname "${BASH_SOURCE[0]}")/isaizs-logo.txt"
if [ -t 1 ] && [ -n "${TERM:-}" ] && [ "${TERM}" != dumb ]; then
  printf '\033[0m'
fi
cat <<'NOTICE'
ISAIZS COMPUTER SERVICES COMPANY, LLC
A subsidiary of TOMEY GENERAL COMPANY, LLC

DISCLAIMER: ISAIZS COMPUTER SERVICES COMPANY, LLC AND ITS PARENT,
TOMEY GENERAL COMPANY, LLC, ARE NOT LEGALLY RESPONSIBLE FOR ACTIONS
TAKEN WITH THIS SOFTWARE. USE RESPONSIBLY.

Use this software only for testing expressly authorized by the
applicable program or asset owner. This notice does not override law.
NOTICE
