#!/bin/sh

exec diff "$HOME/secrets/file" - <<EOF
secret data
EOF
