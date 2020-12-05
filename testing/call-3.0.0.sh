#!/usr/bin/env bash
. vars.sh

echo "[IMAGE=${IMAGE} PROFILE=${PROFILE}]"
start=$(date +%s)
volatility3 -f "${IMAGE}" --profile="${PROFILE}" ${@} |& tee output.txt
elapsed=$(($(date +%s) - start))
printf "[took %-4s secs]\n" "${elapsed}"
