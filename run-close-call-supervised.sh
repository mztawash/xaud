#!/bin/sh
set -u

cd /home/xaud/wash/technocore-agent
export PYTHONPATH=/home/xaud/wash/technocore-agent
export CLOSE_CALL_STATE=/home/xaud/wash/technocore-agent/close_call_state.json
# User's forecast for the final xyz:NVDA trade before 2026-10-04 10:00 UTC.
export CLOSE_CALL_FORECAST_FINAL_PRICE=215.2
export CLOSE_CALL_MAX_POSITION=20
export CLOSE_CALL_MAX_TRADE_QTY=5
export CLOSE_CALL_RECONCILED=1

while true; do
  printf '%s close-call supervisor starting\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -u close_call_agent.py --live --once
  status=$?
  if [ "$status" -eq 0 ]; then
    printf '%s close-call cycle completed; next sweep check in 300s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    sleep 300
  else
    printf '%s close-call cycle exited status=%s; retrying in 5s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status"
    sleep 5
  fi
done
