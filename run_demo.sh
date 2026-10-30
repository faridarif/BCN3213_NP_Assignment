#!/usr/bin/env bash
# run_demo.sh - start one gateway and N simulated sensor nodes (mixed transport modes).
#
#   ./run_demo.sh [N_DEVICES=12] [PORT=9000]
#
# The gateway console stays attached to this terminal: try  list, stats,
# set 1001 1000, alert 1002 2, clear 1002, report 1003, shutdown 1004, quit.
# Ctrl-C (or 'quit') stops the gateway and every device.  Device output goes to
# demo_logs/node_<id>.log, telemetry to demo_telemetry.csv.
set -u
N=${1:-12}
PORT=${2:-9000}
cd "$(dirname "$0")" || exit 1

if [ ! -x ./central_gateway ] || [ ! -x ./node ]; then
    make >/dev/null || { echo "build failed" >&2; exit 1; }
fi

mkdir -p demo_logs
pids=()
cleanup() {
    trap - INT TERM EXIT
    kill "${pids[@]}" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup INT TERM EXIT

# '<&0' keeps the terminal attached to the gateway (a plain '&' would feed it /dev/null).
./central_gateway -t "$PORT" -u "$PORT" -q -l demo_telemetry.csv <&0 &
gateway=$!
pids+=("$gateway")
sleep 0.5

modes=(hybrid udp tcp)
for i in $(seq 1 "$N"); do
    id=$((1000 + i))
    mode=${modes[$(((i - 1) % 3))]}
    ./node -i "$id" -t "$PORT" -u "$PORT" -m "$mode" -I 2000 -e $((8 + i % 7)) \
        > "demo_logs/node_${id}.log" 2>&1 &
    pids+=($!)
done
echo "[demo] $N devices started (hybrid/udp/tcp round-robin) against port $PORT"

wait "$gateway"
