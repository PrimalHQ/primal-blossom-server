#!/usr/bin/env sh

prog="$1"
if [ "$prog" = "" ]; then
    echo "Usage: $0 <path to primal_blossom_server executable>"
    exit 1
fi

progname="$(basename $prog)"

m () { stat $prog | awk '/^Modify:/'; }

pkill -f "^$prog"

sleep 0.2

m1=""
while true; do
    while [ "$m1" = "$(m)" ] && pgrep -f "^$prog" > /dev/null; do
        sleep 0.2
    done
    m1="$(m)"

    echo $prog modified, restarting

    pids="$(pgrep -f "^$prog" | tr '\n' ' ')"

    RUST_BACKTRACE=full $prog serve &

    sleep 0.5

    if [ "$pids" != "" ]; then
        echo $pids | while read pid; do kill -USR1 $pid; done
    fi
done
