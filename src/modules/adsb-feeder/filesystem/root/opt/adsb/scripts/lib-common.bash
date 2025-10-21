# Common bash functions and constants.

LOG_FILE="/run/porttracker-sdr-feeder.log"
CONFIG_DIR="/etc/adsb"
ENV_FILE="${CONFIG_DIR}/.env"
DOCKER_COMPOSE_UP_FAILED_MARKER_FILE="/run/porttracker-sdr-feeder-docker-compose-up-failed"

# Log a message in a nice format.
# log <logger_name> <message>...
function log() {
    logger_name=$1
    shift
    message="$@"
    echo "$(date -u -Iseconds)|||shell|||${logger_name}|||${message}" >> ${LOG_FILE}
}

# Log a message and exit. Sync the log file.
# log_and_exit_sync <exit_code> <logger_name> <message>...
function log_and_exit_sync() {
    exit_code=$1
    shift
    log "$@"
    sync ${LOG_FILE}
    sleep 1
    exit $exit_code
}

function rootcheck() {
    if [ $(id -u) != "0" ] ; then
        log_and_exit_sync 1 $0 "this command requires superuser privileges - please run as sudo bash $0"
    fi
}

function logparent() {
    # identify the calling process for better log messages
    PARENTPID=$(ps -cp $$ -o ppid="")
    if kill -0 "$PARENTPID" &> /dev/null ; then
        # shellcheck disable=SC2086 # the ps -q call fails with quotes around the variable
        PARENTPROC=$(ps -q$PARENTPID -o args=)
    else
        PARENTPROC="process $PARENTPID (appears already gone)"
    fi
    log $0 "$(date -u +"%FT%T.%3NZ") $PARENTPROC called $0"
}
