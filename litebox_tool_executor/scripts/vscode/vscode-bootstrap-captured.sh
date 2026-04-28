# shellcheck shell=sh

echo "4bb1a9b7b20e: running"
echo "Script executing under PID: $$"

VSC_TMP="${XDG_RUNTIME_DIR:-/tmp}"

# Configuration
UUID="4bb1a9b7b20e"
COMMIT_ID="41dd792b5e652393e7787322889ed5fdc58bd75b"
QUALITY="stable"
TOKEN="83883a34-4381-4753-91e1-1567ebecf203"
VSCODE_AGENT_FOLDER="$HOME/.vscode-server"
ALLOW_CLIENT_DOWNLOAD="1"
FORCE_CLIENT_DOWNLOAD="0"
CLI_NAME_IN_ARCHIVE="code"
IGNORE_WGET_CONFIG_FLAG=" --no-config "
IGNORE_CURL_CONFIG_FLAG=" --disable "
WGET_TRIES_SEGMENT="--tries=1"
LISTEN_ARGS="--on-host=127.0.0.1 --on-port"
VERBOSE="0"
HTTP_PROXY_INPUT=""
HTTPS_PROXY_INPUT=""
RECONNECTION_GRACE_TIME=""

CLI_NAME_ON_DISK="${CLI_NAME_IN_ARCHIVE}-${COMMIT_ID}"
CLI_PATH="${VSCODE_AGENT_FOLDER}/${CLI_NAME_ON_DISK}"
CLI_LOG_FILE="${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.log"

# Marker strings
GET_DOWNLOAD_SERVER_START_TRIGGER="4bb1a9b7b20e:trigger_server_download"
GET_DOWNLOAD_SERVER_END_TRIGGER="4bb1a9b7b20e:trigger_server_download_end"
GET_PROGRESS_DOWNLOADING="4bb1a9b7b20e%%1%%"
GET_PROGRESS_INSTALLING="4bb1a9b7b20e%%2%%"

UNPACK_RESULT=
DID_LOCAL_DOWNLOAD=0
DOWNLOAD_TIME=
INSTALL_TIME=
SERVER_START_TIME=

fail_with_exitcode() {
	echo "${UUID}: start"
	echo "exitCode==$1=="
	echo_common_results
	echo "${UUID}: end"
	exit 0
}

echo_common_results() {
	echo "listeningOn==$LISTENING_ON=="
	echo "osReleaseId==$OSRELEASEID=="
	echo "arch==$ARCH=="
	echo "vscodeArch==$VSCODE_ARCH=="
	echo "bitness==$BITNESS=="
	echo "tmpDir==$VSC_TMP=="
	echo "platform==$PLATFORM=="
	echo "unpackResult==$UNPACK_RESULT=="
	echo "didLocalDownload==$DID_LOCAL_DOWNLOAD=="
	echo "downloadTime==$DOWNLOAD_TIME=="
	echo "installTime==$INSTALL_TIME=="
	echo "serverStartTime==$SERVER_START_TIME=="
	echo "execServerToken==${TOKEN}=="
	echo "platformDownloadPath==$PLATFORM_DOWNLOAD_PATH=="
	echo "SSH_AUTH_SOCK==$SSH_AUTH_SOCK=="
echo "DISPLAY==$DISPLAY=="
}

millis() {
	d=$(date +%s%N)
	# Test if 'd' contains any non-digit characters
	if [ -z "${d##*[!0-9]*}" ] || [ "$PLATFORM" != "linux" ]; then
	    # Fallback for MacOS or any date binary that doesn't handle '%N'
		echo $(($(date +%s)*1000))
		return
	fi
	echo $((d/1000000))
}

elapsed() {
	echo $(($(millis) - $1))
}

printenv_indent() {
	if [ "$VERBOSE" = "1" ]; then
		echo "printenv:"
		printenv | sed 's/^/    /'
	fi
}

[ -z "${http_proxy}" ] && [ "${HTTP_PROXY_INPUT}" != "" ] && export http_proxy="$HTTP_PROXY_INPUT"
[ -z "${https_proxy}" ] && [ "${HTTPS_PROXY_INPUT}" != "" ] && export https_proxy="$HTTPS_PROXY_INPUT"

#
# Get OS name
#
OSRELEASEID=$(cat /etc/os-release 2>/dev/null | grep -a -E '^ID=' | sed 's/^[Ii][Dd]=//g' | sed 's/"//g')
if [ -z "$OSRELEASEID" ]
then
	OSRELEASEID=$(cat /usr/lib/os-release 2>/dev/null | grep -a -E '^ID=' | sed 's/^[Ii][Dd]=//g' | sed 's/"//g')
	if [ -z "$OSRELEASEID" ]
	then
		OSRELEASEID=$(uname -s)
	fi
fi

#
# Get host platform/architecture
#
UNAME=$(uname -s)
case $UNAME in
	Linux) PLATFORM=linux;;
	Darwin) PLATFORM=macOS;;
	*)
		echo "Unsupported platform: $UNAME"
		fail_with_exitcode 203
		;;
esac

BITNESS=$(getconf LONG_BIT)
ARCH=$(uname -m)
case $ARCH in
	x86_64) VSCODE_ARCH="x64";;
	armv7l | armv8l)
		VSCODE_ARCH="armhf"
		;;
	arm64 | aarch64)
		if [ "$BITNESS" = 32 ]; then
			# Can have 32-bit userland on 64-bit kernel
			VSCODE_ARCH="armhf"
		else
			VSCODE_ARCH="arm64"
		fi
		;;
	*)
		OSRELEASE=$(uname -r)
		case $OSRELEASE in
			*x86_64*) VSCODE_ARCH="x64";;
			*)
				echo "Unsupported architecture: $ARCH"
				fail_with_exitcode 196
			;;
		esac
		;;
esac

if [ "$PLATFORM" = linux ]; then
	if [ "$VSCODE_ARCH" = armhf ]; then
		PLATFORM_DOWNLOAD_PATH=cli-linux-armhf
	else
		PLATFORM_DOWNLOAD_PATH=cli-alpine-$VSCODE_ARCH
	fi
elif [ "$VSCODE_ARCH" = "arm64" ]; then
	PLATFORM_DOWNLOAD_PATH=cli-darwin-arm64
else
	PLATFORM_DOWNLOAD_PATH=cli-darwin-x64
fi

if [ ! -d "$VSCODE_AGENT_FOLDER" ]; then
	mkdir -p "$VSCODE_AGENT_FOLDER"
	chmod 750 "$VSCODE_AGENT_FOLDER"

	error_code=$?
	if [ "${error_code}" -gt 0 ]; then
		echo "Creating the server install dir failed..."
		fail_with_exitcode 202
	fi
fi

#
# Delete old CLIs if needed
#

# shellcheck disable=SC2010
TO_DELETE=$(ls -1 -t "$VSCODE_AGENT_FOLDER" | grep -E "code(-insiders)?-[a-fA-F0-9]{40}" | tail -n +6)
for CLI_TO_DELETE in $TO_DELETE; do
	target_dir="$VSCODE_AGENT_FOLDER/$CLI_TO_DELETE"
	echo "Deleting old install $target_dir"
	rm -rf "$target_dir"
done

do_client_download() {
	DID_LOCAL_DOWNLOAD=1
	echo "Trigger local server download"
	echo "${GET_DOWNLOAD_SERVER_START_TRIGGER}"
	echo artifact==$PLATFORM_DOWNLOAD_PATH==
	echo destFolder==$VSCODE_AGENT_FOLDER==
	echo destFolder2==/vscode-cli-$COMMIT_ID.tar.gz==
	echo "${GET_DOWNLOAD_SERVER_END_TRIGGER}"
	echo "Waiting for client to transfer server archive..."
	echo "Waiting for $VSCODE_AGENT_FOLDER/vscode-cli-$COMMIT_ID.tar.gz.done and vscode-server.tar.gz to exist"

	while true; do
		if [ -f "$VSCODE_AGENT_FOLDER/vscode-cli-$COMMIT_ID.tar.gz.done" ]; then
			if [ ! -f "$VSCODE_AGENT_FOLDER/vscode-cli-$COMMIT_ID.tar.gz" ]; then
				echo "Found flag but not server tar - server transfer failed"
				fail_with_exitcode 199
			fi

			echo "Found flag and server on host"
			rm "$VSCODE_AGENT_FOLDER/vscode-cli-$COMMIT_ID.tar.gz.done"
			break
		else
			printf ' '
			sleep 3
		fi
	done
}

do_client_download_or_fail() {
	error_code="${1:-"1"}"
	if [ "$DID_LOCAL_DOWNLOAD" = "1" ]; then
		echo "Already attempted local download, failing"
		fail_with_exitcode "$error_code"
	elif [ $ALLOW_CLIENT_DOWNLOAD = "1" ]; then
		do_client_download
	else
		fail_with_exitcode "$error_code"
	fi
}

is_program_from_busybox() {
	program=$1
	if command -v busybox > /dev/null 2>&1
	then
		# Check symlink from program to busybox
		if [ -L "$(command -v "$program")" ] && [ "$(readlink -f "$(command -v "$program")")" = "$(command -v busybox)" ]
		then
			echo "Program '$program' is provided by busybox" >&2
			echo 'yes'
			return
		fi
	fi
	echo 'no'
}

supports_flag() {
    program="$1"
    flag="$2"

    if command -v "$program" > /dev/null 2>&1; then
        if "$program" --help 2>&1 | grep -q -- "$flag"
		then
			echo "Program '$program' appears to support flag '$flag'" >&2
			echo 'yes'
			return
		fi
    fi
		echo "Program '$program' is not available or does not appear to support flag '$flag'" >&2
        echo 'no'
}

do_host_download() {
	start=$(millis)
	echo "${GET_PROGRESS_DOWNLOADING}"

	UPDATE_URL="https://update.code.visualstudio.com"
	DOWNLOAD_URL=$UPDATE_URL/commit:$COMMIT_ID/$PLATFORM_DOWNLOAD_PATH/${QUALITY}

	if command -v wget > /dev/null 2>&1
	then
		echo "Downloading with wget"
		IS_WGET_BUSYBOX=$(is_program_from_busybox wget)

		echo "wget is from busybox: $IS_WGET_BUSYBOX"

		if [ "$IS_WGET_BUSYBOX" = 'no' ]
		then
			# Not busybox.
			# Assuming its GNU wget or similar

			if [ -n "$IGNORE_WGET_CONFIG_FLAG" ] && [ "$(supports_flag 'wget' '--no-config')" = "no" ]; then
				echo "Detected that this version of wget does not support '--no-config'. Will not ignore wget default configuration files."
				IGNORE_WGET_CONFIG_FLAG=""
			fi

			WGET_ERRORS=$(2>&1 wget ${IGNORE_WGET_CONFIG_FLAG} ${WGET_TRIES_SEGMENT} --connect-timeout=7 --dns-timeout=7 -nv -O vscode-cli-$COMMIT_ID.tar.gz ${DOWNLOAD_URL})
		else
			# Is busybox.
			# Remove flags for the sake of compatibility

			WGET_ERRORS=$(2>&1 wget -O vscode-cli-$COMMIT_ID.tar.gz ${DOWNLOAD_URL})
		fi

		error_code=$?
		if [ $error_code -ne 0 ]
		then
			echo "wget download failed"
			echo "$WGET_ERRORS"
			printenv_indent

			do_client_download_or_fail 193
		else
			echo "Download complete"
			DOWNLOAD_TIME=$(elapsed $start)
		fi
	else
		command -v curl > /dev/null 2>&1
		error_code=$?
		if [ $error_code -eq 0 ]
		then
			echo "Downloading with curl"
			CURL_STATUS_CODE_RESULT=$(curl ${IGNORE_CURL_CONFIG_FLAG} --connect-timeout 7 -L $DOWNLOAD_URL --output vscode-cli-$COMMIT_ID.tar.gz -w "%{http_code}")
			error_code=$?
			curl_status_code_if_2xx=$(echo "$CURL_STATUS_CODE_RESULT" | grep -E "^2[0-9]{2}$")
			if [ $error_code -ne 0 ] || [ -z "$curl_status_code_if_2xx" ]
			then
				echo "curl download failed"
				echo "HTTP status code: $CURL_STATUS_CODE_RESULT"
				printenv_indent

				do_client_download_or_fail 193
			else
				echo "Download complete"
				DOWNLOAD_TIME=$(elapsed $start)
			fi
		else
			printenv_indent
			echo "Neither wget nor curl is installed"

			do_client_download_or_fail 194
		fi
	fi
}

do_install() {
	start=$(millis)
	echo "${GET_PROGRESS_INSTALLING}"
	UNPACK_RESULT="success"
	echo "tar --version: $(tar --version)"
	tar -xf vscode-cli-$COMMIT_ID.tar.gz --no-same-owner
	TAR_EXIT=$?
	INSTALL_TIME=$(elapsed $start)

	if [ $TAR_EXIT -ne 0 ]
	then
		echo "ERROR: tar exited with a non-zero exit code: $TAR_EXIT"
		UNPACK_RESULT="error"
		do_client_download_or_fail "205"
		do_install
		return
	fi

	mv "$CLI_NAME_IN_ARCHIVE" "$CLI_PATH"

	# cheap sanity check

	if ! eval "$CLI_PATH --version"
	then
		UNPACK_RESULT="missingFiles"
		echo "ERROR: $CLI_PATH don't exist"
		do_client_download_or_fail "205"
		do_install
		return
	fi

	# Delete the leftover folder which might have -web prefix, and the .tar.gz
	rm -rf vscode-cli*
}

#
# Install if needed
#
if [ ! -f "$CLI_PATH" ]
then
	echo "Installing to $VSCODE_AGENT_FOLDER..."
	STASHED_WORKING_DIR="$(pwd)"
	cd "$VSCODE_AGENT_FOLDER" || fail_with_exitcode 206

	if [ $FORCE_CLIENT_DOWNLOAD = "1" ]; then
		do_client_download
	else
		do_host_download
	fi

	do_install
	cd "$STASHED_WORKING_DIR" || fail_with_exitcode 206
else
	echo "Found existing installation at $VSCODE_AGENT_FOLDER..."
fi


#
# Start the server
#
start_server() {
	echo "Starting VS Code CLI..."
	printenv_indent
	start=$(millis)
	if [ -f $CLI_LOG_FILE ]; then
		echo "Removing old logfile at $CLI_LOG_FILE"
		rm "$CLI_LOG_FILE" # See #6265
	fi

	# Stop exporting VSCODE_AGENT_FOLDER once https://github.com/microsoft/vscode/pull/228287 is available and replace with:
	# --extensions-dir "$VSCODE_AGENT_FOLDER/extensions" --user-data-dir "$VSCODE_AGENT_FOLDER/data"
	# See https://github.com/microsoft/vscode-internalbacklog/issues/2604, https://github.com/microsoft/vscode-remote-release/issues/10255
	export VSCODE_AGENT_FOLDER

	touch $CLI_LOG_FILE
	chmod 600 $CLI_LOG_FILE

	LOG_LEVEL_FLAG=""
	if [ "$VERBOSE" = "1" ]; then
	    echo "Setting '--log trace' on CLI"
		LOG_LEVEL_FLAG="--log trace"
	fi

	RECONNECTION_FLAG=""
	if [ -n "$RECONNECTION_GRACE_TIME" ]; then
		RECONNECTION_FLAG="--reconnection-grace-time $RECONNECTION_GRACE_TIME"
	fi

	VSCODE_CLI_REQUIRE_TOKEN=${TOKEN} "$CLI_PATH" command-shell ${LOG_LEVEL_FLAG} ${RECONNECTION_FLAG} --cli-data-dir "$VSCODE_AGENT_FOLDER/cli" --parent-process-id $$ ${LISTEN_ARGS} > "$CLI_LOG_FILE" 2>&1 < /dev/null &
	CLI_PID=$!
	echo "Spawned remote CLI: $!"

	count=0
	max_retries=15
	while [ $count -lt $max_retries ]; do
		count=$((count + 1))
		LISTENING_ON=$(cat "$CLI_LOG_FILE" | grep -a -E 'Listening on .+' | grep -v grep | sed 's/Listening on //')
		if [ "$LISTENING_ON" != '' ]
		then
			break
		fi

		# "If sig is 0 (the null signal), error checking is performed but no signal is actually sent.
		# The null signal can be used to check the validity of pid.""
		# Source: https://pubs.opengroup.org/onlinepubs/007908799/xsh/kill.html
		if ! kill -0 $CLI_PID > /dev/null; then
			echo "Exec server process not found"
			cat $CLI_LOG_FILE
			if grep -q "This machine does not meet .* prerequisites, expected either..." "$CLI_LOG_FILE"; then
				fail_with_exitcode 207
			fi
			break
		fi

		echo "Waiting for server log..."
		sleep .03 || sleep 1
	done
	SERVER_START_TIME=$(elapsed $start)
}

start_server

# What we echo below cannot be wider than 80 characters
echo "${UUID}: start"
echo_common_results
echo "${UUID}: end"

while true; do sleep 180; printf ' '; done
