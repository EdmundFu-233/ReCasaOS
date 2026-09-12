#!/bin/bash
###
# @Author: LinkLeong link@icewhale.org
# @Date: 2022-08-25 11:41:22
 # @LastEditors: LinkLeong
 # @LastEditTime: 2022-08-31 17:54:17
 # @FilePath: /CasaOS/build/scripts/setup/service.d/casaos/debian/setup-casaos.sh
# @Description:

# @Website: https://www.casaos.io
# Copyright (c) 2022 by icewhale, All Rights Reserved.
###

set -e
umask 077

APP_NAME="casaos"

# copy config files
CONF_PATH=/etc/casaos
OLD_CONF_PATH=/etc/casaos.conf
CONF_FILE=${CONF_PATH}/${APP_NAME}.conf
CONF_FILE_SAMPLE=${CONF_PATH}/${APP_NAME}.conf.sample

CONF_TMP=""
cleanup_config_tmp() {
    if [ -n "${CONF_TMP}" ]; then
        rm -f -- "${CONF_TMP}"
    fi
}
trap cleanup_config_tmp EXIT
trap 'exit 1' HUP INT TERM


if [ -L "${CONF_FILE}" ] || { [ -e "${CONF_FILE}" ] && [ ! -f "${CONF_FILE}" ]; }; then
    echo "Refusing unsafe config path: ${CONF_FILE}" >&2
    exit 1
fi

if [ ! -e "${CONF_FILE}" ]; then
    if [ -e "${OLD_CONF_PATH}" ] || [ -L "${OLD_CONF_PATH}" ]; then
        if [ ! -f "${OLD_CONF_PATH}" ] || [ -L "${OLD_CONF_PATH}" ]; then
            echo "Refusing unsafe legacy config: ${OLD_CONF_PATH}" >&2
            exit 1
        fi
        echo "Migrating legacy config file..."
        CONF_SOURCE="${OLD_CONF_PATH}"
    else
        echo "Initializing config file..."
        CONF_SOURCE="${CONF_FILE_SAMPLE}"
    fi

    if [ ! -f "${CONF_SOURCE}" ] || [ -L "${CONF_SOURCE}" ]; then
        echo "Refusing unsafe config source: ${CONF_SOURCE}" >&2
        exit 1
    fi

    # Publish a complete file in one namespace operation. A crash while
    # copying leaves only the private temporary file; a concurrent creator of
    # CONF_FILE makes ln fail instead of being overwritten.
    CONF_TMP=$(mktemp "${CONF_PATH}/.${APP_NAME}.conf.tmp.XXXXXX")
    install -o root -g root -m 0600 -- "${CONF_SOURCE}" "${CONF_TMP}"
    sync -f "${CONF_TMP}"
    if ! ln -- "${CONF_TMP}" "${CONF_FILE}"; then
        echo "Refusing to replace config created concurrently: ${CONF_FILE}" >&2
        exit 1
    fi
    rm -f -- "${CONF_TMP}"
    CONF_TMP=""
    sync -f "${CONF_PATH}"
fi

chown root:root -- "${CONF_FILE}"
chmod 0600 -- "${CONF_FILE}"

rm -f -- /etc/systemd/system/casaos.service # remove old service file

systemctl daemon-reload

# enable service (without starting)
echo "Enabling service..."
systemctl enable --force --no-ask-password "${APP_NAME}.service"
