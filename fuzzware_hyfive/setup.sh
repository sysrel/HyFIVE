#!/bin/bash

[[ ! -z $WORKON_HOME ]] || { echo "[ERROR] WORKON_HOME not set..."; exit 1; }

# install fuzzware with angr instead
hyfive_venv_name="fuzzware-hyfive"
echo "[*] Installing vulnerability detection component in venv '$hyfive_venv_name'"

HYFIVE_VENV_PYTHON3=${HYFIVE_VENV_PYTHON3:-/usr/bin/python3}

# check whether installation is supported on local system due to python3 / angr compatibility
$HYFIVE_VENV_PYTHON3 -c 'import sys; assert sys.version_info >= (3,8)' &>/dev/null || {
    echo "[ERROR] Your python3 version is too low for an installation on your local system."
    echo
    echo "The version of angr which is used requires Python 3.8+."
    echo "As a workaround, you may install a newer version of python3 (>=3.8 should work) and set the HYFIVE_VENV_PYTHON3 environment variable to its path (currently, '$HYFIVE_VENV_PYTHON3' is used)."
    exit 1
}

/usr/bin/python3 -m virtualenv --python=$HYFIVE_VENV_PYTHON3 "$WORKON_HOME/$hyfive_venv_name"
venv_pip="$WORKON_HOME/$hyfive_venv_name/bin/pip"
if [ ! -e "$venv_pip" ]; then
    echo "Creating virtualenv $hyfive_venv_name"
    mkvirtualenv -p $HYFIVE_VENV_PYTHON3 $hyfive_venv_name || exit 1
fi

$venv_pip install -U -r requirements.txt || exit 1
$venv_pip install -U . || exit 1

exit 0
