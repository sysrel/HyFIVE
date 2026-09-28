
FROM ubuntu:22.04 as fuzzware-base

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi && \
    pip3 install virtualenv virtualenvwrapper cython setuptools

ENV FUZZWARE=/home/user/fuzzware
ENV WORKON_HOME=/home/user/.virtualenvs

ARG USERID=1000

RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZWARE /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

RUN USER=user GROUP=user VERSION=0.5.1 && \
    wget https://github.com/boxboat/fixuid/releases/download/v$VERSION/fixuid-$VERSION-linux-amd64.tar.gz && \
    tar -C /usr/local/bin -xzf fixuid-$VERSION-linux-amd64.tar.gz && \
    chown root:root /usr/local/bin/fixuid && \
    chmod 4755 /usr/local/bin/fixuid && \
    mkdir -p /etc/fixuid && \
    printf "user: $USER\ngroup: $GROUP\npaths:\n  - /home/user/.cache\n" > /etc/fixuid/config.yml


# ============================================================
# Modeling container
# ============================================================

FROM fuzzware-base as fuzzware-modeling

USER user

COPY --chown=user modeling/requirements.txt /requirements-modeling.txt

RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip install -r /requirements-modeling.txt

COPY --chown=user modeling $FUZZWARE/modeling

RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip install $FUZZWARE/modeling


# ============================================================
# HYFIVE container
# ============================================================

FROM fuzzware-base as fuzzware-hyfive

USER user

COPY --chown=user fuzzware_hyfive/requirements.txt /requirements-hyfive.txt

RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-hyfive && \
    ls -l $WORKON_HOME/ && \
    ls -l $WORKON_HOME/fuzzware-hyfive/ && \
    . $WORKON_HOME/fuzzware-hyfive/bin/activate && \
    pip install -r /requirements-hyfive.txt

RUN echo "Contents of lib:" && \
    ls -l -R $WORKON_HOME/fuzzware-hyfive/

COPY --chown=user fuzzware_hyfive $FUZZWARE/fuzzware_hyfive

RUN . $WORKON_HOME/fuzzware-hyfive/bin/activate && \
    pip install $FUZZWARE/fuzzware_hyfive


# ============================================================
# Main Fuzzware container
# ============================================================

FROM fuzzware-base as fuzzware

USER root

COPY --chown=user pipeline/requirements.txt /requirements-pipeline.txt
COPY --chown=user emulator/requirements.txt /requirements-emulator.txt

RUN pip3 install -r /requirements-emulator.txt -r /requirements-pipeline.txt

# Build and install emulator dependencies: AFL and Unicorn

COPY --chown=user emulator/get_afl.sh emulator/afl.patch $FUZZWARE/emulator/
COPY --chown=user emulator/unicorn/ $FUZZWARE/emulator/unicorn

WORKDIR $FUZZWARE/emulator

USER user

RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZWARE/emulator/afl clean all && \
    make -C $FUZZWARE/emulator/AFLplusplus clean all && \
    cd $FUZZWARE/emulator/unicorn && \
    ./build_unicorn.sh


# ============================================================
# FIX: Extract Unicorn native library from ZIP egg
# ============================================================

USER root

# Unicorn 1.0.3 may be installed as a ZIP-based .egg.
#
# Its Python loader cannot directly load libunicorn.so from
# inside the ZIP archive.
#
# Extract the native library to a real filesystem location.

RUN python3 - <<'PY'
import glob
import os
import zipfile

from pathlib import Path

# Locate Unicorn egg installed by build_unicorn.sh.

patterns = [
    "/usr/local/lib/python*/dist-packages/unicorn-*.egg",
    "/usr/local/lib/python*/site-packages/unicorn-*.egg",
]

eggs = []

for pattern in patterns:
    eggs.extend(glob.glob(pattern))

eggs = sorted(set(eggs))

print("Found Unicorn egg candidates:", eggs)

if not eggs:
    raise RuntimeError("Unicorn egg not found")

# Find the ZIP egg containing the native library.

member = "unicorn/lib/libunicorn.so"

selected_egg = None

for egg in eggs:
    if not zipfile.is_zipfile(egg):
        continue

    with zipfile.ZipFile(egg) as archive:
        if member in archive.namelist():
            selected_egg = egg
            break

if selected_egg is None:
    raise RuntimeError(
        "Could not find unicorn/lib/libunicorn.so "
        "inside any Unicorn egg"
    )

print("Selected Unicorn egg:", selected_egg)

# Extract the native library.

destination = Path("/usr/local/lib/libunicorn.so")

with zipfile.ZipFile(selected_egg) as archive:
    data = archive.read(member)

destination.write_bytes(data)

os.chmod(destination, 0o755)

print("Extracted:", destination)
print("Library size:", destination.stat().st_size)
PY

# Tell Unicorn to load the extracted native library first.

ENV LIBUNICORN_PATH=/usr/local/lib

# Verify the native library and Python bindings during build.

RUN python3 - <<'PY'
import ctypes
import os
import unicorn

library = os.path.join(
    os.environ["LIBUNICORN_PATH"],
    "libunicorn.so"
)

ctypes.CDLL(library)

print("Native library loaded:", library)
print("Unicorn Python version:", unicorn.__version__)
print("Unicorn native version:", unicorn.uc_version())

uc = unicorn.Uc(
    unicorn.UC_ARCH_ARM,
    unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS
)

print("ARM Cortex-M emulator initialized successfully")
PY


# ============================================================
# Install emulator and pipeline
# ============================================================

USER user

COPY --chown=user emulator $FUZZWARE/emulator

RUN make -C $FUZZWARE/emulator/harness/fuzzware_harness/native clean all

COPY --chown=user pipeline $FUZZWARE/pipeline

USER root

RUN pip3 install -e $FUZZWARE/emulator/harness && \
    pip3 install -e $FUZZWARE/pipeline


# ============================================================
# Copy modeling and HYFIVE virtual environments
# ============================================================

COPY --chown=user --from=fuzzware-modeling $WORKON_HOME/ $WORKON_HOME/

COPY --chown=user --from=fuzzware-hyfive $WORKON_HOME/ $WORKON_HOME/


# ============================================================
# Final container configuration
# ============================================================

USER user:user

WORKDIR $FUZZWARE/targets

ENTRYPOINT ["fixuid", "-q"]

# ENTRYPOINT ["fuzzware-start-tmux-docker"]
