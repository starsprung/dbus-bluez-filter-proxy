#!/usr/bin/env bash
#
# dbus-bluez-filter-proxy: BlueZ-aware filtering D-Bus proxy.
# Copyright (C) 2026 Shaun Starsprung
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Build the test container and run the test suite inside it.
#
# Usage:  ./run-tests.sh [extra cargo-test args...]
# Example: ./run-tests.sh --test auth
set -euo pipefail

cd "$(dirname "$0")"

IMAGE_TAG=dbus-bluez-filter-proxy-test:latest

docker build -f Dockerfile.test -t "$IMAGE_TAG" . >&2

# Pass any extra args through to `cargo test`. The image's CMD already
# includes `--`; argv after that goes to the test harness directly.
docker run --rm "$IMAGE_TAG" cargo test --release --locked -- --nocapture "$@"
