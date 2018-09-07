#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "$0")" && pwd -P)"/..

bazel build //:kazel //:buildozer
export PATH="$(bazel info bazel-genfiles)/:$PATH"

bazel run //:gazelle

kazel
buildozer -types 'go_library,go_binary,go_test' 'add tags manual' '//vendor/...:*' || [[ $? -eq 3 ]]
buildozer -types 'go_library,go_binary,go_test' 'add tags manual' '//docs/generated/...:*' || [[ $? -eq 3 ]]
buildozer -types 'go_library,go_binary,go_test' 'add tags manual' '//test/e2e/...:*' || [[ $? -eq 3 ]]