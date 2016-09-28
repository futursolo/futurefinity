#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2016 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os
import sys


def main(args=None):
    try:
        import pytest
    except ImportError as e:
        raise RuntimeError(
            "Cannot Import pytest. Try installing test requirements.") from e

    args = args if args is not None else sys.argv[1:]

    if "-c" not in args:
        test_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path = os.path.join(test_path, "pytest.ini")

        args.append("-c")
        args.append(config_file_path)

    args.append(test_path)

    raise SystemExit(pytest.main(args=args))

if __name__ == "__main__":
    main()
