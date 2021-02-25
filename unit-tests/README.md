# Unit tests

## Prerequisite

Be sure to have installed:

- CMake >= 3.10
- CMocka >= 1.1.5

and for code coverage generation:

- lcov >= 1.14

## Overview

In `unit-tests` folder, compile with

```
cmake -Bbuild -H. && make -C build
```

and run tests with

```
CTEST_OUTPUT_ON_FAILURE=1 make -C build test
```

## Generate code coverage

Just execute in `unit-tests` folder

```
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).
