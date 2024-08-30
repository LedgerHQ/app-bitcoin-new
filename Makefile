# ****************************************************************************
#    Ledger App for Bitcoin
#    (c) 2024 Ledger SAS.
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
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

# TODO: Compile with the right path restrictions
#
#       The right path restriction would be something like
#         --path "*'/0'"
#       for mainnet, and
#         --path "*'/1'"
#       for testnet.
#
#       That is, restrict the BIP-44 coin_type, but not the purpose.
#       However, such wildcards are not currently supported by the OS.
#
#       Note that the app still requires explicit user approval before exporting
#       any xpub outside of a small set of allowed standard paths.

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS = ""

# Allowed SLIP21 paths
PATH_SLIP21_APP_LOAD_PARAMS = "LEDGER-Wallet policy"

# Application version
APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION_SUFFIX = # if not empty, appended at the end. Do not add a dash.

ifeq ($(APPVERSION_SUFFIX),)
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"
else
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)-$(strip $(APPVERSION_SUFFIX))"
endif

# If set, the app will automatically approve all requests without user interaction. Useful for performance tests.
# It is critical that no such app is ever deployed in production.
AUTOAPPROVE_FOR_PERF_TESTS ?= 0
ifneq ($(AUTOAPPROVE_FOR_PERF_TESTS),0)
    DEFINES += HAVE_AUTOAPPROVE_FOR_PERF_TESTS
endif

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = bitcoin_testnet bitcoin

# simplify for tests
ifndef COIN
COIN=bitcoin_testnet
endif

########################################
#     Application custom permissions   #
########################################
HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
HAVE_APPLICATION_FLAG_LIBRARY = 1

ifeq ($(COIN),bitcoin_testnet)
    # Bitcoin testnet, no legacy support
    DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
    DEFINES   += BIP44_COIN_TYPE=1
    DEFINES   += COIN_P2PKH_VERSION=111
    DEFINES   += COIN_P2SH_VERSION=196
    DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
    DEFINES   += COIN_COINID_SHORT=\"TEST\"

    APPNAME = "Acre Test"
else ifeq ($(COIN),bitcoin)
    # the version for performance tests automatically approves all requests
    # there is no reason to ever compile the mainnet app with this flag
    ifneq ($(AUTOAPPROVE_FOR_PERF_TESTS),0)
        $(error Use testnet app for performance tests)
    endif

    # Bitcoin mainnet, no legacy support
    DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
    DEFINES   += BIP44_COIN_TYPE=0
    DEFINES   += COIN_P2PKH_VERSION=0
    DEFINES   += COIN_P2SH_VERSION=5
    DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bc\"
    DEFINES   += COIN_COINID_SHORT=\"BTC\"

    APPNAME = "Acre"

else
    ifeq ($(filter clean,$(MAKECMDGOALS)),)
        $(error Unsupported COIN - use bitcoin_testnet, bitcoin)
    endif
endif

ifneq (,$(filter-out clean,$(MAKECMDGOALS)))
  ifeq ($(TARGET_NAME),TARGET_NANOS)
    $(error This branch is not compatible with the Nano S device. Checkout the 'nanos' branch for the latest code for Nano S.)
  endif
endif

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/nanox_app_acre.gif
ICON_NANOSP = icons/nanox_app_acre.gif
ICON_STAX = icons/stax_app_acre.gif
ICON_FLEX = icons/flex_app_acre.gif

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
#          Features disablers          #
########################################
# Don't use standard app file to avoid conflicts for now
DISABLE_STANDARD_APP_FILES = 1

# Don't use default IO_SEPROXY_BUFFER_SIZE to use another
# value for NANOS for an unknown reason.
DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1

DEFINES   += HAVE_BOLOS_APP_STACK_CANARY


DEFINES   += IO_SEPROXYHAL_BUFFER_SIZE_B=300

# debugging helper functions and macros
CFLAGS    += -g -include debug-helpers/debug.h

# DEFINES   += HAVE_PRINT_STACK_POINTER

DEBUG = 1 # 0 for production, 1 for debug
ifeq ($(DEBUG),10)
    $(warning Using semihosted PRINTF. Only run with speculos!)
    DEFINES   += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF PRINTF=semihosted_printf
endif

# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# Application source files
APP_SOURCE_PATH += src

# Allow usage of function from lib_standard_app/crypto_helpers.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c

include $(BOLOS_SDK)/Makefile.standard_app

# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
