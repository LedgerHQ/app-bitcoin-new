# ****************************************************************************
#    Ledger App Boilerplate
#    (c) 2020 Ledger SAS.
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

APP_LOAD_PARAMS  = --curve secp256k1
APP_LOAD_PARAMS += --appFlags 0x240
APP_LOAD_PARAMS += --path "44'"
APP_LOAD_PARAMS += $(COMMON_LOAD_PARAMS)

APPNAME      = "Boilerplate"
APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 1
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

ifeq ($(TARGET_NAME),TARGET_NANOX)
    ICONNAME=icons/nanox_app_boilerplate.gif
else
    ICONNAME=icons/nanos_app_boilerplate.gif
endif

all: default

DEFINES += $(DEFINES_LIB)
DEFINES += APPNAME=\"$(APPNAME)\"
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += MAJOR_VERSION=$(APPVERSION_M) MINOR_VERSION=$(APPVERSION_N) PATCH_VERSION=$(APPVERSION_P)
DEFINES += OS_IO_SEPROXYHAL
DEFINES += HAVE_BAGL HAVE_UX_FLOW HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += USB_SEGMENT_SIZE=64
DEFINES += BLE_SEGMENT_SIZE=32
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""
DEFINES += UNUSED\(x\)=\(void\)x

ifeq ($(TARGET_NAME),TARGET_NANOX)
    DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=300
    DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
    DEFINES += HAVE_GLO096
    DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
    DEFINES += HAVE_BAGL_ELLIPSIS
    DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
    DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
    DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
else
    DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=128
endif

DEBUG = 0
ifneq ($(DEBUG),0)
    DEFINES += HAVE_PRINTF
    ifeq ($(TARGET_NAME),TARGET_NANOX)
        DEFINES += PRINTF=mcu_usb_printf
    else
        DEFINES += PRINTF=screen_printf
    endif
else
        DEFINES += PRINTF\(...\)=
endif

ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif

CC      := $(CLANGPATH)clang
CFLAGS  += -O3 -Os
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS  += -lm -lgcc -lc

include $(BOLOS_SDK)/Makefile.glyphs

APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl lib_ux

ifeq ($(TARGET_NAME),TARGET_NANOX)
    SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

load-offline: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN BOL
