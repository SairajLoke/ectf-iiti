# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
# CRYPTO_EXAMPLE=0

# Enable Crypto Example
CRYPTO_EXAMPLE=1
# IPATH += /secrets #for the secrets.h file

#other libs that we may require
# json-c--------------------------------
# IPATH += /usr/include/json-c worked
# PROJ_LDFLAGS += -ljson-c #nope

# LINKERFILE += /usr/lib/x86_64-linux-gnu/libjson-c.so
# PROJ_LDFLAGS += /usr/lib/x86_64-linux-gnu/libjson-c.so


PROJ_CFLAGS += -DHAVE_ECC -DWOLFSSL_AES -DWOLFSSL_SHA256  #REQUIRED 
# PROJ_CFLAGS += -DHAVE_AESGCM
# PROJ_CFLAGS += -DHAVE_PK_CALLBACKS -DWOLFSSL_USER_IO -DNO_WRITEV -DTIME_T_NOT_64BIT
#-----------------------------------------
# PROJ_CFLAGS += -ljson-c
# LIBS += -ljson-c 
# nope
# PROJ_CFLAGS += -I/usr/include/
# IPATH += json-c

# ----------------------------------------
