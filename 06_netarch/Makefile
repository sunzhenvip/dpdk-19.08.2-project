# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = dpdk_netarch

# all source are stored in SRCS-y
SRCS-y := netarch.c

# Build using pkg-config variables if possible
ifeq ($(shell pkg-config --exists libdpdk && echo 0),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF=pkg-config --define-prefix

PC_FILE := $(shell $(PKGCONF) --path libdpdk)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk)

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true

else # Build using legacy build system

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV_LINUX),y)
$(error This application can only operate in a linux environment, \
please change the definition of the RTE_TARGET environment variable)
endif

CFLAGS += -O3
# -D: 这个选项用于定义一个预处理器宏。在这种情况下，定义了宏 ALLOW_EXPERIMENTAL_API。
# ALLOW_EXPERIMENTAL_API: 定义这个宏允许在代码中使用 DPDK 提供的实验性 API。DPDK 的某些 API 被标记为实验性的，
# 意味着这些 API 可能在将来的版本中发生变化或被删除。为了确保开发者明确意识到这些 API 的不稳定性，
# DPDK 要求通过定义这个宏来显式允许使用这些 API。
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)
#调试信息，这样在调试时可以使用调试器对程序进行调试
CFLAGS += -g

# 针对 CLion IDE 函数提示 跳转到.c 文件源码  添加指定的扩展库源码(部分跳转 有一些函数或者其他类型报红)
#CFLAGS += -I$(RTE_SDK)/lib/librte_ethdev
# 获取 $(RTE_SDK)/lib 目录下 所有的目录 不包含 当前 lib 本身目录
# 判断是否设置了该环境变量 执行下面的引入代码
ifdef ADD_DPDK_LIB_INCLUDES
DPDK_LIB_DIRS := $(shell find $(RTE_SDK)/lib -mindepth 1 -type d)
$(foreach dir,$(DPDK_LIB_DIRS),$(eval CFLAGS += -I$(dir)))
endif


include $(RTE_SDK)/mk/rte.extapp.mk
endif
