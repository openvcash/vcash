
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libdatabase

LOCAL_CFLAGS := -std=c++11

LOCAL_CPPFLAGS := \
	-fpermissive \
	-w \
	-fexceptions \
	-frtti \
	-D__ANDROID__ \
	-D__arm_ \
	-D__GLIBC__ \
	-D_GLIBCXX_HAS_GTHREADS \
	-D_GLIBCXX_USE_C99_STDINT_TR1 \
	-DBOOST_ASIO_DISABLE_STD_ATOMIC

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
	../database/include \
    ./../deps/openssl/include \
	./../deps/boost \

LOCAL_SRC_FILES := \
	../src/block.cpp \
	../src/broadcast_operation.cpp \
	../src/compression.cpp \
    ../src/ecdhe.cpp \
	../src/entry.cpp \
	../src/find_operation.cpp \
    ../src/hc256.cpp \
    ../src/key_pool.cpp \
	../src/message.cpp \
	../src/node_impl.cpp \
	../src/node.cpp \
	../src/operation.cpp \
	../src/operation_queue.cpp \
	../src/ping_operation.cpp \
	../src/query.cpp \
	../src/routing_table.cpp \
	../src/rpc.cpp \
	../src/slot.cpp \
	../src/stack.cpp \
	../src/stack_impl.cpp \
	../src/storage.cpp \
	../src/store_operation.cpp \
	../src/udp_handler.cpp \
	../src/udp_multiplexor.cpp \
    ../src/whirlpool.cpp \

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := libdatabaseshared
LOCAL_STATIC_LIBRARIES := libdatabase
#
include $(BUILD_SHARED_LIBRARY)
