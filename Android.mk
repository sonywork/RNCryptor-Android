LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)


#LOCAL_CFLAGS := -pg
#LOCAL_STATIC_LIBRARIES := android-ndk-profiler

LOCAL_MODULE := jcryptoc
define all-cpp-files-under
	$(patsubst ./%,%, \
	  $(shell cd $(LOCAL_PATH) ; \
	          find $(1) -name "*.cpp" -or -name "*.cc" -or -name "*.c" -and -not -name ".*" -and -not -name "testxxx.cpp") \
	 )
endef

define all-subdir-cpp-files
	$(call all-cpp-files-under,./)
endef
LOCAL_SRC_FILES := \
				$(call all-subdir-cpp-files)
LOCAL_LDLIBS    := -lm -llog -g -lssl

include $(BUILD_SHARED_LIBRARY)

#$(call import-module,android-ndk-profiler)