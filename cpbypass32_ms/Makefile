include $(THEOS)/makefiles/common.mk
ARCHS = armv7
TWEAK_NAME = cpbypass

cpbypass_FILES = Tweak.x
cpbypass_CFLAGS = -fobjc-arc
cpbypass_FRAMEWORKS = UIKit
include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"