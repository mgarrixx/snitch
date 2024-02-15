CP := cp

RM := rm

CXX := g++

SRCS := $(wildcard src/*.cpp)

OBJS := $(patsubst src/%.cpp,obj/%.o,$(SRCS))

MKDIR := mkdir

TARGET := bin/snitch

CXXFLAGS := -Wall -O2 -std=c++11

INCLUDES := -I"./header" 

INSTALL_DIR := /usr/local

# Build
all: libs $(TARGET) install

libs:
	@$(MKDIR) -p obj
	@$(MKDIR) -p bin
	@echo '# Start build processes'

obj/%.o: src/%.cpp
	@echo ' └─Building file: $<'
	@$(CXX) $(INCLUDES) $(CXXFLAGS) -c $< -o $@ -MD -lpcap
 
$(TARGET) : $(OBJS)
	@$(CXX) $(INCLUDES) $(CXXFLAGS) $(OBJS) -o $(TARGET) -lpcap -lpthread
	@echo '# Finished successfully building Snitch'

# Clean
clean: uninstall
	@$(RM) -rf ./obj
	@$(RM) -rf ./bin
	@echo '# Finished successfully cleaning Snitch'

# Install
install: 
	@$(MKDIR) -p $(INSTALL_DIR)/include/snitch
	@$(MKDIR) -p $(INSTALL_DIR)/etc/snitchn/logDIR
	@$(CP) header/* $(INSTALL_DIR)/include/snitch
	@$(MKDIR) -p $(INSTALL_DIR)/bin
	@$(CP) bin/* $(INSTALL_DIR)/bin
	@echo '# Installation complete!'

# Uninstall
uninstall:
	@$(RM) -rf $(INSTALL_DIR)/include/snitch
	@$(RM) -f $(INSTALL_DIR)/bin/snitch
	@$(RM) -rf $(INSTALL_DIR)/etc/snitch
	@echo '# Uninstallation complete!'



