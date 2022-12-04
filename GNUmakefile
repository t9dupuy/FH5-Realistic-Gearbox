# Original makefile from https://www.enib.fr/~harrouet/s4prc/
# Modified by T. Dupuy -- works on both Windows and Ubuntu

#~~~~ control global settings ~~~~
# opt=2 --> optimization for size + no debug
# opt=1 --> optimization          + no debug
# opt=0 --> no optimization       + debug
opt=0
# clang=1 --> use clang/clang++
# clang=0 --> use gcc/g++
clang=0
# no-warn=1 --> disable all warnings
# no-warn=0 --> enable all warnings
no-warn=1
# verbose=1 --> verbose output
# verbose=0 --> silent output
verbose=0

#~~~~ build program ~~~~
EXE_PREFIX=main

#~~~~ detect operating system ~~~~
ifneq (${OS},Windows_NT)
  ifneq (,${findstring Ubuntu,${shell lsb_release -i 2>/dev/null}})
    OS:=Ubuntu
  endif
endif

#~~~~ adjust project-specific settings ~~~~
CFLAGS   =
CPPFLAGS =
CXXFLAGS =
LDFLAGS  = -lwsock32 -limagehlp
BINFLAGS =

# additional include directory  : CPPFLAGS+=-I header/path
# linking precompiled libraries : LDFLAGS+=-L library/path -Wl,-rpath,library/path -l library_name

#~~~~ source directories ~~~~#
SRC_DIRS = .

#~~~~ adjust platform-specific features ~~~~
ifneq (,${findstring Windows_NT,${OS}})
  EXE_SUFFIX=.exe
  SKIP_LINE=echo.
  REMOVE=del /q
else
  EXE_SUFFIX=
  SKIP_LINE=echo
  REMOVE=rm -rf
endif

ifeq (${OS},Windows_NT)
define if_cond
	@IF /I "$(1)" EQU "$(2)" ($(3)) ELSE ($(4))
endef
else
define if_cond
	@if [ "$(1)" = "$(2)" ] then $(3) else $(4) fi
endef
endif

#~~~~ deduce file names ~~~~
MAIN_C_FILES=${foreach d,${SRC_DIRS},${wildcard ${d}/${strip ${EXE_PREFIX}}*.c}}
MAIN_CXX_FILES=${foreach d,${SRC_DIRS},${wildcard ${d}/${strip ${EXE_PREFIX}}*.cpp}}

COMMON_C_FILES=${filter-out ${MAIN_C_FILES},${foreach d,${SRC_DIRS},${wildcard ${d}/*.c}}}
COMMON_CXX_FILES=${filter-out ${MAIN_CXX_FILES},${foreach d,${SRC_DIRS},${wildcard ${d}/*.cpp}}}

MAIN_OBJECT_FILES=${sort ${patsubst %.c,%.o,${MAIN_C_FILES}} \
                         ${patsubst %.cpp,%.o,${MAIN_CXX_FILES}}}
COMMON_OBJECT_FILES=${sort ${patsubst %.c,%.o,${COMMON_C_FILES}} \
                           ${patsubst %.cpp,%.o,${COMMON_CXX_FILES}}}

OBJECT_FILES=${MAIN_OBJECT_FILES} ${COMMON_OBJECT_FILES}
DEPEND_FILES=${patsubst %.o,%.d,${OBJECT_FILES}}

EXE_FILES=${sort ${patsubst %.c,%${EXE_SUFFIX},${MAIN_C_FILES}} \
                 ${patsubst %.cpp,%${EXE_SUFFIX},${MAIN_CXX_FILES}}}

GENERATED_FILES=${DEPEND_FILES} ${OBJECT_FILES} ${EXE_FILES}

GENERATED_FILES+=${wildcard output_* *~}

ifeq (${OS},Windows_NT)
	GENERATED_FILES:=${subst /,\,${GENERATED_FILES}}
endif

TO_CLEAR_FILES=${filter-out ${subst /,\,${EXE_FILES}},${GENERATED_FILES}}

#~~~~ compiler/linker settings ~~~~
CFLAGS   += -std=c18
CPPFLAGS += -Wall -Wextra -Wshadow -pedantic
CXXFLAGS += -std=c++17 -Wnon-virtual-dtor
LDFLAGS  +=
BINFLAGS +=

# consider these :
# -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wpedantic -Wconversion -Wsign-conversion
# -Wmisleading-indentation -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wnull-dereference
# -Wuseless-cast -Wdouble-promotion -Wformat=2 -Wlifetime

ifeq (${strip ${clang}},1)
  CC=clang
  CXX=clang++
else
  CC=gcc
  CXX=g++
endif

ifneq (,${strip ${MAIN_CXX_FILES} ${COMMON_CXX_FILES}})
  # force c++ link if there is at least one c++ source file
  LD:=${CXX}
else
  LD:=${CC}
endif

#~~~~ debug/optimisation settings ~~~~
ifeq (${strip ${opt}},0)
  BINFLAGS+=-O0 -g
endif
ifeq (${strip ${opt}},1)
  BINFLAGS+=-O3 -s -DNDEBUG
endif
ifeq (${strip ${opt}},2)
  BINFLAGS+=-Os -DNDEBUG
endif

#~~~~ no warnings option ~~~~
ifeq (${strip ${no-warn}},1)
  BINFLAGS+=-w
endif

#~~~~ main target ~~~~
build : ${EXE_FILES}

all : rebuild run

rebuild : clean build clear

.SUFFIXES:
.SECONDARY:
.PHONY: clean clear build rebuild run all test

#~~~~ linker command to produce the executable files (if any) ~~~~
%${EXE_SUFFIX} : %.o ${COMMON_OBJECT_FILES}
	@${LD} -o $@ $^ ${BINFLAGS} ${LDFLAGS}
	$(call if_cond, ${verbose}, 0, 								 		\
    	@echo [32m[OK]   [37m ${LD} -o $@ $^ ${BINFLAGS},			\
    	@echo ==== linking [opt=${opt}] $@ ==== 					   &\
    	@echo ${LD} -o $@ $^ ${BINFLAGS} ${LDFLAGS}                    &\
    	@${SKIP_LINE})

#~~~~ compiler command for every source file ~~~~
%.o : %.c
	@${CC} -o $@ $< -c ${BINFLAGS} ${CPPFLAGS} ${CFLAGS}
	$(call if_cond, ${verbose}, 0, 								 		\
    	@echo [32m[OK]   [37m ${CC} -o $@ $< -c ${BINFLAGS},		\
    	@echo ==== compiling [opt=${opt}] $< ==== 					   &\
    	@echo ${CC} -o $@ $< -c ${BINFLAGS} ${CPPFLAGS} ${CFLAGS}      &\
    	@${SKIP_LINE})

%.o : %.cpp
	@${CXX} -o $@ $< -c ${BINFLAGS} ${CPPFLAGS} ${CXXFLAGS}
	$(call if_cond, ${verbose}, 0, 								 		\
		@echo [32m[OK]   [37m ${CXX} -o $@ $< -c ${BINFLAGS},		\
		@echo ==== compiling [opt=${opt}] $< ==== 					   &\
		@echo ${CXX} -o $@ $< -c ${BINFLAGS} ${CPPFLAGS} ${CXXFLAGS}   &\
		@${SKIP_LINE})

-include ${DEPEND_FILES}

#~~~~ remove all files ~~~~
clean :
	@${REMOVE} ${GENERATED_FILES}
	$(call if_cond, ${verbose}, 0, 										\
		@${SKIP_LINE},													\
		@echo ==== cleaning ====								   	   &\
		@echo ${REMOVE} ${GENERATED_FILES}							   &\
		@${SKIP_LINE})

#~~~~ remove generated files ~~~~
clear :
	@${REMOVE} ${TO_CLEAR_FILES}
	$(call if_cond, ${verbose}, 0, 										\
		@${SKIP_LINE}, 													\
		@echo ==== clearing ==== 									   &\
		@echo ${REMOVE} ${TO_CLEAR_FILES} 							   &\
		@${SKIP_LINE})

#~~~~ run main file ~~~~
run :
	@${EXE_FILES}

