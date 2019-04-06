DEPS=compat.h Makefile
MSBUILD="/c/Program Files (x86)/MSBuild/14.0/Bin/MSBuild.exe"

.PHONY: build-in-container linux windows clean
.PHONY: hvbench.linux hvecho.linux hvstress.linux

# Build Linux binaries in a container
build-in-container:
	@docker build -t hvsock-build -f ./Dockerfile.build .
	@docker run --rm -v ${CURDIR}/build:/src/build hvsock-build

linux: build/hvbench build/hvecho build/hvstress
windows: build/hvecho.exe build/hvstress.exe build/hvbench.exe

# Linux targets
CFLAGS := -Wall -Werror -g -ggdb -static
build/hvbench: hvbench.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ $<

build/hvecho: hvecho.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ $<

build/hvstress: hvstress.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ $<


# Windows targets
build/hvbench.exe: hvbench.c hvbench.vcxproj hvbench.sln $(DEPS)
	$(MSBUILD) hvbench.sln
	mkdir -p build
	cp x64/Debug/hvbench.exe $@

build/hvecho.exe: hvecho.c hvecho.vcxproj hvecho.sln $(DEPS)
	$(MSBUILD) hvecho.sln
	mkdir -p build
	cp x64/Debug/hvecho.exe $@

build/hvstress.exe: hvstress.c hvstress.vcxproj hvstress.sln $(DEPS)
	$(MSBUILD) hvstress.sln
	mkdir -p build
	cp x64/Debug/hvstress.exe $@

clean:
	rm -rf build
	rm -rf Debug x64
