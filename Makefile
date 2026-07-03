CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g -Iinclude
LDLIBS = -lm

SRCS = src/main.c src/entropy.c src/filetype.c src/strings.c src/ioc.c src/sha256.c src/hashlist.c

fileinspect: $(SRCS)
	$(CC) $(CFLAGS) -o fileinspect $(SRCS) $(LDLIBS)

clean:
	rm -f fileinspect src/*.o
	rm -rf build

# Compiles the same C sources to WebAssembly and produces a single
# self-contained web/fileinspect.html (drag & drop UI). Requires emscripten.
web: $(SRCS) web/template.html
	@command -v emcc >/dev/null 2>&1 || { echo "error: emcc not found (install emscripten, e.g. 'brew install emscripten')"; exit 1; }
	mkdir -p build
	emcc -O2 -std=c11 -Iinclude $(SRCS) -o build/fileinspect.js \
		-sMODULARIZE=1 -sEXPORT_NAME=createFileInspect -sSINGLE_FILE=1 \
		-sINVOKE_RUN=0 -sEXPORTED_RUNTIME_METHODS=callMain,FS \
		-sALLOW_MEMORY_GROWTH=1 -sGROWABLE_ARRAYBUFFERS=0
	python3 -c "import pathlib; t = pathlib.Path('web/template.html').read_text(); js = pathlib.Path('build/fileinspect.js').read_text(); pathlib.Path('web/fileinspect.html').write_text(t.replace('//__FILEINSPECT_JS__', js))"
	@echo "Built web/fileinspect.html - open it in any browser."

.PHONY: clean web
