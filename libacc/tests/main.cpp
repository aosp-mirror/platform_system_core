/*
 * Android "Almost" C Compiler.
 * This is a compiler for a small subset of the C language, intended for use
 * in scripting environments where speed and memory footprint are important.
 *
 * This code is based upon the "unobfuscated" version of the
 * Obfuscated Tiny C compiler, see the file LICENSE for details.
 *
 */

#include <ctype.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__arm__)
#include <unistd.h>
#endif

#include <acc/acc.h>


typedef int (*MainPtr)(int, char**);
// This is a separate function so it can easily be set by breakpoint in gdb.
int run(MainPtr mainFunc, int argc, char** argv) {
    return mainFunc(argc, argv);
}

// Private API for development:

extern "C"
void accDisassemble(ACCscript* script);

ACCvoid* symbolLookup(ACCvoid* pContext, const ACCchar* name) {
    return (ACCvoid*) dlsym(RTLD_DEFAULT, name);
}

int main(int argc, char** argv) {
    const char* inFile = NULL;
    bool printListing;
    bool runResults = false;
    FILE* in = stdin;
    int i;
    for (i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            switch (arg[1]) {
                case 'S':
                    printListing = true;
                    break;
                case 'R':
                    runResults = true;
                    break;
            default:
                fprintf(stderr, "Unrecognized flag %s\n", arg);
                return 3;
            }
        } else if (inFile == NULL) {
            inFile = arg;
        } else {
            break;
        }
    }

    if (! inFile) {
        fprintf(stderr, "input file required\n");
        return 2;
    }

    if (inFile) {
        in = fopen(inFile, "r");
        if (!in) {
            fprintf(stderr, "Could not open input file %s\n", inFile);
            return 1;
        }
    }

    fseek(in, 0, SEEK_END);
    size_t fileSize = (size_t) ftell(in);
    rewind(in);
    ACCchar* text = new ACCchar[fileSize + 1];
    size_t bytesRead = fread(text, 1, fileSize, in);
    if (bytesRead != fileSize) {
        fprintf(stderr, "Could not read all of file %s\n", inFile);
    }

    text[fileSize] = '\0';

    ACCscript* script = accCreateScript();

    const ACCchar* scriptSource[] = {text};
    accScriptSource(script, 1, scriptSource, NULL);
    delete[] text;

    accRegisterSymbolCallback(script, symbolLookup, NULL);

    accCompileScript(script);
    int result = accGetError(script);
    MainPtr mainPointer = 0;
    if (result != 0) {
        char buf[1024];
        accGetScriptInfoLog(script, sizeof(buf), NULL, buf);
        fprintf(stderr, "%s", buf);
        goto exit;
    }

    {
        ACCsizei numPragmaStrings;
        accGetPragmas(script, &numPragmaStrings, 0, NULL);
        if (numPragmaStrings) {
            char** strings = new char*[numPragmaStrings];
            accGetPragmas(script, NULL, numPragmaStrings, strings);
            for(ACCsizei i = 0; i < numPragmaStrings; i += 2) {
                fprintf(stderr, "#pragma %s(%s)\n", strings[i], strings[i+1]);
            }
            delete[] strings;
        }
    }

    if (printListing) {
        accDisassemble(script);
    }

    if (runResults) {
        accGetScriptLabel(script, "main", (ACCvoid**) & mainPointer);

        result = accGetError(script);
        if (result != ACC_NO_ERROR) {
            fprintf(stderr, "Could not find main: %d\n", result);
        } else {
            fprintf(stderr, "Executing compiled code:\n");
            int codeArgc = argc - i + 1;
            char** codeArgv = argv + i - 1;
            codeArgv[0] = (char*) (inFile ? inFile : "stdin");
            result = run(mainPointer, codeArgc, codeArgv);
            fprintf(stderr, "result: %d\n", result);
        }
    }

exit:

    accDeleteScript(script);

    return result;
}
