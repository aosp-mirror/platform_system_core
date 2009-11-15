/*
 * RuntimeTest for ACC compiler.
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


typedef void (*ScriptPtr)();

// This is a separate function so it can easily be set by breakpoint in gdb.
void run(ScriptPtr scriptFn) {
    scriptFn();
}

// Private API for development:

extern "C"
void accDisassemble(ACCscript* script);

int globalVar;

void op_int(int a) {
    printf("op_int(%d)\n", a);
}

void op_float12(float a, float b, float c, float d,
                float e, float f, float g, float h,
                float i, float j, float k, float l) {
    printf("op_float12(%g, %g, %g, %g, %g, %g, %g, %g, %g, %g, %g, %g)\n",
           a, b, c, d, e, f, g, h, i, j, k, l);
}

const char* text = "void op_int(int a);\n"
    "void op_float12(float a, float b, float c, float d,\n"
    "           float e, float f, float g, float h,\n"
    "           float i, float j, float k, float l);\n"
    "void script() {\n"
    "  globalVar += 3;\n"
    "  op_int(123);\n"
    "  op_float12(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0);\n"
    "}\n";

ACCvoid* symbolLookup(ACCvoid* pContext, const ACCchar* name) {
    if (strcmp("op_int", name) == 0) {
        return (ACCvoid*) op_int;
    }
    if (strcmp("op_float12", name) == 0) {
        return (ACCvoid*) op_float12;
    }
    if (strcmp("globalVar", name) == 0) {
        return (ACCvoid*) &globalVar;
    }
    return (ACCvoid*) dlsym(RTLD_DEFAULT, name);
}

int main(int argc, char** argv) {
    ACCscript* script = accCreateScript();

    accRegisterSymbolCallback(script, symbolLookup, NULL);

    const ACCchar* scriptSource[] = {text};
    accScriptSource(script, 1, scriptSource, NULL);

    accCompileScript(script);
    int result = accGetError(script);
    ScriptPtr scriptPointer = 0;
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

    accGetScriptLabel(script, "script", (ACCvoid**) & scriptPointer);

    result = accGetError(script);
    if (result != ACC_NO_ERROR) {
        fprintf(stderr, "Could not find script: %d\n", result);
    } else {
        fprintf(stderr, "Executing script:\n");
        globalVar = 17;
        run(scriptPointer);
        fprintf(stderr, "After script globalVar = %d\n", globalVar);
    }


exit:

    accDeleteScript(script);

    return result;
}
