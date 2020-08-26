#!/bin/bash
PROJECT_PATH=system/core/fs_mgr/libsnapshot
FUZZ_TARGET=libsnapshot_fuzzer
TARGET_ARCH=$(get_build_var TARGET_ARCH)
FUZZ_BINARY=/data/fuzz/${TARGET_ARCH}/${FUZZ_TARGET}/${FUZZ_TARGET}
DEVICE_INIT_CORPUS_DIR=/data/fuzz/${TARGET_ARCH}/${FUZZ_TARGET}/corpus
DEVICE_GENERATED_CORPUS_DIR=/data/local/tmp/${FUZZ_TARGET}/corpus
DEVICE_GCOV_DIR=/data/local/tmp/${FUZZ_TARGET}/gcov
HOST_SCRATCH_DIR=/tmp/${FUZZ_TARGET}
GCOV_TOOL=${HOST_SCRATCH_DIR}/llvm-gcov

build_normal() (
    pushd $(gettop)
    NATIVE_COVERAGE="" NATIVE_LINE_COVERAGE="" NATIVE_COVERAGE_PATHS="" m ${FUZZ_TARGET}
    ret=$?
    popd
    return ${ret}
)

build_cov() {
    pushd $(gettop)
    NATIVE_COVERAGE="true" NATIVE_LINE_COVERAGE="true" NATIVE_COVERAGE_PATHS="${PROJECT_PATH}" m ${FUZZ_TARGET}
    ret=$?
    popd
    return ${ret}
}

prepare_device() {
    adb root && adb remount &&
    adb shell mkdir -p ${DEVICE_GENERATED_CORPUS_DIR} &&
    adb shell rm -rf ${DEVICE_GCOV_DIR} &&
    adb shell mkdir -p ${DEVICE_GCOV_DIR}
}

push_binary() {
    adb push ${ANDROID_PRODUCT_OUT}/${FUZZ_BINARY} ${FUZZ_BINARY} &&
    adb push ${ANDROID_PRODUCT_OUT}/${DEVICE_INIT_CORPUS_DIR} $(dirname ${FUZZ_BINARY})
}

prepare_host() {
    which lcov || {
        echo "please run:";
        echo "   sudo apt-get install lcov ";
        return 1;
    }
    rm -rf ${HOST_SCRATCH_DIR} &&
    mkdir -p ${HOST_SCRATCH_DIR}
}

# run_snapshot_fuzz -runs=10000
generate_corpus() {
    [[ "$@" ]] || { echo "run with -runs=X"; return 1; }

    prepare_device &&
    build_normal &&
    push_binary &&
    adb shell ${FUZZ_BINARY} "$@" ${DEVICE_INIT_CORPUS_DIR} ${DEVICE_GENERATED_CORPUS_DIR}
}

run_snapshot_fuzz() {
    prepare_device &&
    build_cov &&
    push_binary &&
    adb shell GCOV_PREFIX=${DEVICE_GCOV_DIR} GCOV_PREFIX_STRIP=3 \
        ${FUZZ_BINARY} \
        -runs=0 \
        ${DEVICE_INIT_CORPUS_DIR} ${DEVICE_GENERATED_CORPUS_DIR}
}

show_fuzz_result() {
    prepare_host &&
    unzip -o -j -d ${HOST_SCRATCH_DIR} ${ANDROID_PRODUCT_OUT}/coverage/data/fuzz/${TARGET_ARCH}/${FUZZ_TARGET}/${FUZZ_TARGET}.zip &&
    adb shell find ${DEVICE_GCOV_DIR} -type f | xargs -I {} adb pull {} ${HOST_SCRATCH_DIR} &&
    ls ${HOST_SCRATCH_DIR} &&
    cat > ${GCOV_TOOL} <<< '
#!/bin/bash
exec llvm-cov gcov "$@"
' &&
    chmod +x ${GCOV_TOOL} &&
    lcov --directory ${HOST_SCRATCH_DIR} --base-directory $(gettop) --gcov-tool ${GCOV_TOOL} --capture -o ${HOST_SCRATCH_DIR}/report.cov &&
    genhtml ${HOST_SCRATCH_DIR}/report.cov -o ${HOST_SCRATCH_DIR}/html &&
    echo file://$(realpath ${HOST_SCRATCH_DIR}/html/index.html)
}

# run_snapshot_fuzz -runs=10000
run_snapshot_fuzz_all() {
    generate_corpus "$@" &&
    run_snapshot_fuzz &&
    show_fuzz_result
}
