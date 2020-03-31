#!/bin/bash
SOURCE_DIR="../android/src/main/kotlin/lib"
OUTPUT_DIR="./Classes/j2objc"


if [ ! -f "${J2OBJC_HOME}/j2objc" ]; then echo "J2OBJC_HOME not correctly defined, currently set to '${J2OBJC_HOME}'"; exit 1; fi;

rm -rf ${OUTPUT_DIR} && mkdir -p ${OUTPUT_DIR}

"${J2OBJC_HOME}/j2objc" -Xlint:none -d ${OUTPUT_DIR} \
-sourcepath ${SOURCE_DIR} \
--swift-friendly \
--no-segmented-headers \
--no-package-directories \
-use-arc \
$(find ${SOURCE_DIR} -name '*.java')

