FROM ubuntu:24.10

RUN apt-get update && apt-get install -y  \
    wget \
    unzip \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

ENV ANDROID_NDK_VERSION=r26d
RUN wget https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip -O /tmp/ndk.zip \
    && unzip /tmp/ndk.zip -d /opt/ \
    && rm /tmp/ndk.zip

ENV ANDROID_NDK_HOME=/opt/android-ndk-${ANDROID_NDK_VERSION}

COPY . /app
WORKDIR /app

ENV CMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake
ENV ANDROID_ABI=arm64-v8a
ENV ANDROID_PLATFORM=android-29

ARG BUILD_INLINE_TEST=OFF
ARG BUILD_GOTPLT_TEST=OFF

RUN cmake -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=${ANDROID_PLATFORM} \
    -DBUILD_INLINE_TEST=${BUILD_INLINE_TEST} -DBUILD_GOTPLT_TEST=${BUILD_GOTPLT_TEST} . \
    && make

ENV OUTPUT_DIR=/output

RUN mkdir -p ${OUTPUT_DIR}

CMD ["sh", "-c", "cp *.so ${OUTPUT_DIR}/"]