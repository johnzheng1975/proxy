#!/bin/sh
#

ISTIO_TAG=""
OPTIONS="all"
DOCKER_REPO="quay.io/fitstation"
ISTIO_RELEASE_DIR=$HOME/go/out/linux_amd64/release
ISTIO_ENVOY_DEBUG=$ISTIO_RELEASE_DIR/envoy
ISTIO_ENVOY_RELEASE=$ISTIO_RELEASE_DIR/envoy-6166ae7ebac7f630206b2fe4e6767516bf198313
ENVOY_CODE_DIR="$HOME/work/istio/code/proxy"
ENVOY_BIN_DIR="$ENVOY_CODE_DIR/bazel-bin/src/envoy"
ISTIO_CODE_DIR=$GOPATH/src/istio.io/istio
ISTIO_STRIP_OUTPUT="envoy-istio"

if [ $# -ge 1 ]; then
ISTIO_TAG="$1"
fi

if [ "$ISTIO_TAG" = "" ]; then
echo "ISTIO_TAG is not specified."
exit 1;
fi
echo "ISTIO_TAG is: " "$ISTIO_TAG"

OPTION_BUILD=0
OPTION_DOCKER=0
if [ $# -ge 2 ]; then
    if [ "$2" = "build" ]; then
    OPTION_BUILD=1
    elif [ "$2" = "docker" ]; then
    OPTION_DOCKER=1
    elif [ "$2" = "all" ]; then
    OPTION_BUILD=1
    OPTION_DOCKER=1
    fi
fi

if [ $OPTION_BUILD -eq 1  ]; then
cd $ENVOY_CODE_DIR
echo 'cd' $(pwd)
echo "Build envoy."
make BAZEL_BUILD_ARGS="-c opt"

cd $ENVOY_BIN_DIR
echo 'cd' $(pwd)
echo "Copy files....."
strip envoy -o $ISTIO_STRIP_OUTPUT && cp -v $ISTIO_STRIP_OUTPUT $ISTIO_ENVOY_RELEASE && cp -v $ISTIO_STRIP_OUTPUT $ISTIO_ENVOY_DEBUG
echo "End copy files....."
fi

if [ $OPTION_DOCKER -eq 1  ]; then
cd $ISTIO_CODE_DIR
echo 'cd' $(pwd)
echo "Make istio docker and push to quay."
export TAG=$ISTIO_TAG
make docker && docker push $DOCKER_REPO/proxy_init:$ISTIO_TAG && docker push $DOCKER_REPO/proxyv2:$ISTIO_TAG
fi

