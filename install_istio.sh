#!/bin/sh
#

ISTIO_TAG=""
OPTIONS="build"
DOCKER_REPO="quay.io/fitstation"
ISTIO_CODE_DIR=$GOPATH/src/istio.io/istio
ENVOY_CODE_DIR="$(pwd)"
ISTIO_RELEASE_DIR=$GOPATH/out/linux_amd64/release
ENVOY_STABLE_SHA="$(cat $ISTIO_CODE_DIR/istio.deps | grep lastStableSHA | cut -f 4 -d '"')"
ISTIO_ENVOY_DEBUG=$ISTIO_RELEASE_DIR/envoy
ISTIO_ENVOY_RELEASE=$ISTIO_RELEASE_DIR/envoy-$ENVOY_STABLE_SHA
ENVOY_BIN_DIR="$ENVOY_CODE_DIR/bazel-bin/src/envoy"
ISTIO_STRIP_OUTPUT="envoy-istio"

if [ "$GOPATH" = "" ]; then
echo "GOPATH is not defined. You may not install golang. Please install golang 1.10.1 and define GOPATH."
exit 1;
fi
echo "ENVOY_CODE_DIR: " $ENVOY_CODE_DIR
echo "ISTIO_RELEASE_DIR: " $ISTIO_RELEASE_DIR
echo "ENVOY_STABLE_SHA: " $ENVOY_STABLE_SHA
echo "ISTIO_ENVOY_RELEASE: " $ISTIO_ENVOY_RELEASE

if [ $# -ge 2 ]; then
ISTIO_TAG="$2"
fi

if [ "$1" != "" ]; then
OPTIONS=$1
fi

echo "OPTIONS is: " "$OPTIONS"
echo "ISTIO_TAG is: " "$ISTIO_TAG"
if [ "$OPTIONS" != "build" ] && [ "$ISTIO_TAG" = "" ]; then
echo "Will generate docker image, but ISTIO_TAG is not specified."
exit 1;
fi

OPTION_BUILD=0
OPTION_DOCKER=0
if [ "$OPTIONS" = "build" ]; then
OPTION_BUILD=1
elif [ "$OPTIONS" = "docker" ]; then
OPTION_DOCKER=1
elif [ "$OPTIONS" = "all" ]; then
OPTION_BUILD=1
OPTION_DOCKER=1
fi

if [ $OPTION_BUILD -eq 1  ]; then
cd $ENVOY_CODE_DIR
echo 'cd' $(pwd)
echo "Build envoy."
result=`make BAZEL_BUILD_ARGS="-c opt"`
if [ "$result" != "" ]; then
echo "make result: $result"
exit 1
fi

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

