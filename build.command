#!/bin/sh
# Double-click in Finder to build ssl2pem.app and launch it. Output goes to build/build.log.
cd "$(dirname "$0")"
mkdir -p build
{
  echo "=== build started $(date)"
  xcodebuild -project ssl2pem.xcodeproj -scheme ssl2pem -configuration Release \
    -derivedDataPath build/DerivedData CODE_SIGN_IDENTITY=- build 2>&1
  echo "=== xcodebuild exit: $?"
  if [ -d build/DerivedData/Build/Products/Release/ssl2pem.app ]; then
    rm -rf build/ssl2pem.app
    cp -R build/DerivedData/Build/Products/Release/ssl2pem.app build/ssl2pem.app
    echo "=== copied to build/ssl2pem.app; launching"
    pkill -x ssl2pem; sleep 1; open build/ssl2pem.app
  fi
  echo "=== done $(date)"
} > build/build.log 2>&1
