#!/bin/sh
# Run the PEMCore tests and build a Release copy of ssl2pem.app into ./build/ssl2pem.app
set -e
cd "$(dirname "$0")"
( cd PEMCore && swift test )
xcodebuild -project ssl2pem.xcodeproj -scheme ssl2pem -configuration Release \
  -derivedDataPath build/DerivedData CODE_SIGN_IDENTITY=- build | tail -n 5
rm -rf build/ssl2pem.app
cp -R build/DerivedData/Build/Products/Release/ssl2pem.app build/ssl2pem.app
echo "Built build/ssl2pem.app"
