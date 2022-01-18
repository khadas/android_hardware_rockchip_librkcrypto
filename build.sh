#/bin/bash

set -e

collect_bin()
{
	cp $BUILD_DIR/librkcrypto.so $TARGET_DIR
	cp $BUILD_DIR/librkcrypto.a $TARGET_DIR
	cp $BUILD_DIR/test/librkcrypto_test $TARGET_DIR
	cp $BUILD_DIR/demo/librkcrypto_demo $TARGET_DIR
	echo "copy target files to $TARGET_DIR success"
}

build()
{
	echo "build $ARM_BIT libraries and binaries"
	TARGET_DIR=$SCRIPT_DIR/out/target/$ARM_BIT/
	BUILD_DIR=$SCRIPT_DIR/out/build/$ARM_BIT/
	mkdir -p $TARGET_DIR
	mkdir -p $BUILD_DIR
	cd $BUILD_DIR
	cmake $SCRIPT_DIR $DBUILD
	make -j12
}

BUILD_PARA="$1"
SCRIPT_DIR=$(pwd)

if [ $# -eq 0 ]; then
	# build both 32-bit and 64-bit
	DBUILD="-DBUILD=32"
	ARM_BIT="arm"
	build
	collect_bin

	DBUILD="-DBUILD=64"
	ARM_BIT="arm64"
	build
	collect_bin
else
	if [ $BUILD_PARA == "32" ]; then
		DBUILD="-DBUILD=32"
		ARM_BIT="arm"
	else
		DBUILD="-DBUILD=64"
		ARM_BIT="arm64"
	fi

	build
	collect_bin
fi
