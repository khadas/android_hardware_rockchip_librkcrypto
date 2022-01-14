#/bin/bash

clear_out()
{
	echo "clear out directories"
	rm -rf $SCRPIT_DIR/out
	mkdir -p $SCRPIT_DIR/out/tmp
}

collect_bin()
{
	TARGET_DIR=$SCRPIT_DIR/out/target/$ARM_BIT/
	mkdir -p $TARGET_DIR
	cp $SCRPIT_DIR/out/tmp/librkcrypto.so $TARGET_DIR
	cp $SCRPIT_DIR/out/tmp/test/librkcrypto_test $TARGET_DIR
	cp $SCRPIT_DIR/out/tmp/demo/librkcrypto_demo $TARGET_DIR
}

build()
{
	echo "build $ARM_BIT binaries"
	cd $SCRPIT_DIR/out/tmp/
	cmake $SCRPIT_DIR $DBUILD
	make
}

BUILD_PARA="$1"
SCRPIT_DIR=$(pwd)
clear_out

if [ $# -eq 0 ]; then
	# build both 32-bit and 64-bit
	DBUILD="-DBUILD=32"
	ARM_BIT="arm"
	build
	collect_bin

	DBUILD="-DBUILD=64"
	ARM_BIT="arm64"
	rm -rf $SCRPIT_DIR/out/tmp/*
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
