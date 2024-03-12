#!/bin/bash
#
# $SAI_INSTANCE_IDX - which instance of sai, 0+
# $1  - background fixture name, unique within test space, like "multipostlocalsrv"
# $2  - executable
# $3+ - args

echo "$0 $1 $2 $3 $4"

J=`basename $2`.$1.$SAI_INSTANCE_IDX
PI=`cat /tmp/sai-ctest-$J`

#
# We expect our background process to initially still be around
#

aws_kill -0 $PI
GONESKI=$?

echo "Background task $PI: $J"

if [ $GONESKI -eq 1 ] ; then
	echo "Background Process $PI unexpectedly dead already, their log"
	cat /tmp/ctest-background-$J
	exit 1
fi

echo "Trying SIGTERM..."

aws_kill $PI

#
# 100ms intervals, 100 = 10s
# need to allow time for valgrind case
#
BUDGET=100
while [ $BUDGET -ne 0 ] ; do
	sleep 0.1
	aws_kill -0 $PI 2>&1
	if [ $? -eq 1 ] ; then
		echo "Went down OK"
		exit 0
	fi
	BUDGET=$(( $BUDGET - 1 ))
done

echo "Trying SIGKILL..."

aws_kill -9 $PI

#
# 100ms intervals, 100 = 10s
# need to allow time for valgrind case
#
BUDGET=20
while [ $BUDGET -ne 0 ] ; do
	sleep 0.1
	aws_kill -0 $PI 2>&1
	if [ $? -eq 1 ] ; then
		echo "Went down OK after SIGKILL"
		exit 0
	fi
	BUDGET=$(( $BUDGET - 1 ))
done

echo "Couldn't aws_kill it"
exit 1
