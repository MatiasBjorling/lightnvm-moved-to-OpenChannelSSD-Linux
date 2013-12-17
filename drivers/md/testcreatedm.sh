if [ "$(whoami)" != "root" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

if [ $# -lt 3 ]
then
        echo "Usage : $0 testcreatedm.sh <hint> <pools> <blocks_per_pool>"
        exit
fi

echo "removing device"
dmsetup remove dm2
sleep 2
echo 3 > /proc/sys/vm/drop_caches

if [ "$1" = "remove" ];then
        exit
fi

echo "reloading module"
rmmod dm_openssd
insmod dm-openssd.ko

HINT=$1
POOLS=$2
BLOCKS=$3
DEVICE="/dev/ram0"
dmsetup create dm2 --table "0 12582912 lightnvm $DEVICE $HINT $POOLS $BLOCKS 128 1 1 100 100 500 1500"

chmod 777 /dev/mapper/dm2
