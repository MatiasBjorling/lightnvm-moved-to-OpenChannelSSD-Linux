echo "stopping mysql and creating ram openssd"
service mysql stop
./testcreatedm.sh none 8 2048 # 8G device

echo "create and mount file system in /var/lib/mysql"
mkfs -t ext4 -b 4096 /dev/mapper/dm2
mount -t ext4 /dev/mapper/dm2 /var/lib/mysql

echo "copy mysql base back to /var/lib/mysql"
cp -r base_mysql/* /var/lib/mysql
chown -R mysql:mysql /var/lib/mysql

echo "stop apparmor"
/etc/init.d/apparmor stop
/etc/init.d/apparmor teardown
update-rc.d -f apparmor remove

echo "restarting mysql..."
service mysql start

echo "run dm_tpcc"
cd tpcc-mysql
./dm_tpcc.sh
