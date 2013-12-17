RESULTS="results.txt"
WAREHOUSES="40"

echo "dropping db"
mysql -u root -p123456 -e "DROP DATABASE tpcc1000"
echo "re-creating db"
mysqladmin -u root -p123456 create tpcc1000
echo "creating tables"
mysql -u root -p123456 tpcc1000 < create_table.sql
echo "add key"
mysql -u root -p123456 tpcc1000 < add_fkey_idx.sql
echo "load tpcc"
./tpcc_load 127.0.0.1:3306 tpcc1000 root "123456" ${WAREHOUSES}
echo "run tpcc"
./tpcc_start -h127.0.0.1 -P3306 -dtpcc1000 -uroot -p123456 -w${WAREHOUSES} -c32 -r10 -l3600
