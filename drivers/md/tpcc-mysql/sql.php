
<?php
#This script will change all the table engine types for a given database!
#All the DB tools I have (GNU/freeware) will not change a list of database
# types, so this script saves time when a CMS or other populates a database
# with tables we cannot use! This can be migrated to InnoDB by changing line
# 23, col 46 from MyISAM to InnoDB (double check the capitals there!).
# Change these variables relative: serverName, userName, password, databaseName

# 20051410 JLynch
# myisamFixer.php

ini_set('display_errors', 'On');
error_reporting(E_ALL);

$link = mysql_connect("localhost","root","123456")
or die("unable to connect to msql server: " . msql_error());

mysql_select_db("tpcc1000", $link)
or die("unable to select database 'db': " . msql_error());

$result = mysql_query("show tables");
if (!$result) {
	die('query failed: ');
}

while ($row = mysql_fetch_array($result)){
	mysql_query("ALTER TABLE ".$row[0]." ENGINE=MyISAM; ");
	#Command Reference: ALTER TABLE tableName ENGINE=MyISAM
}

?> 
