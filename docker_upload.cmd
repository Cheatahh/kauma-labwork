rmdir /q /s "labwork/__pycache__"
rmdir /q /s "labwork/util/__pycache__"
rmdir /q /s "labwork/impl/__pycache__"
rmdir /q /s "labwork/handlers/__pycache__"
rmdir /q /s "rc4-bonus/__pycache__"
del labwork.tar.gz
tar -czvf labwork.tar.gz labwork rc4-bonus
docker cp labwork-test %1:/labwork/labwork-test
docker cp labwork.tar.gz %1:/labwork/labwork.tar.gz