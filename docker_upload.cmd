rmdir /q /s "labwork/__pycache__"
rmdir /q /s "labwork/util/__pycache__"
rmdir /q /s "labwork/handlers/__pycache__"
del labwork.tar.gz
tar -czvf labwork.tar.gz labwork
docker cp labwork-test 7bc4a2e41062d6a0d944d577030e550efdb7162732252f6b35b2a39b956c55b4:/labwork/labwork-test
docker cp labwork.tar.gz 7bc4a2e41062d6a0d944d577030e550efdb7162732252f6b35b2a39b956c55b4:/labwork/labwork.tar.gz