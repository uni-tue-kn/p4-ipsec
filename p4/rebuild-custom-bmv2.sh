# Replace simple_switch.cpp of BMv2 with modified version
cp simple_switch.cpp ../dependencies/behavioral-model/targets/simple_switch/simple_switch.cpp
cd ../dependencies/behavioral-model/targets/simple_switch
# Add -lcrypto to LIBS in Makefiles of simple_switch and simple_switch_grpc and compile
sed -i -E 's/^LIBS =(.*)/LIBS=\1 -lcrypto/g' Makefile
make
cd ../simple_switch_grpc
sed -i -E 's/^LIBS =(.*)/LIBS=\1 -lcrypto/g' Makefile
make
