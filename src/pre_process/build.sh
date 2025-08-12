mkdir packets_processing_src/build
cd packets_processing_src/build
cmake ..
make
cd ../..
cp packets_processing_src/build/1_filter ./1_filter
cp packets_processing_src/build/2_split_connection ./2_split_connection
cp packets_processing_src/build/3_field_extraction ./3_field_extraction