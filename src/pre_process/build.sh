cd packets_processing_src/build
cmake ..
make
cd ../..
cp packets_processing_src/build/1_filter ./1_filter
cp packets_processing_src/build/3_field_extraction ./3_field_extraction
cp packets_processing_src/build/4_field_extraction_no_header ./4_field_extraction_no_header