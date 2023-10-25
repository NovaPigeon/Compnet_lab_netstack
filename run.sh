#!/bin/bash

read -p "Enter choice (CP{1-6}/HANDIN/MAKE/CLEAN): " choice
handinpack="lab2-寿晨宸-2100012945"
cd "$pwd"
case "$choice" in
  "CP1")
    cd ./checkpoints/CP1
    script -c "bash ./cp1.sh"
    cd ../..
    ;;
  "CP2")
    cd ./checkpoints/CP2
    script -c "bash ./cp2.sh"
    cd ../..
    ;;
  "CP3")
    cd ./checkpoints/CP3
    script -c "bash ./cp3.sh"
    cd ../..
    ;;
  "CP4")
    cd ./checkpoints/CP4
    script -c "bash ./cp4.sh"
    cd ../..
    ;;
  "CP5")
    cd ./checkpoints/CP5
    script -c "bash ./cp5.sh"
    cd ../..
    ;;
  "CP6")
    cd ./checkpoints/CP6
    script -c "bash ./cp6.sh"
    cd ../..
    ;;
  "HANDIN")
    mkdir -p ./"$handinpack"
    cp -r ./CMakeLists.txt ./run.sh ./src/ ./checkpoints/ ./vnetUtils/ ./README.md ./README.pdf ./not-implemented.pdf ./"$handinpack" 
    tar -czvf "$handinpack".tar ./"$handinpack"
    rm -rf ./"$handinpack"
    ;;
   "MAKE")
    mkdir -p ./build
    cd ./build
    cmake ..
    make
    ;;
    "CLEAN")
    rm -rf ./build
    rm -rf checkpoints/CP*/log checkpoints/CP*/typescript
    rm -rf checkpoints/CP3/ip_example.pcap
    rm -rf "$handinpack".tar
    rm -rf ./"$handinpack"
    ;;
  *)
    echo "Invalid choice. Please enter CP{1-6}/HANDIN/MAKE/CLEAN."
    ;;
esac
